#include <ntddk.h>
#include <aux_klib.h>
#include <wdmsec.h>
#include "dump/shared/dump-protocol.h"

namespace {
    using namespace win_obj::dump;
    constexpr ULONG pool_tag = 'DmOW';
    const GUID device_class = { 0x42aeb5cc, 0x6029, 0x4cf1, { 0xb7, 0x36, 0x5d, 0x13, 0x64, 0x98, 0x16, 0x2a } };

    struct Modules {
        AUX_MODULE_EXTENDED_INFO* entries = nullptr;
        ULONG count = 0;
        ~Modules() { if (entries) ExFreePoolWithTag(entries, pool_tag); }
        NTSTATUS Query() {
            for (ULONG retry = 0; retry < 4; ++retry) {
                ULONG bytes = 0;
                auto status = AuxKlibQueryModuleInformation(&bytes, sizeof(*entries), nullptr);
                if (!NT_SUCCESS(status)) return status;
                if (!bytes || bytes > max_modules * sizeof(*entries)) return STATUS_INSUFFICIENT_RESOURCES;
                entries = static_cast<AUX_MODULE_EXTENDED_INFO*>(ExAllocatePool2(POOL_FLAG_PAGED, bytes, pool_tag));
                if (!entries) return STATUS_INSUFFICIENT_RESOURCES;
                status = AuxKlibQueryModuleInformation(&bytes, sizeof(*entries), entries);
                if (NT_SUCCESS(status)) { count = bytes / sizeof(*entries); return status; }
                ExFreePoolWithTag(entries, pool_tag);
                entries = nullptr;
                if (status != STATUS_BUFFER_TOO_SMALL) return status;
            }
            return STATUS_RETRY;
        }
    };

    Module Describe(const AUX_MODULE_EXTENDED_INFO& source) {
        Module result{};
        result.base = reinterpret_cast<ULONGLONG>(source.BasicInfo.ImageBase);
        result.size = source.ImageSize;
        RtlCopyMemory(result.path, source.FullPathName, sizeof(result.path) - 1);
        return result;
    }

    struct Target {
        Module module{};
        PFILE_OBJECT file = nullptr;
        PDEVICE_OBJECT device = nullptr;
        UNICODE_STRING driver_path{};
        ~Target() {
            if (driver_path.Buffer) ExFreePool(driver_path.Buffer);
            if (device) ObDereferenceObject(device);
            if (file) ObDereferenceObject(file);
        }
    };

    NTSTATUS Resolve(const Request& request, Target& target) {
        if (request.version != protocol_version || request.reserved || !request.name[0] ||
            request.name[target_characters - 1]) return STATUS_INVALID_PARAMETER;
        UNICODE_STRING name{};
        RtlInitUnicodeString(&name, request.name);
        if (request.kind == TargetKind::DEVICE) {
            UNICODE_STRING prefix = RTL_CONSTANT_STRING(L"\\Device\\");
            if (!RtlPrefixUnicodeString(&prefix, &name, TRUE)) return STATUS_OBJECT_NAME_INVALID;
            PDEVICE_OBJECT device = nullptr;
            // This is the TOP of the named stack, not necessarily the PDO's driver.
            auto status = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES, &target.file, &device);
            if (!NT_SUCCESS(status)) return status;
            // Hold an explicit reference to the current top device while resolving/capturing.
            target.device = IoGetAttachedDeviceReference(target.file->DeviceObject);
            status = IoQueryFullDriverPath(target.device->DriverObject, &target.driver_path);
            if (!NT_SUCCESS(status)) return status;
            name = target.driver_path;
            for (USHORT i = name.Length / sizeof(WCHAR); i > 0; --i) {
                if (name.Buffer[i - 1] == L'\\') {
                    name.Buffer += i;
                    name.Length -= i * sizeof(WCHAR);
                    name.MaximumLength = name.Length;
                    break;
                }
            }
            if (!name.Length) return STATUS_NOT_FOUND;
        }
        else if (request.kind != TargetKind::MODULE) return STATUS_INVALID_PARAMETER;
        Modules modules;
        auto status = modules.Query();
        if (!NT_SUCCESS(status)) return status;
        ULONG matches = 0;
        for (ULONG i = 0; i < modules.count; ++i) {
            const auto& entry = modules.entries[i];
            bool match = false;
            if (entry.FileNameOffset < sizeof(entry.FullPathName)) {
                WCHAR text[256]{};
                ULONG j = 0;
                for (ULONG position = entry.FileNameOffset; position < sizeof(entry.FullPathName) && j < RTL_NUMBER_OF(text) - 1; ++position, ++j) {
                    auto c = entry.FullPathName[position];
                    if (!c) break;
                    text[j] = c;
                }
                UNICODE_STRING module_name{};
                RtlInitUnicodeString(&module_name, text);
                match = RtlEqualUnicodeString(&name, &module_name, TRUE) != FALSE;
            }
            if (match) { target.module = Describe(entry); ++matches; }
        }
        if (!matches) return STATUS_NOT_FOUND;
        if (matches != 1) return STATUS_OBJECT_NAME_COLLISION;
        if (!target.module.size || target.module.size > max_image_size ||
            target.module.base < reinterpret_cast<ULONGLONG>(MmSystemRangeStart) ||
            target.module.base + target.module.size < target.module.base) return STATUS_INVALID_IMAGE_FORMAT;
        if ((request.expected_base && request.expected_base != target.module.base) ||
            (request.expected_size && request.expected_size != target.module.size)) return STATUS_RETRY;
        return STATUS_SUCCESS;
    }

    bool StillLoaded(const Module& module) {
        Modules modules;
        if (!NT_SUCCESS(modules.Query())) return false;
        for (ULONG i = 0; i < modules.count; ++i) {
            auto current = Describe(modules.entries[i]);
            if (current.base == module.base && current.size == module.size &&
                RtlCompareMemory(current.path, module.path, sizeof(current.path)) == sizeof(current.path)) return true;
        }
        return false;
    }

    NTSTATUS Control(PIRP irp, PIO_STACK_LOCATION stack, ULONG_PTR& information) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        // Recheck the effective caller on EVERY request, including duplicated handles.
        if (!SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE), irp->RequestorMode))
            return STATUS_PRIVILEGE_NOT_HELD;
        auto code = stack->Parameters.DeviceIoControl.IoControlCode;
        auto input = stack->Parameters.DeviceIoControl.InputBufferLength;
        auto output = stack->Parameters.DeviceIoControl.OutputBufferLength;
        if (code == ioctl_list) {
            if (input != sizeof(ULONG) || *static_cast<ULONG*>(irp->AssociatedIrp.SystemBuffer) != protocol_version)
                return STATUS_INVALID_PARAMETER;
            Modules modules;
            auto status = modules.Query();
            if (!NT_SUCCESS(status)) return status;
            auto bytes = sizeof(ModuleList) + modules.count * sizeof(Module);
            if (output < bytes) return STATUS_BUFFER_TOO_SMALL;
            auto list = static_cast<ModuleList*>(irp->AssociatedIrp.SystemBuffer);
            RtlZeroMemory(list, bytes);
            list->version = protocol_version;
            list->count = modules.count;
            auto items = reinterpret_cast<Module*>(list + 1);
            for (ULONG i = 0; i < modules.count; ++i) items[i] = Describe(modules.entries[i]);
            information = bytes;
            return STATUS_SUCCESS;
        }
        if (code != ioctl_query && code != ioctl_capture) return STATUS_INVALID_DEVICE_REQUEST;
        if (input != sizeof(Request)) return STATUS_INVALID_PARAMETER;
        // Copy before overwriting the buffered request with a query response.
        Request request = *static_cast<Request*>(irp->AssociatedIrp.SystemBuffer);
        Target target;
        auto status = Resolve(request, target);
        if (!NT_SUCCESS(status)) return status;
        if (code == ioctl_query) {
            if (output < sizeof(Module)) return STATUS_BUFFER_TOO_SMALL;
            *static_cast<Module*>(irp->AssociatedIrp.SystemBuffer) = target.module;
            information = sizeof(Module);
            return STATUS_SUCCESS;
        }
        if (!request.expected_base || !request.expected_size) return STATUS_INVALID_PARAMETER;
        auto bytes = CaptureSize(target.module.size);
        if (output < bytes || !irp->MdlAddress || MmGetMdlByteCount(irp->MdlAddress) < bytes)
            return STATUS_BUFFER_TOO_SMALL;
        auto buffer = static_cast<UCHAR*>(MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute));
        if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;
        RtlZeroMemory(buffer, bytes);
        // The mapped output is user-writable. Never read control fields back from it.
        Capture header{};
        header.version = protocol_version;
        header.module = target.module;
        header.pages = PageCount(target.module.size);
        header.image_offset = ImageOffset(target.module.size);
        LARGE_INTEGER time{};
        KeQuerySystemTimePrecise(&time);
        header.started = time.QuadPart;
        auto pages = reinterpret_cast<Page*>(buffer + sizeof(Capture));
        for (ULONG i = 0; i < header.pages; ++i) {
            if (irp->Cancel) { RtlZeroMemory(buffer, bytes); return STATUS_CANCELLED; }
            auto offset = i * page_size;
            auto count = min(page_size, target.module.size - offset);
            MM_COPY_ADDRESS address{};
            address.VirtualAddress = reinterpret_cast<PVOID>(target.module.base + offset);
            SIZE_T copied = 0;
            pages[i].status = MmCopyMemory(buffer + header.image_offset + offset, address, count,
                MM_COPY_MEMORY_VIRTUAL, &copied);
            pages[i].copied = static_cast<ULONG>(copied);
        }
        KeQuerySystemTimePrecise(&time);
        header.finished = time.QuadPart;
        // Best-effort live capture: safely detect ordinary unload/reload races.
        // No undocumented loader locks or direct dereferences of image memory.
        if (!StillLoaded(target.module)) { RtlZeroMemory(buffer, bytes); return STATUS_RETRY; }
        RtlCopyMemory(buffer, &header, sizeof(header));
        information = bytes;
        return STATUS_SUCCESS;
    }

    NTSTATUS Dispatch(PDEVICE_OBJECT, PIRP irp) {
        auto stack = IoGetCurrentIrpStackLocation(irp);
        NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
        ULONG_PTR information = 0;
        switch (stack->MajorFunction) {
        case IRP_MJ_CREATE:
            status = stack->FileObject->FileName.Length ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_SUCCESS;
            break;
        case IRP_MJ_CLOSE: case IRP_MJ_CLEANUP: status = STATUS_SUCCESS; break;
        case IRP_MJ_DEVICE_CONTROL: status = Control(irp, stack, information); break;
        }
        irp->IoStatus.Status = status;
        irp->IoStatus.Information = information;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
    }

    void Unload(PDRIVER_OBJECT driver) {
        UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\WinObjDump");
        IoDeleteSymbolicLink(&link);
        IoDeleteDevice(driver->DeviceObject);
    }
}

extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING) {
    auto status = AuxKlibInitialize();
    if (!NT_SUCCESS(status)) return status;
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\WinObjDump");
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\WinObjDump");
    UNICODE_STRING security = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    PDEVICE_OBJECT device = nullptr;
    status = IoCreateDeviceSecure(driver, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
        FALSE, &security, &device_class, &device);
    if (!NT_SUCCESS(status)) return status;
    for (auto& dispatch : driver->MajorFunction) dispatch = Dispatch;
    driver->DriverUnload = Unload;
    status = IoCreateSymbolicLink(&link, &name);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(device); return status; }
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
