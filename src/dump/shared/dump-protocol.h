#pragma once

// Include Windows.h/winioctl.h in user mode or ntddk.h in kernel mode first.
namespace win_obj::dump {
    constexpr ULONG protocol_version = 1;
    constexpr ULONG page_size = 4096;
    constexpr ULONG max_image_size = 128 * 1024 * 1024;
    constexpr ULONG max_modules = 4096;
    constexpr ULONG target_characters = 512;
    constexpr ULONG ioctl_list = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA);
    constexpr ULONG ioctl_query = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA);
    constexpr ULONG ioctl_capture = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_OUT_DIRECT, FILE_READ_DATA);
    constexpr wchar_t device_path[] = L"\\\\.\\WinObjDump";

    enum class TargetKind : ULONG { MODULE = 1, DEVICE = 2 };

    struct Request {
        ULONG version;
        TargetKind kind;
        ULONGLONG expected_base;
        ULONG expected_size;
        ULONG reserved;
        WCHAR name[target_characters];
    };

    struct Module {
        ULONGLONG base;
        ULONG size;
        ULONG reserved;
        CHAR path[256];
    };

    struct ModuleList {
        ULONG version;
        ULONG count;
        // Followed by count Module records.
    };

    struct Page {
        ULONG copied;
        LONG status;
    };

    struct Capture {
        ULONG version;
        ULONG pages;
        Module module;
        ULONGLONG started;
        ULONGLONG finished;
        ULONG image_offset;
        ULONG reserved;
        // Followed by Page records, then image bytes at image_offset.
    };

    constexpr ULONG PageCount(ULONG size) { return (size + page_size - 1) / page_size; }
    constexpr ULONG ImageOffset(ULONG size) { return sizeof(Capture) + PageCount(size) * sizeof(Page); }
    constexpr ULONG CaptureSize(ULONG size) { return ImageOffset(size) + size; }
    static_assert(sizeof(Module) == 272 && sizeof(Capture) == 304 && sizeof(Request) == 1048);
}
