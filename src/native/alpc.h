#pragma once

#include "native/nt.h"

// Native ALPC ABI declarations, isolated from the documented Win32 surface.
// Reference: https://github.com/winsiderss/phnt/blob/master/ntlpcapi.h
namespace win_obj {
    struct NativePortAttributes {
        ULONG flags;
        SECURITY_QUALITY_OF_SERVICE qos;
        SIZE_T max_message_length, memory_bandwidth, max_pool_usage;
        SIZE_T max_section_size, max_view_size, max_total_section_size;
        ULONG dup_object_types;
#ifdef _WIN64
        ULONG reserved;
#endif
    };

    struct NativePortMessage {
        USHORT data_length, total_length, type, data_info_offset;
        HANDLE process_id, thread_id;
        ULONG message_id;
        SIZE_T client_view_size;
    };

    using AlpcConnect = NTSTATUS(NTAPI*)(PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, NativePortAttributes*,
        ULONG, PSID, NativePortMessage*, PSIZE_T, PVOID, PVOID, PLARGE_INTEGER);
    using AlpcCreate = NTSTATUS(NTAPI*)(PHANDLE, POBJECT_ATTRIBUTES, NativePortAttributes*);
    using AlpcReceive = NTSTATUS(NTAPI*)(HANDLE, ULONG, NativePortMessage*, PVOID, NativePortMessage*, PSIZE_T, PVOID, PLARGE_INTEGER);
    using AlpcAccept = NTSTATUS(NTAPI*)(PHANDLE, HANDLE, ULONG, POBJECT_ATTRIBUTES, NativePortAttributes*, PVOID, NativePortMessage*, PVOID, BOOLEAN);

    static_assert(sizeof(NativePortMessage) == (sizeof(void*) == 8 ? 40 : 24));
    static_assert(sizeof(NativePortAttributes) == (sizeof(void*) == 8 ? 72 : 44));
}
