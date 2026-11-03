#pragma once

#include <windows.h>
#include <winternl.h>

#define DIRECTORY_QUERY                   0x0001
#define DIRECTORY_TRAVERSE                0x0002
#define DIRECTORY_CREATE_OBJECT           0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY     0x0008

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

extern "C" NTSTATUS NTAPI NtOpenDirectoryObject(
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS NTAPI NtQueryDirectoryObject(
    IN HANDLE DirectoryHandle,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN BOOLEAN ReturnSingleEntry,
    IN BOOLEAN RestartScan,
    IN OUT PULONG Context,
    OUT PULONG ReturnLength OPTIONAL
);
