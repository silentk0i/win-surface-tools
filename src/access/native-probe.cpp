#include <memory>
#include <string_view>
#include "access/native-probe.h"
#include "native/nt.h"
#include "native/alpc.h"
#include <rpc.h>
#include <wtsapi32.h>

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "wtsapi32.lib")

namespace {
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;

    win_obj::AccessObservation InspectHandle(HANDLE handle, ACCESS_MASK requested, bool compare) {
        using namespace win_obj;
        AccessObservation result{};
        result.opened = 1;
        auto query = reinterpret_cast<decltype(&NtQueryObject)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
        if (!query) {
            result.error_type = AccessErrorType::WIN32_ERROR;
            result.error = ERROR_PROC_NOT_FOUND;
            return result;
        }
        PUBLIC_OBJECT_BASIC_INFORMATION information{};
        auto status = query(handle, ObjectBasicInformation, &information, sizeof(information), nullptr);
        if (status < 0) {
            result.query_error = static_cast<u32>(status);
            return result;
        }
        result.has_granted = 1;
        result.granted = information.GrantedAccess;
        result.status = AccessStatus::GRANTED;
        constexpr ACCESS_MASK generic = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
        if (compare && !(requested & (generic | MAXIMUM_ALLOWED)) && (result.granted & requested) != requested)
            result.status = AccessStatus::REDUCED;
        return result;
    }

    const char* OpenFunction(win_obj::WinObjType type) {
        switch (type) {
        case win_obj::EVENT: return "NtOpenEvent";
        case win_obj::MUTANT: return "NtOpenMutant";
        case win_obj::SEMAPHORE: return "NtOpenSemaphore";
        case win_obj::TIMER: return "NtOpenTimer";
        case win_obj::JOB: return "NtOpenJobObject";
        default: return nullptr;
        }
    }
}

namespace win_obj {
    AccessObservation AccessFailure(u32 error, AccessErrorType type) {
        AccessObservation result{};
        result.error = error;
        result.error_type = type;
        auto code = error;
        if (type == AccessErrorType::NT_ERROR) {
            using Translate = ULONG(NTAPI*)(NTSTATUS);
            auto translate = reinterpret_cast<Translate>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
            if (translate)
                code = translate(static_cast<NTSTATUS>(error));
        }
        else if (type == AccessErrorType::HRESULT_ERROR && HRESULT_FACILITY(error) == FACILITY_WIN32) {
            code = HRESULT_CODE(error);
        }
        switch (code) {
        case ERROR_ACCESS_DENIED: result.status = AccessStatus::DENIED; break;
        case ERROR_PRIVILEGE_NOT_HELD: result.status = AccessStatus::PRIVILEGE_REQUIRED; break;
        case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: case ERROR_INVALID_NAME:
        case ERROR_PIPE_NOT_CONNECTED: case ERROR_BROKEN_PIPE: case RPC_S_SERVER_UNAVAILABLE:
            result.status = AccessStatus::UNAVAILABLE; break;
        case ERROR_PIPE_BUSY: case ERROR_SHARING_VIOLATION: case ERROR_BUSY:
            result.status = AccessStatus::BUSY; break;
        case ERROR_TIMEOUT: case WAIT_TIMEOUT: case ERROR_SEM_TIMEOUT:
            result.status = AccessStatus::TIMEOUT; break;
        case ERROR_NOT_SUPPORTED: case ERROR_CALL_NOT_IMPLEMENTED: case ERROR_PROC_NOT_FOUND:
        case ERROR_INVALID_FUNCTION: case RPC_S_PROTSEQ_NOT_SUPPORTED:
            result.status = AccessStatus::UNSUPPORTED; break;
        default: break;
        }
        return result;
    }

    AccessObservation ProbeNativeObject(const WinObj& object, AccessMethod method, ACCESS_MASK access, u32 timeout_ms) {
        if (method == AccessMethod::SESSION_QUERY) {
            if (!object.session_id)
                return AccessFailure(ERROR_INVALID_PARAMETER, AccessErrorType::WIN32_ERROR);
            LPWSTR data = nullptr;
            DWORD bytes = 0;
            if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, *object.session_id, WTSUserName, &data, &bytes))
                return AccessFailure(GetLastError(), AccessErrorType::WIN32_ERROR);
            WTSFreeMemory(data);
            AccessObservation result{};
            result.status = AccessStatus::GRANTED;
            return result;
        }

        if (method == AccessMethod::RPC_QUERY) {
            RPC_BINDING_HANDLE binding = nullptr;
            auto status = RpcBindingFromStringBindingW(reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(object.name.c_str())), &binding);
            if (status != RPC_S_OK)
                return AccessFailure(status, AccessErrorType::RPC_ERROR);
            struct BindingCleanup {
                RPC_BINDING_HANDLE* binding;
                ~BindingCleanup() { RpcBindingFree(binding); }
            } cleanup{ &binding };
            status = RpcBindingSetOption(binding, RPC_C_OPT_CALL_TIMEOUT, timeout_ms);
            RPC_SECURITY_QOS qos{};
            qos.Version = RPC_C_SECURITY_QOS_VERSION;
            qos.IdentityTracking = RPC_C_QOS_IDENTITY_DYNAMIC;
            qos.ImpersonationType = RPC_C_IMP_LEVEL_IDENTIFY;
            if (status == RPC_S_OK)
                status = RpcBindingSetAuthInfoExW(binding, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                    RPC_C_AUTHN_WINNT, nullptr, RPC_C_AUTHZ_NONE, &qos);
            if (status == RPC_S_OK)
                status = RpcMgmtIsServerListening(binding);
            if (status != RPC_S_OK)
                return AccessFailure(status, AccessErrorType::RPC_ERROR);
            AccessObservation result{};
            result.status = AccessStatus::GRANTED;
            return result;
        }

        HANDLE raw_handle = nullptr;
        if (method == AccessMethod::FILTER_CONNECT) {
            auto module = LoadLibraryExW(L"fltlib.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (!module)
                return AccessFailure(GetLastError(), AccessErrorType::WIN32_ERROR);
            using Connect = HRESULT(WINAPI*)(LPCWSTR, DWORD, LPCVOID, WORD, LPSECURITY_ATTRIBUTES, PHANDLE);
            auto connect = reinterpret_cast<Connect>(GetProcAddress(module, "FilterConnectCommunicationPort"));
            auto status = connect ? connect(object.name.c_str(), 0, nullptr, 0, nullptr, &raw_handle) : HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
            FreeLibrary(module);
            if (FAILED(status))
                return AccessFailure(static_cast<u32>(status), AccessErrorType::HRESULT_ERROR);
            Handle handle(raw_handle, CloseHandle);
            return InspectHandle(handle.get(), 0, false);
        }

        std::wstring path = object.name;
        if (object.type == NAMEDPIPE) {
            constexpr std::wstring_view prefix = L"\\\\.\\pipe\\";
            if (!path.starts_with(prefix))
                return AccessFailure(ERROR_INVALID_NAME, AccessErrorType::WIN32_ERROR);
            path = L"\\Device\\NamedPipe\\" + path.substr(prefix.size());
        }
        if (path.empty() || path[0] != L'\\' || path.size() > 32767)
            return AccessFailure(ERROR_INVALID_NAME, AccessErrorType::WIN32_ERROR);
        UNICODE_STRING name{};
        name.Buffer = path.data();
        name.Length = static_cast<USHORT>(path.size() * sizeof(wchar_t));
        name.MaximumLength = name.Length;
        SECURITY_QUALITY_OF_SERVICE qos{ sizeof(qos), SecurityIdentification, SECURITY_STATIC_TRACKING, FALSE };
        OBJECT_ATTRIBUTES attributes{};
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
        attributes.SecurityQualityOfService = &qos;
        auto module = GetModuleHandleW(L"ntdll.dll");
        NTSTATUS status = 0;
        if (method == AccessMethod::ALPC_CONNECT) {
            auto connect = reinterpret_cast<AlpcConnect>(GetProcAddress(module, "NtAlpcConnectPort"));
            if (!connect)
                return AccessFailure(ERROR_PROC_NOT_FOUND, AccessErrorType::WIN32_ERROR);
            NativePortAttributes port_attributes{};
            port_attributes.qos = qos;
            port_attributes.max_message_length = 256;
            LARGE_INTEGER timeout{};
            timeout.QuadPart = -static_cast<LONGLONG>(timeout_ms) * 10000;
            alignas(NativePortMessage) unsigned char buffer[256]{};
            auto message = reinterpret_cast<NativePortMessage*>(buffer);
            message->total_length = sizeof(NativePortMessage);
            SIZE_T length = sizeof(buffer);
            constexpr ULONG synchronous_request = 0x20000;
            status = connect(&raw_handle, &name, nullptr, &port_attributes, synchronous_request, nullptr,
                message, &length, nullptr, nullptr, &timeout);
        }
        else if (object.type == DEVICE || object.type == NAMEDPIPE) {
            auto open = reinterpret_cast<decltype(&NtOpenFile)>(GetProcAddress(module, "NtOpenFile"));
            if (!open)
                return AccessFailure(ERROR_PROC_NOT_FOUND, AccessErrorType::WIN32_ERROR);
            IO_STATUS_BLOCK io{};
            status = open(&raw_handle, access, &attributes, &io,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
        }
        else {
            auto function = OpenFunction(static_cast<WinObjType>(object.type));
            using Open = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
            auto open = function ? reinterpret_cast<Open>(GetProcAddress(module, function)) : nullptr;
            if (!open)
                return AccessFailure(ERROR_PROC_NOT_FOUND, AccessErrorType::WIN32_ERROR);
            status = open(&raw_handle, access, &attributes);
        }

        Handle handle(raw_handle, CloseHandle);
        // STATUS_TIMEOUT and STATUS_PENDING are nonnegative, but not successful opens.
        if (status != 0)
            return AccessFailure(static_cast<u32>(status), AccessErrorType::NT_ERROR);
        if (!handle || handle.get() == INVALID_HANDLE_VALUE)
            return AccessFailure(ERROR_INVALID_HANDLE, AccessErrorType::WIN32_ERROR);
        return InspectHandle(handle.get(), access, method == AccessMethod::OPEN);
    }
}
