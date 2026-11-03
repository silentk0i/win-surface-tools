#include "access/access-tests.h"

namespace win_obj {
    const wchar_t* AccessStatusName(AccessStatus status) {
        switch (status) {
        case AccessStatus::GRANTED: return L"granted";
        case AccessStatus::REDUCED: return L"reduced";
        case AccessStatus::DENIED: return L"denied";
        case AccessStatus::PRIVILEGE_REQUIRED: return L"privilege-required";
        case AccessStatus::UNAVAILABLE: return L"unavailable";
        case AccessStatus::BUSY: return L"busy";
        case AccessStatus::TIMEOUT: return L"timeout";
        case AccessStatus::UNSUPPORTED: return L"unsupported";
        case AccessStatus::SKIPPED: return L"skipped";
        default: return L"error";
        }
    }

    const wchar_t* AccessErrorName(AccessErrorType type) {
        switch (type) {
        case AccessErrorType::WIN32_ERROR: return L"Win32";
        case AccessErrorType::NT_ERROR: return L"NTSTATUS";
        case AccessErrorType::RPC_ERROR: return L"RPC";
        case AccessErrorType::HRESULT_ERROR: return L"HRESULT";
        default: return L"none";
        }
    }

    AccessTestResult ObjectAccessTest::Test(const WinObj& object, const AccessOptions& options, IAccessProbe& probe) {
        AccessTestResult result{ object };
        FILETIME now{};
        GetSystemTimeAsFileTime(&now);
        result.timestamp = (static_cast<u64>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
        auto record = [&](const wchar_t* name, ACCESS_MASK mask, AccessMethod method,
            const wchar_t* detail = L"", bool run = true, AccessStatus skipped = AccessStatus::SKIPPED) {
            AccessAttempt attempt{ name, method, mask, {}, detail };
            if (run)
                attempt.observation = probe.Execute(method, mask);
            else
                attempt.observation.status = skipped;
            const auto& observed = attempt.observation;
            if (method == AccessMethod::OPEN && mask != MAXIMUM_ALLOWED && observed.has_granted)
                result.observed_explicit |= observed.granted;
            result.attempts.push_back(std::move(attempt));
        };

        if (type_ == ALPC || type_ == FLT || type_ == RPC) {
            auto method = type_ == ALPC ? AccessMethod::ALPC_CONNECT :
                type_ == FLT ? AccessMethod::FILTER_CONNECT : AccessMethod::RPC_QUERY;
            bool supported = !(type_ == ALPC && object.native_type == L"Port") &&
                !(type_ == FLT && object.native_type == L"FilterCommunicationPort");
            record(type_ == RPC ? L"RPC_MANAGEMENT_LISTEN_QUERY" : L"CONNECT", 0, method,
                type_ == RPC ? L"Management query only; does not establish interface/procedure access. Uses current credentials with packet privacy." :
                L"Connection outcome only; any returned mask belongs to the client endpoint. No application messages or custom context.",
                options.connections && supported, supported ? AccessStatus::SKIPPED : AccessStatus::UNSUPPORTED);
            record(L"SERVER_OBJECT_ACCESS_MASK", 0, method,
                L"A connection handle is not a handle to the discovered server object.", false, AccessStatus::UNSUPPORTED);
            record(L"APPLICATION_OPERATIONS", 0, method,
                L"Requires a protocol-specific adapter; no arbitrary RPC calls or messages are sent.", false, AccessStatus::UNSUPPORTED);
            return result;
        }

        if (type_ == SESSIONS) {
            record(L"QUERY_INFORMATION", 0x1, AccessMethod::SESSION_QUERY,
                L"WTSUserName query for this session ID; operation evidence, not a handle mask.");
            const std::pair<const wchar_t*, ACCESS_MASK> rights[] = {
                { L"SET_INFORMATION", 0x2 }, { L"RESET", 0x4 }, { L"VIRTUAL_CHANNELS", 0x8 },
                { L"REMOTE_CONTROL", 0x10 }, { L"LOGON", 0x20 }, { L"LOGOFF", 0x40 },
                { L"MESSAGE", 0x80 }, { L"CONNECT", 0x100 }, { L"DISCONNECT", 0x200 },
                { L"DELETE", DELETE }, { L"READ_CONTROL", READ_CONTROL },
                { L"WRITE_DAC", WRITE_DAC }, { L"WRITE_OWNER", WRITE_OWNER },
                { L"ACCESS_SYSTEM_SECURITY", ACCESS_SYSTEM_SECURITY }
            };
            for (const auto& right : rights)
                record(right.first, right.second, AccessMethod::SESSION_QUERY,
                    L"No implemented non-mutating session permission check.", false, AccessStatus::UNSUPPORTED);
            return result;
        }

        bool enabled = (type_ != DEVICE || options.devices) && (type_ != NAMEDPIPE || options.connections);
        auto open = [&](const wchar_t* name, ACCESS_MASK mask, const wchar_t* detail = L"") {
            record(name, mask, AccessMethod::OPEN, detail, enabled);
        };
        // Specific requests ALWAYS run independently and before MAXIMUM_ALLOWED.
        ACCESS_MASK specific = 0;
        switch (type_) {
        case EVENT:
            specific = 3;
            open(L"EVENT_QUERY_STATE", 1, L"Native query-state bit.");
            open(L"EVENT_MODIFY_STATE", 2);
            break;
        case MUTANT:
            specific = 1;
            open(L"MUTANT_QUERY_STATE", 1, L"Native query right; Win32 MUTEX_MODIFY_STATE is a reserved alias.");
            break;
        case SEMAPHORE:
            specific = 3;
            open(L"SEMAPHORE_QUERY_STATE", 1, L"Native query-state bit.");
            open(L"SEMAPHORE_MODIFY_STATE", 2);
            break;
        case TIMER:
            specific = 3;
            open(L"TIMER_QUERY_STATE", 1);
            open(L"TIMER_MODIFY_STATE", 2);
            break;
        case JOB:
            specific = 0x3f;
            open(L"JOB_OBJECT_QUERY", 4);
            open(L"JOB_OBJECT_ASSIGN_PROCESS", 1);
            open(L"JOB_OBJECT_SET_ATTRIBUTES", 2);
            open(L"JOB_OBJECT_TERMINATE", 8);
            open(L"JOB_OBJECT_SET_SECURITY_ATTRIBUTES", 0x10, L"Legacy bit; associated operation is unsupported on modern Windows.");
            open(L"JOB_OBJECT_IMPERSONATE", 0x20, L"Version-dependent native right.");
            break;
        case DEVICE:
        case NAMEDPIPE:
            specific = 0x1ff;
            open(L"FILE_READ_DATA", FILE_READ_DATA);
            open(L"FILE_READ_ATTRIBUTES", FILE_READ_ATTRIBUTES);
            open(L"FILE_READ_EA", FILE_READ_EA);
            open(L"FILE_WRITE_DATA", FILE_WRITE_DATA);
            open(L"FILE_WRITE_ATTRIBUTES", FILE_WRITE_ATTRIBUTES);
            open(L"FILE_WRITE_EA", FILE_WRITE_EA);
            if (type_ == DEVICE) {
                open(L"FILE_APPEND_DATA", FILE_APPEND_DATA);
                open(L"FILE_EXECUTE", FILE_EXECUTE);
                record(L"FILE_DELETE_CHILD", FILE_DELETE_CHILD, AccessMethod::OPEN,
                    L"Directory operation; not probed on a native device endpoint.", false, AccessStatus::UNSUPPORTED);
            }
            else {
                record(L"FILE_CREATE_PIPE_INSTANCE", FILE_CREATE_PIPE_INSTANCE, AccessMethod::OPEN,
                    L"Server-side capability; a client open does not validate it. No server instance is created.", false, AccessStatus::UNSUPPORTED);
            }
            open(L"READ_WRITE_DATA", FILE_READ_DATA | FILE_WRITE_DATA);
            break;
        default:
            record(L"OBJECT_TYPE", 0, AccessMethod::OPEN, L"No rights catalog.", false, AccessStatus::UNSUPPORTED);
            return result;
        }

        open(L"READ_CONTROL", READ_CONTROL);
        open(L"SYNCHRONIZE", SYNCHRONIZE);
        open(L"WRITE_DAC", WRITE_DAC);
        open(L"WRITE_OWNER", WRITE_OWNER);
        open(L"DELETE", DELETE);
        open(L"ACCESS_SYSTEM_SECURITY", ACCESS_SYSTEM_SECURITY, L"Privileges are not enabled by the probe.");
        open(L"GENERIC_READ", GENERIC_READ);
        open(L"GENERIC_WRITE", GENERIC_WRITE);
        open(L"GENERIC_EXECUTE", GENERIC_EXECUTE);
        open(L"GENERIC_ALL", GENERIC_ALL);
        open(L"ALL_ACCESS", STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | specific,
            L"Combined request; failure says nothing about individual requests. Native/version-dependent bits may be rejected.");
        open(L"ZERO_ACCESS", 0, L"Open baseline only; does not establish useful access.");
        record(L"MAXIMUM_ALLOWED", MAXIMUM_ALLOWED, AccessMethod::OPEN,
            L"Advisory only. Never gates explicit probes or supplies their summary mask.", enabled && options.maximum_allowed);
        return result;
    }
}
