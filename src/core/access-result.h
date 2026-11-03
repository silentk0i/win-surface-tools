#pragma once

#include "core/win-obj.h"

namespace win_obj {
    enum class AccessStatus : u32 {
        GRANTED, REDUCED, DENIED, PRIVILEGE_REQUIRED, UNAVAILABLE,
        BUSY, TIMEOUT, UNSUPPORTED, SKIPPED, FAILED_PROBE
    };

    enum class AccessErrorType : u32 { NONE, WIN32_ERROR, NT_ERROR, RPC_ERROR, HRESULT_ERROR };
    enum class AccessMethod : u32 { OPEN, ALPC_CONNECT, FILTER_CONNECT, RPC_QUERY, SESSION_QUERY };

    // Also used as the fixed-size response from an isolated probe worker.
    struct AccessObservation {
        AccessStatus status = AccessStatus::FAILED_PROBE;
        AccessErrorType error_type = AccessErrorType::NONE;
        u32 error = 0;
        ACCESS_MASK granted = 0;
        u32 has_granted = 0;
        u32 opened = 0;
        u32 query_error = 0; // NTSTATUS from querying the returned handle.
        u64 elapsed_ms = 0;
        u32 context_verified = 0; // Primary context matched before and after this attempt.
        u32 context_error = 0; // A context failure invalidates all access evidence.
    };

    struct AccessAttempt {
        std::wstring name;
        AccessMethod method = AccessMethod::OPEN;
        ACCESS_MASK requested = 0;
        AccessObservation observation;
        std::wstring detail;
    };

    struct AccessOptions {
        bool devices = false;
        bool connections = false;
        bool maximum_allowed = true;
        u32 timeout_ms = 2000;
    };

    struct AccessTokenInfo {
        std::wstring user_sid;
        u32 integrity_level = 0;
        bool elevated = false;
        bool restricted = false;
        bool app_container = false;
        bool impersonating = false;
        std::vector<std::wstring> enabled_privileges;
        u32 error = 0;
        std::wstring error_operation;
        std::wstring fingerprint;
        std::wstring authentication_id;
        std::wstring token_id;
        std::wstring modified_id;
        u32 session_id = 0;
        u32 elevation_type = 0;
        std::vector<std::wstring> groups;
        std::vector<std::wstring> privilege_states;
        std::vector<std::wstring> restricted_sids;
        std::vector<std::wstring> capabilities;
    };

    struct AccessTestResult {
        WinObj object;
        std::vector<AccessAttempt> attempts;
        // Union of observed explicit-open handle masks, NOT a jointly tested mask.
        // MAXIMUM_ALLOWED and connection handles never contribute to this field.
        ACCESS_MASK observed_explicit = 0;
        u64 timestamp = 0; // UTC FILETIME, 100 ns ticks since 1601.
    };

    const wchar_t* AccessStatusName(AccessStatus status);
    const wchar_t* AccessErrorName(AccessErrorType type);
}
