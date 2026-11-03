#include <iomanip>
#include <iostream>
#include <sstream>
#include "cli/access-output.h"

namespace win_obj {
    std::wstring JsonString(const std::wstring& value) {
        std::wostringstream output;
        output << L'"';
        for (auto character : value) {
            if (character == L'"' || character == L'\\')
                output << L'\\' << character;
            else if (character < 0x20 || (character >= 0xd800 && character <= 0xdfff))
                output << L"\\u" << std::hex << std::setw(4) << std::setfill(L'0') << static_cast<unsigned>(character) << std::dec;
            else
                output << character;
        }
        output << L'"';
        return output.str();
    }

    std::wstring ProcessJson(const ProcessIdentity& process) {
        std::wostringstream output;
        output << L"{\"pid\":" << process.pid << L",\"name\":" << JsonString(process.name)
            << L",\"created\":" << JsonString(std::to_wstring(process.created)) << L",\"session\":" << process.session
            << L",\"imagePath\":" << JsonString(process.image_path) << L'}';
        return output.str();
    }

    std::wstring ProcessScanJson(const ProcessScanInfo& info) {
        std::wostringstream output;
        output << L"{\"requested\":" << info.requested << L",\"complete\":" << info.complete
            << L",\"budgetExhausted\":" << info.budget_exhausted << L",\"time\":" << JsonString(std::to_wstring(info.timestamp))
            << L",\"handles\":" << info.handles << L",\"queried\":" << info.queried << L",\"failed\":" << info.failed
            << L",\"timeouts\":" << info.timeouts << L",\"inaccessibleProcesses\":" << info.inaccessible_processes
            << L",\"tcpError\":" << info.tcp_error
            << L",\"error\":" << info.error << L",\"errorOperation\":" << JsonString(info.error_operation) << L'}';
        return output.str();
    }

    std::wstring AccessTokenJson(const AccessTokenInfo& token) {
        std::wostringstream output;
        output << L"{\"sid\":" << JsonString(token.user_sid) << L",\"integrity\":" << token.integrity_level
            << L",\"elevated\":" << token.elevated << L",\"restricted\":" << token.restricted << L",\"appContainer\":" << token.app_container
            << L",\"impersonating\":" << token.impersonating << L",\"error\":" << token.error << L",\"errorOperation\":" << JsonString(token.error_operation)
            << L",\"execution\":\"primary\",\"fingerprint\":" << JsonString(token.fingerprint) << L",\"authenticationId\":" << JsonString(token.authentication_id)
            << L",\"tokenId\":" << JsonString(token.token_id) << L",\"modifiedId\":" << JsonString(token.modified_id)
            << L",\"session\":" << token.session_id << L",\"elevationType\":" << token.elevation_type;
        auto list = [&](const wchar_t* name, const std::vector<std::wstring>& values) {
            output << L',' << JsonString(name) << L":[";
            for (size_t i = 0; i < values.size(); ++i) { if (i) output << L','; output << JsonString(values[i]); }
            output << L']';
        };
        list(L"privileges", token.enabled_privileges); list(L"groups", token.groups); list(L"privilegeStates", token.privilege_states);
        list(L"restrictedSids", token.restricted_sids); list(L"capabilities", token.capabilities);
        output << L'}'; return output.str();
    }

    std::wstring CollectorSummaryJson(const CollectorData& collector) {
        std::wostringstream output;
        output << L"{\"requested\":" << collector.requested << L",\"received\":" << collector.received
            << L",\"cleanupConfirmed\":" << collector.cleanup_confirmed
            << L",\"error\":" << collector.error << L",\"errorOperation\":" << JsonString(collector.error_operation)
            << L",\"started\":" << JsonString(std::to_wstring(collector.started)) << L",\"finished\":" << JsonString(std::to_wstring(collector.finished))
            << L",\"debugRequested\":" << collector.debug_requested << L",\"debugEnabled\":" << collector.debug_enabled << L",\"debugError\":" << collector.debug_error
            << L",\"token\":" << (collector.received ? AccessTokenJson(collector.token) : L"null")
            << L",\"processScan\":" << ProcessScanJson(collector.processes) << L'}';
        return output.str();
    }

    void PrintAccessToken(const AccessTokenInfo& token, bool json) {
        if (json) {
            std::wcout << L"{\"record\":\"token\",\"sid\":" << JsonString(token.user_sid)
                << L",\"integrity\":" << token.integrity_level << L",\"elevated\":" << (token.elevated ? L"true" : L"false")
                << L",\"restricted\":" << (token.restricted ? L"true" : L"false")
                << L",\"app_container\":" << (token.app_container ? L"true" : L"false")
                << L",\"impersonating\":" << (token.impersonating ? L"true" : L"false")
                << L",\"error\":" << token.error << L",\"error_operation\":" << JsonString(token.error_operation)
                << L",\"enabled_privileges\":[";
            bool first = true;
            for (const auto& privilege : token.enabled_privileges) {
                if (!first) std::wcout << L',';
                first = false;
                std::wcout << JsonString(privilege);
            }
            std::wcout << L"],\"primary_context\":" << AccessTokenJson(token) << L"}" << std::endl;
            return;
        }
        std::wcout << L"Token: " << token.user_sid << L" | integrity=" << token.integrity_level
            << L" | elevated=" << token.elevated << L" | restricted=" << token.restricted
            << L" | app-container=" << token.app_container << L" | impersonating=" << token.impersonating << L'\n';
        std::wcout << L"Enabled privileges:";
        for (const auto& privilege : token.enabled_privileges)
            std::wcout << L' ' << privilege;
        std::wcout << std::endl;
    }

    void PrintAccessResult(const AccessTestResult& result, bool json) {
        if (json) {
            std::wcout << L"{\"record\":\"access\",\"type\":" << static_cast<unsigned>(result.object.type)
                << L",\"name\":" << JsonString(result.object.name)
                << L",\"native_type\":" << JsonString(result.object.native_type)
                << L",\"timestamp_filetime\":" << result.timestamp
                << L",\"observed_explicit_union\":" << result.observed_explicit
                << L",\"access_context\":\"user-primary\",\"discovery_source\":" << JsonString(CollectionSourceName(result.object.discovery_sources));
            if (result.object.session_id)
                std::wcout << L",\"session_id\":" << *result.object.session_id;
            if (result.object.rpc)
                std::wcout << L",\"rpc_interface\":" << JsonString(result.object.rpc->interface_id)
                    << L",\"rpc_major\":" << result.object.rpc->major_version << L",\"rpc_minor\":" << result.object.rpc->minor_version
                    << L",\"rpc_object\":" << JsonString(result.object.rpc->object_id);
            std::wcout << L",\"creator\":null,\"process_status\":" << JsonString(result.object.process_status) << L",\"processes\":[";
            for (size_t i = 0; i < result.object.processes.size(); ++i) {
                if (i) std::wcout << L',';
                const auto& association = result.object.processes[i];
                std::wcout << L"{\"process\":" << ProcessJson(association.process) << L",\"relation\":" << JsonString(association.relation)
                    << L",\"source\":" << JsonString(CollectionSourceName(association.sources)) << L'}';
            }
            std::wcout << L"],\"attempts\":[";
        }
        bool first = true;
        for (const auto& attempt : result.attempts) {
            const auto& observed = attempt.observation;
            const wchar_t* evidence = attempt.method == AccessMethod::OPEN ? L"handle-open" :
                attempt.method == AccessMethod::ALPC_CONNECT || attempt.method == AccessMethod::FILTER_CONNECT ? L"connection" : L"operation";
            if (json) {
                if (!first) std::wcout << L',';
                std::wcout << L"{\"name\":" << JsonString(attempt.name) << L",\"evidence\":" << JsonString(evidence)
                    << L",\"method\":" << static_cast<u32>(attempt.method)
                    << L",\"requested\":" << attempt.requested << L",\"status\":" << JsonString(AccessStatusName(observed.status))
                    << L",\"opened\":" << (observed.opened ? L"true" : L"false") << L",\"granted\":";
                if (observed.has_granted) std::wcout << observed.granted;
                else std::wcout << L"null";
                std::wcout << L",\"error_domain\":" << JsonString(AccessErrorName(observed.error_type))
                    << L",\"error\":" << observed.error << L",\"query_ntstatus\":" << observed.query_error
                    << L",\"elapsed_ms\":" << observed.elapsed_ms << L",\"detail\":" << JsonString(attempt.detail)
                    << L",\"context_verified\":" << observed.context_verified << L",\"context_error\":" << observed.context_error << L'}';
            }
            else {
                std::wcout << L"  " << attempt.name << L": " << AccessStatusName(observed.status)
                    << L" | " << evidence << L" | requested=0x" << std::hex << attempt.requested;
                if (observed.has_granted)
                    std::wcout << L" | granted=0x" << observed.granted;
                else if (observed.opened)
                    std::wcout << L" | opened; granted mask unavailable";
                if (observed.error)
                    std::wcout << L" | " << AccessErrorName(observed.error_type) << L"=0x" << observed.error;
                if (observed.query_error)
                    std::wcout << L" | query NTSTATUS=0x" << observed.query_error;
                std::wcout << std::dec << L" | " << observed.elapsed_ms << L" ms";
                if (observed.context_error) std::wcout << L" | INVALID CONTEXT=" << observed.context_error;
                else if (observed.context_verified) std::wcout << L" | user primary verified";
                if (!attempt.detail.empty()) std::wcout << L" | " << attempt.detail;
                std::wcout << L'\n';
            }
            first = false;
        }
        if (json) std::wcout << L"]}" << std::endl;
        else std::wcout << L"  Explicit observed union (not a combined grant): 0x" << std::hex << result.observed_explicit << std::dec << std::endl;
    }
}
