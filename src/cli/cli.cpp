#include <iostream>
#include <string>
#include <fcntl.h>
#include <io.h>
#include <filesystem>
#include "core/enumerator-manager.h"
#include "enumerators/enumerators.h"
#include "core/access-manager.h"
#include "cli/access-output.h"
#include "report/report-output.h"
#include "process/process-associator.h"
#include "process/process-worker.h"
#include "collection/admin-collector.h"

namespace {
    struct CliOptions {
        bool access = false;
        bool json = false;
        bool processes = true;
        bool admin_collect = false;
        bool admin_debug = false;
        bool skip_probes = false;
        u32 process_budget = 30000;
        std::wstring match;
        std::wstring html_path;
        std::wstring llm_path;
        win_obj::AccessOptions probes;
    };

    struct EnumerationOption {
        const wchar_t* name;
        win_obj::WinObjType type;
    };

    std::wstring ReportPathKey(const std::wstring& path) {
        auto absolute = std::filesystem::absolute(path).lexically_normal();
        // Resolve the existing parent directly. Walking every ancestor with
        // weakly_canonical can fail under restricted tokens even when it is writable.
        auto handle = CreateFileW(absolute.parent_path().c_str(), 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (handle == INVALID_HANDLE_VALUE) return absolute.wstring();
        win_obj::UniqueHandle directory(handle, CloseHandle);
        auto length = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED);
        if (!length) return absolute.wstring();
        std::wstring parent(length, L'\0');
        auto written = GetFinalPathNameByHandleW(handle, parent.data(), length, FILE_NAME_NORMALIZED);
        if (!written || written >= length) return absolute.wstring();
        parent.resize(written);
        return (std::filesystem::path(parent) / absolute.filename()).wstring();
    }

    constexpr EnumerationOption options[] = {
        { L"device", win_obj::DEVICE },
        { L"alpc", win_obj::ALPC },
        { L"rpc", win_obj::RPC },
        { L"flt", win_obj::FLT },
        { L"event", win_obj::EVENT },
        { L"job", win_obj::JOB },
        { L"mutant", win_obj::MUTANT },
        { L"namedpipe", win_obj::NAMEDPIPE },
        { L"semaphore", win_obj::SEMAPHORE },
        { L"sessions", win_obj::SESSIONS },
        { L"timer", win_obj::TIMER }
    };

    bool Enumerate(win_obj::EnumerationManager& manager, const EnumerationOption& option,
        const CliOptions& settings, win_obj::AccessManager* access, win_obj::ReportGroup* report, const win_obj::ProcessAssociator* processes, const win_obj::CollectedGroup* elevated) {
        auto objects = manager.Enumerate(option.type);
        if (objects && processes) processes->Apply(*objects);
        bool user_discovered = objects.has_value();
        size_t user_total = objects ? objects->size() : 0;
        if (elevated && elevated->discovered) {
            if (!objects) objects.emplace();
            win_obj::MergeCollectorObjects(*objects, *elevated);
        }
        bool console_rows = settings.json || (settings.html_path.empty() && settings.llm_path.empty());
        if (report) {
            report->discovered = objects.has_value();
            report->user_discovered = user_discovered;
            report->user_total = user_total;
            if (elevated) { report->admin_discovered = elevated->discovered; report->admin_total = elevated->objects.size(); report->admin_issues = elevated->issues; }
            report->total = objects ? objects->size() : 0;
        }
        if (!settings.json) std::wcout << L"[" << option.name << L"]" << std::endl;
        bool probe_success = true;
        size_t matched = 0;
        if (objects) {
            for (const auto& object : *objects) {
                if (!settings.match.empty() && object.name.find(settings.match) == std::wstring::npos)
                    continue;
                ++matched;
                win_obj::ReportObject* report_object = nullptr;
                if (report) {
                    report->objects.push_back({ object });
                    report_object = &report->objects.back();
                }
                if (!settings.json && console_rows) std::wcout << object.name << L" | discovery=" << win_obj::CollectionSourceName(object.discovery_sources);
                if (!settings.json && console_rows && object.rpc) {
                    std::wcout << L" | interface=" << object.rpc->interface_id
                        << L" v" << object.rpc->major_version << L"." << object.rpc->minor_version
                        << L" | object=" << object.rpc->object_id;
                }
                if (!settings.json && console_rows) {
                    for (const auto& association : object.processes)
                        std::wcout << L" | " << association.process.name << L" (PID " << association.process.pid << L", " << association.relation << L", " << win_obj::CollectionSourceName(association.sources) << L")";
                    if (object.processes.empty()) std::wcout << L" | processes=" << object.process_status;
                    std::wcout << L'\n';
                }
                if (access && settings.skip_probes) {
                    probe_success = false;
                    if (report_object) report_object->error = L"User probes skipped: administrator collector cleanup was not confirmed.";
                    if (settings.json) std::wcout << L"{\"record\":\"access_unavailable\",\"name\":" << win_obj::JsonString(object.name)
                        << L",\"reason\":\"administrator-cleanup-unconfirmed\"}" << std::endl;
                }
                if (access && !settings.skip_probes) {
                    auto result = access->Test(object, settings.probes);
                    if (!result) {
                        probe_success = false;
                        if (report_object) report_object->error = L"No access test registered.";
                        continue;
                    }
                    if (console_rows) win_obj::PrintAccessResult(*result, settings.json);
                    for (const auto& attempt : result->attempts) {
                        auto status = attempt.observation.status;
                        if (status == win_obj::AccessStatus::FAILED_PROBE || status == win_obj::AccessStatus::TIMEOUT ||
                            status == win_obj::AccessStatus::BUSY || status == win_obj::AccessStatus::UNAVAILABLE)
                            probe_success = false;
                    }
                    if (report_object) report_object->access = std::move(result);
                }
            }
            if (settings.json)
                std::wcout << L"{\"record\":\"summary\",\"type\":" << win_obj::JsonString(option.name)
                    << L",\"discovered\":" << objects->size() << L",\"user_discovered\":" << user_total
                    << L",\"administrator_discovered\":" << (elevated ? elevated->objects.size() : 0) << L",\"matched\":" << matched << L"}" << std::endl;
            else
                std::wcout << objects->size() << L" object(s) discovered; " << matched << L" matched" << std::endl;
        }
        else {
            std::wcerr << L"Discovery failed for " << option.name << std::endl;
        }

        const auto& issues = manager.GetIssues(option.type);
        if (report) {
            report->issues = issues;
            report->probes_completed = probe_success;
        }
        for (const auto& issue : issues) {
            auto domain = issue.type == win_obj::EnumerationErrorType::NT_ERROR ? L"NTSTATUS" :
                issue.type == win_obj::EnumerationErrorType::RPC_ERROR ? L"RPC" : L"Win32";
            std::wcerr << L"[" << option.name << L"] " << issue.name << L": " << domain
                << L" 0x" << std::hex << issue.error << std::dec << std::endl;
            if (settings.json)
                std::wcout << L"{\"record\":\"discovery_issue\",\"source\":\"user\",\"type\":" << win_obj::JsonString(option.name)
                    << L",\"name\":" << win_obj::JsonString(issue.name) << L",\"domain\":" << win_obj::JsonString(domain)
                    << L",\"error\":" << issue.error << L"}" << std::endl;
        }
        if (objects && !issues.empty())
            std::wcerr << L"Discovery was incomplete for " << option.name << std::endl;
        if (elevated) for (const auto& issue : elevated->issues) {
            std::wcerr << L"[administrator/" << option.name << L"] " << issue.name << L": 0x" << std::hex << issue.error << std::dec << std::endl;
            auto domain = issue.type == win_obj::EnumerationErrorType::NT_ERROR ? L"NTSTATUS" :
                issue.type == win_obj::EnumerationErrorType::RPC_ERROR ? L"RPC" : L"Win32";
            if (settings.json) std::wcout << L"{\"record\":\"discovery_issue\",\"source\":\"administrator\",\"type\":" << win_obj::JsonString(option.name)
                << L",\"name\":" << win_obj::JsonString(issue.name) << L",\"domain\":" << win_obj::JsonString(domain) << L",\"error\":" << issue.error << L"}" << std::endl;
        }
        return user_discovered && issues.empty() && probe_success && (!elevated || (elevated->discovered && elevated->issues.empty()));
    }
}

int wmain(int argc, wchar_t* argv[]) {
    if (auto collector = win_obj::AdminCollectorMain(argc, argv)) return *collector;
    if (auto worker = win_obj::ProcessWorkerMain(argc, argv))
        return *worker;
    if (auto worker = win_obj::AccessWorkerMain(argc, argv))
        return *worker;
    // Preserve Unicode object names both in the console and redirected output.
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);
    if (argc < 2) {
        std::wcerr << L"Usage: " << argv[0]
            << L" <all|device|alpc|rpc|flt|event|job|mutant|namedpipe|semaphore|sessions|timer>"
            << L" [--access] [--devices] [--connect] [--no-maximum] [--timeout <ms>] [--match <text>] [--json]"
            << L" [--html <file>] [--llm <file>] [--no-processes] [--process-budget <ms>] [--admin-collect] [--admin-debug]" << std::endl;
        return 1;
    }

    std::wstring option = argv[1];
    CliOptions settings;
    for (int i = 2; i < argc; ++i) {
        std::wstring argument = argv[i];
        if (argument == L"--access") settings.access = true;
        else if (argument == L"--devices") settings.probes.devices = true;
        else if (argument == L"--connect") settings.probes.connections = true;
        else if (argument == L"--no-maximum") settings.probes.maximum_allowed = false;
        else if (argument == L"--json") settings.json = true;
        else if (argument == L"--admin-collect") settings.admin_collect = true;
        else if (argument == L"--admin-debug") settings.admin_debug = true;
        else if (argument == L"--no-processes") settings.processes = false;
        else if (argument == L"--process-budget" && i + 1 < argc) {
            wchar_t* end = nullptr;
            auto value = wcstoul(argv[++i], &end, 10);
            if (!end || *end || !value || value > 300000) {
                std::wcerr << L"Process budget must be between 1 and 300000 milliseconds." << std::endl;
                return 1;
            }
            settings.process_budget = static_cast<u32>(value);
        }
        else if ((argument == L"--html" || argument == L"--llm") && i + 1 < argc) {
            auto& path = argument == L"--html" ? settings.html_path : settings.llm_path;
            if (!path.empty() || !argv[i + 1][0] || std::wstring_view(argv[i + 1]).starts_with(L"--")) {
                std::wcerr << L"Specify one nonempty file path for " << argument << std::endl;
                return 1;
            }
            path = argv[++i];
        }
        else if (argument == L"--match" && i + 1 < argc) settings.match = argv[++i];
        else if (argument == L"--timeout" && i + 1 < argc) {
            wchar_t* end = nullptr;
            auto value = wcstoul(argv[++i], &end, 10);
            if (!end || *end || !value || value > 60000) {
                std::wcerr << L"Timeout must be between 1 and 60000 milliseconds." << std::endl;
                return 1;
            }
            settings.probes.timeout_ms = static_cast<u32>(value);
        }
        else {
            std::wcerr << L"Unknown or incomplete option: " << argument << std::endl;
            return 1;
        }
    }
    if (!settings.access && (settings.json || settings.probes.devices || settings.probes.connections ||
        !settings.probes.maximum_allowed || settings.probes.timeout_ms != 2000)) {
        std::wcerr << L"Probe options and --json require --access." << std::endl;
        return 1;
    }
    if (settings.admin_debug && !settings.admin_collect) {
        std::wcerr << L"--admin-debug requires --admin-collect and affects only the elevated collector." << std::endl;
        return 1;
    }
    bool valid = option == L"all";
    for (const auto& entry : options)
        valid = valid || option == entry.name;
    if (!valid) {
        std::wcerr << L"Unknown option: " << option << std::endl;
        return 1;
    }

    // Validate paths before running potentially expensive access probes.
    try {
        for (const auto& path : { settings.html_path, settings.llm_path }) {
            if (path.empty()) continue;
            auto absolute = std::filesystem::absolute(path);
            if (!std::filesystem::is_directory(absolute.parent_path()) || std::filesystem::is_directory(absolute)) {
                std::wcerr << L"Report destination must be a file in an existing directory: " << path << std::endl;
                return 1;
            }
        }
        if (!settings.html_path.empty() && !settings.llm_path.empty()) {
            auto html = ReportPathKey(settings.html_path);
            auto llm = ReportPathKey(settings.llm_path);
            if (_wcsicmp(html.c_str(), llm.c_str()) == 0) {
                std::wcerr << L"HTML and LLM reports need different destination files." << std::endl;
                return 1;
            }
        }
    }
    catch (const std::filesystem::filesystem_error& error) {
        std::wcerr << L"Unable to resolve report destination: " << error.path1().wstring()
            << L" (error " << error.code().value() << L")" << std::endl;
        return 1;
    }

    bool exporting = !settings.html_path.empty() || !settings.llm_path.empty();
    win_obj::ScanReport report;
    report.started = win_obj::ReportTime();
    report.selection = option;
    report.match = settings.match;
    report.access_requested = settings.access;
    report.options = settings.probes;
    win_obj::AccessContext baseline;
    report.token = baseline.GetInfo();
    if (report.token->error || report.token->elevated) {
        std::wcerr << L"Run the scanner from the intended unelevated user context with no thread impersonation. "
            << L"Use --admin-collect to elevate only metadata collection. " << report.token->error_operation << std::endl;
        return 1;
    }
    auto export_files = [&] {
        report.finished = win_obj::ReportTime();
        bool written = true;
        for (const auto& destination : { std::pair{ settings.html_path, win_obj::ReportFormat::HTML },
            std::pair{ settings.llm_path, win_obj::ReportFormat::LLM } }) {
            if (destination.first.empty()) continue;
            std::wstring error;
            if (!win_obj::WriteReport(destination.first, report, destination.second, error)) {
                std::wcerr << error << L" (" << destination.first << L")" << std::endl;
                written = false;
            }
            else {
                std::wcerr << L"Saved report: " << destination.first << std::endl;
            }
        }
        return written;
    };

    win_obj::EnumerationManager manager;
    manager.Register(std::make_unique<win_obj::DeviceEnumerator>());
    manager.Register(std::make_unique<win_obj::AlpcEnumerator>());
    manager.Register(std::make_unique<win_obj::RpcEnumerator>());
    manager.Register(std::make_unique<win_obj::FltEnumerator>());
    manager.Register(std::make_unique<win_obj::EventEnumerator>());
    manager.Register(std::make_unique<win_obj::JobEnumerator>());
    manager.Register(std::make_unique<win_obj::MutantEnumerator>());
    manager.Register(std::make_unique<win_obj::NamedPipeEnumerator>());
    manager.Register(std::make_unique<win_obj::SemaphoreEnumerator>());
    manager.Register(std::make_unique<win_obj::SessionsEnumerator>());
    manager.Register(std::make_unique<win_obj::TimerEnumerator>());

    std::unique_ptr<win_obj::AccessManager> access;
    if (settings.access) {
        access = std::make_unique<win_obj::AccessManager>();
        if (access->GetTokenInfo().fingerprint != baseline.GetInfo().fingerprint) {
            report.user_context_error = ERROR_INVALID_DATA;
            std::wcerr << L"User primary context changed before access setup." << std::endl;
            if (exporting) export_files();
            return 1;
        }
        if (exporting) report.token = access->GetTokenInfo();
        win_obj::PrintAccessToken(access->GetTokenInfo(), settings.json);
        if (access->GetTokenInfo().error) {
            std::wcerr << L"Cannot capture primary token: " << access->GetTokenInfo().error_operation
                << L" failed with " << access->GetTokenInfo().error << std::endl;
            if (exporting) export_files();
            return 1;
        }
    }

    std::unique_ptr<win_obj::ProcessAssociator> processes;
    if (settings.processes) {
        u32 types = 0;
        for (const auto& entry : options) if (option == L"all" || option == entry.name) types |= 1u << entry.type;
        std::wcerr << L"Collecting process associations (creator attribution is unavailable)..." << std::endl;
        processes = std::make_unique<win_obj::ProcessAssociator>(types, settings.process_budget, std::vector<u32>{ GetCurrentProcessId() });
        report.processes = processes->GetInfo();
        const auto& info = report.processes;
        if (settings.json) std::wcout << L"{\"record\":\"process_scan\",\"coverage\":" << win_obj::ProcessScanJson(info) << L"}" << std::endl;
        std::wcerr << L"Process associations: " << info.queried << L" handle queries, " << info.failed << L" failures, "
            << info.inaccessible_processes << L" inaccessible processes, " << info.timeouts << L" timeouts"
            << (info.budget_exhausted ? L"; time budget exhausted" : L"") << L". Empty associations remain unknown." << std::endl;
        if (info.tcp_error) std::wcerr << L"TCP process snapshot: Win32 0x" << std::hex << info.tcp_error << std::dec << std::endl;
        if (info.error) std::wcerr << info.error_operation << L": 0x" << std::hex << info.error << std::dec << std::endl;
    }
    if (settings.admin_collect) {
        win_obj::CollectorOptions collector;
        for (const auto& entry : options) if (option == L"all" || option == entry.name) collector.types |= 1u << entry.type;
        collector.processes = settings.processes;
        collector.process_budget_ms = settings.process_budget;
        collector.debug_privilege = settings.admin_debug;
        std::wcerr << L"Requesting administrator collection. User access probes stay in the original primary context." << std::endl;
        report.admin = win_obj::CollectAsAdministrator(collector);
        settings.skip_probes = !report.admin.cleanup_confirmed;
        if (settings.skip_probes) std::wcerr << L"Collector cleanup was not confirmed; user access probes will be skipped." << std::endl;
        if (report.admin.debug_error) std::wcerr << L"Collector debug privilege activation failed: Win32 " << report.admin.debug_error << std::endl;
        if (settings.json) std::wcout << L"{\"record\":\"administrator_collection\",\"collection\":" << win_obj::CollectorSummaryJson(report.admin) << L"}" << std::endl;
        if (report.admin.error) std::wcerr << report.admin.error_operation << L": Win32 " << report.admin.error << L"; retaining user results." << std::endl;
        else std::wcerr << L"Administrator collector exited; user access tests will use the original primary context." << std::endl;
    }
    // Process coverage has its own status; it cannot make historical creator attribution complete.
    bool success = !report.admin.error && !report.admin.debug_error;
    for (const auto& entry : options) {
        if (option == L"all" || option == entry.name) {
            win_obj::ReportGroup* group = nullptr;
            if (exporting) {
                report.groups.push_back({ entry.type });
                group = &report.groups.back();
            }
            const win_obj::CollectedGroup* elevated = nullptr;
            if (report.admin.received && !report.admin.error)
                for (const auto& collected : report.admin.groups) if (collected.type == entry.type) elevated = &collected;
            if (!Enumerate(manager, entry, settings, access.get(), group, processes.get(), elevated))
                success = false;
        }
    }
    if (auto error = win_obj::VerifyUnchangedPrimaryContext(baseline.GetInfo())) {
        success = false;
        report.user_context_error = error;
        if (settings.json) std::wcout << L"{\"record\":\"user_context_error\",\"error\":" << error << L"}" << std::endl;
        std::wcerr << L"User primary context changed during scan: " << error << std::endl;
    }
    report.completed = success;
    if (exporting && !export_files()) success = false;
    return success ? 0 : 1;
}
