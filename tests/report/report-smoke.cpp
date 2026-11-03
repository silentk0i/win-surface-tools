#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include "report/report-output.h"
#include "cli/access-output.h"
#include "native/handle.h"

namespace {
    using namespace win_obj;
    void Check(bool condition, const char* message) {
        if (!condition) throw std::runtime_error(message);
    }

    ScanReport Fixture() {
        ScanReport report;
        report.started = L"2026-10-24T12:00:00Z";
        report.finished = L"2026-10-24T12:00:05Z";
        report.selection = L"all";
        report.access_requested = true;
        report.completed = false;
        report.processes.requested = true;
        report.processes.failed = 3;
        report.processes.inaccessible_processes = 1;
        report.admin.requested = report.admin.received = true;
        report.admin.token.elevated = true;
        report.admin.token.user_sid = L"S-1-5-21-administrator";
        report.admin.debug_requested = report.admin.debug_enabled = true;
        report.admin.processes.requested = true;
        report.admin.processes.failed = 2;
        report.token = AccessTokenInfo{};
        report.token->user_sid = L"S-1-5-21-test";
        report.token->enabled_privileges.push_back(L"SeChangeNotifyPrivilege");
        ReportGroup events{ EVENT };
        events.discovered = events.user_discovered = events.admin_discovered = true;
        events.user_total = 500; events.admin_total = 2;
        events.admin_issues.push_back({ L"\\Protected", 5, EnumerationErrorType::WIN32_ERROR });
        events.total = 500;
        events.issues.push_back({ L"\\Private", 0xc0000022, EnumerationErrorType::NT_ERROR });
        for (u32 i = 0; i < 125; ++i) {
            WinObj object{ EVENT, L"\\BaseNamedObjects\\Event-" + std::to_wstring(i) };
            if (i == 0) object.name = L"\\BaseNamedObjects\\<script>alert(1)</script> & \"\u03a9\"\nline";
            object.native_type = L"Event";
            object.process_status = L"observed";
            object.discovery_sources = i == 0 ? 3 : i == 1 ? 2 : 1;
            object.processes.push_back({ { 42, L"Svchost.exe", 133700000000000001ULL, 0 }, L"handle-holder" });
            if (i == 0) object.processes.push_back({ { 142, L"helper-\u03a9</script>.exe", 133700000000000002ULL, 2 }, L"handle-holder" });
            if (i == 0) {
                object.processes.push_back({ { 242, L"third.exe", 133700000000000004ULL, 2 }, L"handle-holder" });
                object.processes.push_back({ { 342, L"hidden-holder.exe", 133700000000000005ULL, 2 }, L"handle-holder" });
            }
            if (i == 0) {
                object.processes[0].sources = 3; object.processes[1].sources = 2; object.processes[3].sources = 2;
                object.processes[1].process.image_path = L"C:\\test\\helper.exe";
            }
            AccessTestResult access{ object };
            access.timestamp = 134373168000000000ULL + i;
            access.observed_explicit = 1;
            AccessAttempt query{ L"EVENT_QUERY_STATE", AccessMethod::OPEN, 1 };
            query.observation.status = AccessStatus::GRANTED;
            query.observation.granted = 1;
            query.observation.has_granted = query.observation.opened = 1;
            query.observation.elapsed_ms = i;
            AccessAttempt modify{ L"EVENT_MODIFY_STATE", AccessMethod::OPEN, 2 };
            modify.observation.status = AccessStatus::DENIED;
            modify.observation.error_type = AccessErrorType::NT_ERROR;
            modify.observation.error = 0xc0000022;
            modify.detail = L"detail </script><script>window.reportInjected=1</script>";
            AccessAttempt maximum{ L"MAXIMUM_ALLOWED", AccessMethod::OPEN, MAXIMUM_ALLOWED };
            maximum.observation.status = AccessStatus::GRANTED;
            maximum.observation.has_granted = maximum.observation.opened = 1;
            // A successful zero-grant maximum response must not hide the explicit query grant.
            query.observation.context_verified = modify.observation.context_verified = maximum.observation.context_verified = 1;
            access.attempts = { query, modify, maximum };
            events.objects.push_back({ object, access });
        }
        report.groups.push_back(std::move(events));
        ReportGroup pipes{ NAMEDPIPE };
        pipes.discovered = pipes.user_discovered = true; pipes.user_total = 1;
        pipes.probes_completed = false;
        pipes.total = 1;
        pipes.issues.push_back({ L"\\Private", 0xc0000022, EnumerationErrorType::NT_ERROR });
        WinObj pipe{ NAMEDPIPE, L"\\\\.\\pipe\\busy" };
        pipe.process_status = L"observed";
        pipe.processes.push_back({ { 142, L"helper-\u03a9</script>.exe", 133700000000000002ULL, 2 }, L"pipe-server" });
        // Same PID at a different creation time must remain a separate identity.
        pipe.processes.push_back({ { 42, L"reused.exe", 133700000000000003ULL, 2 }, L"handle-holder" });
        AccessTestResult pipe_access{ pipe };
        AccessAttempt attempt{ L"FILE_READ_DATA", AccessMethod::OPEN, FILE_READ_DATA };
        attempt.observation.status = AccessStatus::BUSY;
        attempt.observation.error_type = AccessErrorType::WIN32_ERROR;
        attempt.observation.error = ERROR_PIPE_BUSY;
        pipe_access.attempts.push_back(attempt);
        pipes.objects.push_back({ pipe, pipe_access });
        report.groups.push_back(std::move(pipes));
        ReportGroup sessions{ SESSIONS };
        sessions.discovered = sessions.user_discovered = true; sessions.user_total = 1;
        sessions.total = 1;
        WinObj session{ SESSIONS, L"Session 0" };
        session.session_id = 0;
        sessions.objects.push_back({ session });
        report.groups.push_back(std::move(sessions));
        report.groups.push_back({ RPC }); // A failed source must survive the export.
        return report;
    }
}

int main() {
    using namespace win_obj;
    try {
        auto report = Fixture();
        auto html = RenderReport(report, ReportFormat::HTML);
        auto llm = RenderReport(report, ReportFormat::LLM);
        Check(html.find(L"<script>alert(1)</script>") == std::wstring::npos, "Object name escaped its data block");
        Check(html.find(L"</script><script>window.reportInjected") == std::wstring::npos, "Note escaped its data block");
        Check(html.find(L"\\u003cscript\\u003e") != std::wstring::npos, "Script-safe JSON escaping missing");
        Check(llm.find(L"r2:G,o,g=0x0") != std::wstring::npos, "Zero grant lost");
        Check(llm.find(L"ISSUE event,namedpipe NTSTATUS:0xc0000022") != std::wstring::npos, "Repeated issues not consolidated");
        Check(llm.find(L"TYPE rpc discovered=0 matched=0 discovery=failed") != std::wstring::npos, "Failed discovery lost");

        std::wostringstream verbose;
        auto previous = std::wcout.rdbuf(verbose.rdbuf());
        for (const auto& group : report.groups)
            for (const auto& object : group.objects)
                if (object.access) PrintAccessResult(*object.access, true);
        std::wcout.rdbuf(previous);
        Check(llm.size() * 3 < verbose.str().size(), "Repeated access output was not substantially compacted");

        auto directory = std::filesystem::path(L"build/tests/reports");
        std::filesystem::create_directories(directory);
        std::wstring error;
        Check(WriteReport((directory / L"fixture.html").wstring(), report, ReportFormat::HTML, error), "HTML write failed");
        Check(WriteReport((directory / L"fixture-\u03a9.txt").wstring(), report, ReportFormat::LLM, error), "Unicode report path failed");
        auto empty = ScanReport{};
        empty.started = empty.finished = ReportTime();
        empty.selection = L"event";
        empty.completed = true;
        empty.groups.push_back({ EVENT, true });
        empty.groups.back().user_discovered = true;
        Check(WriteReport((directory / L"empty.html").wstring(), empty, ReportFormat::HTML, error), "Empty report write failed");
        Check(!WriteReport((directory / L"missing" / L"file.txt").wstring(), report, ReportFormat::LLM, error), "Invalid output parent accepted");
        auto locked_path = directory / L"locked.txt";
        { std::ofstream original(locked_path, std::ios::binary); original << "original"; }
        UniqueHandle locked(CreateFileW(locked_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr), CloseHandle);
        Check(locked.get() != INVALID_HANDLE_VALUE, "Cannot lock fixture output");
        Check(!WriteReport(locked_path.wstring(), report, ReportFormat::LLM, error), "Locked output unexpectedly replaced");
        locked.reset();
        std::ifstream original(locked_path, std::ios::binary);
        std::string contents((std::istreambuf_iterator<char>(original)), std::istreambuf_iterator<char>());
        Check(contents == "original", "Failed export destroyed existing report");
        for (const auto& file : std::filesystem::directory_iterator(directory))
            Check(file.path().filename().wstring().find(L".tmp-") == std::wstring::npos, "Temporary export file leaked");
        std::cout << "Report tests passed; compact text " << llm.size() << " chars vs JSONL " << verbose.str().size() << " chars" << std::endl;
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << error.what() << std::endl;
        return 1;
    }
}
