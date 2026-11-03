#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <thread>
#include "core/access-manager.h"
#include "access/native-probe.h"
#include "cli/access-output.h"
#include "native/alpc.h"
#include <sddl.h>
#include <rpc.h>

namespace {
    using namespace win_obj;

    void Check(bool condition, const char* message) {
        if (!condition) throw std::runtime_error(message);
    }

    UniqueHandle Own(HANDLE handle) {
        Check(handle && handle != INVALID_HANDLE_VALUE, "Fixture creation failed");
        return UniqueHandle(handle, CloseHandle);
    }

    const AccessAttempt& Find(const AccessTestResult& result, const wchar_t* name) {
        auto it = std::find_if(result.attempts.begin(), result.attempts.end(), [&](const AccessAttempt& attempt) { return attempt.name == name; });
        Check(it != result.attempts.end(), "Expected right missing from catalog");
        return *it;
    }

    class DriverProbe final : public IAccessProbe {
    public:
        int maximum_mode = 0;
        std::vector<ACCESS_MASK> requested;
        AccessObservation Execute(AccessMethod, ACCESS_MASK access) override {
            requested.push_back(access);
            if (access == MAXIMUM_ALLOWED) {
                if (!maximum_mode) return AccessFailure(ERROR_ACCESS_DENIED, AccessErrorType::WIN32_ERROR);
                AccessObservation result{};
                result.status = AccessStatus::GRANTED;
                result.opened = result.has_granted = 1;
                result.granted = maximum_mode == 1 ? 0 : FILE_ALL_ACCESS;
                return result;
            }
            if (access == FILE_READ_DATA || access == FILE_READ_ATTRIBUTES || access == FILE_WRITE_DATA) {
                AccessObservation result{};
                result.status = AccessStatus::GRANTED;
                result.opened = result.has_granted = 1;
                result.granted = access;
                return result;
            }
            return AccessFailure(ERROR_ACCESS_DENIED, AccessErrorType::WIN32_ERROR);
        }
    };

    AccessObservation TestProbe(const WinObj& object, AccessMethod method, ACCESS_MASK access, u32 timeout) {
        HANDLE thread_token = nullptr;
        if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &thread_token)) {
            CloseHandle(thread_token); throw std::runtime_error("Access callback is impersonating");
        }
        if (GetLastError() != ERROR_NO_TOKEN) throw std::runtime_error("Cannot verify absence of thread token");
        if (object.native_type == L"TestPrivilegeChange") {
            HANDLE raw = nullptr;
            Check(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &raw) != FALSE, "Cannot open fixture worker token");
            auto token = Own(raw);
            TOKEN_PRIVILEGES privileges{}; privileges.PrivilegeCount = 1;
            Check(LookupPrivilegeValueW(nullptr, L"SeChangeNotifyPrivilege", &privileges.Privileges[0].Luid) != FALSE, "Privilege fixture lookup failed");
            Check(AdjustTokenPrivileges(token.get(), FALSE, &privileges, 0, nullptr, nullptr) != FALSE, "Privilege fixture adjustment failed");
            return ProbeNativeObject(object, method, access, timeout);
        }
        if (object.native_type == L"TestContextChange") {
            ImpersonateSelf(SecurityImpersonation);
            return ProbeNativeObject(object, method, access, timeout);
        }
        if (object.native_type == L"TestTimeout" && access == 1)
            Sleep(10000);
        return ProbeNativeObject(object, method, access, timeout);
    }

    void TestDriverRegression() {
        ObjectAccessTest test(DEVICE);
        WinObj object{ DEVICE, L"\\Device\\TestDriver" };
        AccessOptions options;
        options.devices = true;
        for (int mode = 0; mode < 3; ++mode) {
            DriverProbe probe;
            probe.maximum_mode = mode;
            auto result = test.Test(object, options, probe);
            Check(Find(result, L"FILE_READ_DATA").observation.status == AccessStatus::GRANTED, "Read access lost due to maximum request");
            Check(Find(result, L"FILE_READ_ATTRIBUTES").observation.status == AccessStatus::GRANTED, "Query access lost due to maximum request");
            Check(result.observed_explicit == (FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES), "Maximum result polluted explicit summary");
            Check(Find(result, L"READ_WRITE_DATA").observation.status == AccessStatus::DENIED, "Individual grants incorrectly prove a combined grant");
            Check(probe.requested.back() == MAXIMUM_ALLOWED, "Maximum request must come after explicit probes");
            Check(std::count(probe.requested.begin(), probe.requested.end(), static_cast<ACCESS_MASK>(FILE_READ_DATA)) == 1, "Specific right not tested independently");
        }
        DriverProbe probe;
        options.maximum_allowed = false;
        auto result = test.Test(object, options, probe);
        Check(std::find(probe.requested.begin(), probe.requested.end(), static_cast<ACCESS_MASK>(MAXIMUM_ALLOWED)) == probe.requested.end(), "Disabled maximum probe executed");
        Check(Find(result, L"MAXIMUM_ALLOWED").observation.status == AccessStatus::SKIPPED, "Disabled maximum probe not reported");
        probe.requested.clear();
        options.devices = false;
        test.Test(object, options, probe);
        Check(probe.requested.empty(), "Device opens must be explicitly selected");

        for (u8 type = DEVICE; type <= TIMER; ++type) {
            ObjectAccessTest catalog(static_cast<WinObjType>(type));
            auto coverage = catalog.Test({ type, L"fixture" }, {}, probe);
            Check(!coverage.attempts.empty(), "Object type has no access coverage");
        }
        Check(AccessFailure(ERROR_PIPE_BUSY, AccessErrorType::WIN32_ERROR).status == AccessStatus::BUSY, "Busy pipe classified as denied");
        Check(AccessFailure(ERROR_PRIVILEGE_NOT_HELD, AccessErrorType::WIN32_ERROR).status == AccessStatus::PRIVILEGE_REQUIRED, "Privilege failure misclassified");
        Check(AccessFailure(0xc0000034, AccessErrorType::NT_ERROR).status == AccessStatus::UNAVAILABLE, "Missing object misclassified");
        Check(JsonString(L"a\"\\\n\u03a9") == L"\"a\\\"\\\\\\u000a\u03a9\"", "JSON escaping failed");
    }

    void TestFixtures() {
        auto suffix = L"win-obj-access-" + std::to_wstring(GetCurrentProcessId()) + L"-\u03a9";
        DWORD session = 0;
        Check(ProcessIdToSessionId(GetCurrentProcessId(), &session) != FALSE, "Session lookup failed");
        auto native = L"\\Sessions\\" + std::to_wstring(session) + L"\\BaseNamedObjects\\" + suffix;
        auto local = L"Local\\" + suffix;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(D;;0x2;;;WD)(A;;0x120001;;;WD)",
            SDDL_REVISION_1, &descriptor, nullptr) != FALSE, "Fixture descriptor failed");
        struct DescriptorCleanup { PSECURITY_DESCRIPTOR value; ~DescriptorCleanup() { LocalFree(value); } } cleanup{ descriptor };
        SECURITY_ATTRIBUTES security{ sizeof(security), descriptor, FALSE };
        auto event = Own(CreateEventExW(&security, (local + L"-restricted").c_str(), CREATE_EVENT_MANUAL_RESET, SYNCHRONIZE | 1));
        AccessManager manager;
        Check(manager.GetTokenInfo().error == 0, "Token capture failed");
        auto result = manager.Test({ EVENT, native + L"-restricted" });
        Check(result.has_value(), "Missing event access test");
        Check(Find(*result, L"EVENT_QUERY_STATE").observation.status == AccessStatus::GRANTED, "Allowed event query failed");
        Check(Find(*result, L"EVENT_QUERY_STATE").observation.context_verified == 1, "Primary context verification missing");
        Check(Find(*result, L"EVENT_MODIFY_STATE").observation.status == AccessStatus::DENIED, "Denied event modify was granted");
        Check(Find(*result, L"ALL_ACCESS").observation.status == AccessStatus::DENIED, "Full-access failure lost");
        Check(WaitForSingleObject(event.get(), 0) == WAIT_TIMEOUT, "Probe changed event state");

        WinObj changed{ EVENT, native + L"-restricted" }; changed.native_type = L"TestContextChange";
        auto invalid = manager.Test(changed);
        for (const auto& attempt : invalid->attempts) if (attempt.observation.opened || attempt.observation.has_granted)
            Check(false, "Token change after open leaked a grant");
        Check(Find(*invalid, L"EVENT_QUERY_STATE").observation.context_error != 0 && invalid->observed_explicit == 0,
            "Post-probe context change was not invalidated");
        changed.native_type = L"TestPrivilegeChange";
        auto changed_privilege = manager.Test(changed);
        Check(Find(*changed_privilege, L"EVENT_QUERY_STATE").observation.context_error && changed_privilege->observed_explicit == 0,
            "Worker privilege change was not invalidated");
        Check(VerifyUnchangedPrimaryContext(manager.GetTokenInfo()) == 0, "Worker modified the parent primary token");
        auto normal_event = Own(CreateEventW(nullptr, TRUE, FALSE, (local + L"-event").c_str()));
        auto mutant = Own(CreateMutexW(nullptr, FALSE, (local + L"-mutant").c_str()));
        auto semaphore = Own(CreateSemaphoreW(nullptr, 0, 2, (local + L"-semaphore").c_str()));
        auto timer = Own(CreateWaitableTimerW(nullptr, TRUE, (local + L"-timer").c_str()));
        auto job = Own(CreateJobObjectW(nullptr, (local + L"-job").c_str()));
        const std::pair<WinObj, const wchar_t*> objects[] = {
            { { EVENT, native + L"-event" }, L"EVENT_MODIFY_STATE" },
            { { MUTANT, native + L"-mutant" }, L"MUTANT_QUERY_STATE" },
            { { SEMAPHORE, native + L"-semaphore" }, L"SEMAPHORE_MODIFY_STATE" },
            { { TIMER, native + L"-timer" }, L"TIMER_MODIFY_STATE" },
            { { JOB, native + L"-job" }, L"JOB_OBJECT_QUERY" }
        };
        for (const auto& fixture : objects) {
            auto access = manager.Test(fixture.first);
            Check(access.has_value(), "Missing access test");
            Check(Find(*access, fixture.second).observation.status == AccessStatus::GRANTED, "Fixture open failed");
            for (const auto& attempt : access->attempts)
                Check(attempt.observation.status != AccessStatus::TIMEOUT, "Fixture probe unexpectedly timed out");
        }
        Check(!ReleaseMutex(mutant.get()) && GetLastError() == ERROR_NOT_OWNER, "Probe acquired mutex");
        LONG previous = -1;
        Check(ReleaseSemaphore(semaphore.get(), 1, &previous) != FALSE && previous == 0, "Probe changed semaphore count");
        Check(WaitForSingleObject(timer.get(), 0) == WAIT_TIMEOUT, "Probe changed timer state");

        AccessContext context;
        WinObj timeout_object{ EVENT, native + L"-event" };
        timeout_object.native_type = L"TestTimeout";
        AccessOptions options;
        options.timeout_ms = 500;
        AccessProbeWorker worker(timeout_object, options, context);
        auto timed_out = worker.Execute(AccessMethod::OPEN, 1);
        Check(timed_out.status == AccessStatus::TIMEOUT && timed_out.elapsed_ms < 4000, "Worker deadline not enforced");
        auto recovered = worker.Execute(AccessMethod::OPEN, EVENT_MODIFY_STATE);
        Check(recovered.status == AccessStatus::GRANTED, "Worker did not recover after timeout");

        auto pipe_name = L"\\\\.\\pipe\\" + suffix;
        auto pipe = Own(CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_WAIT, 1, 1024, 1024, 0, nullptr));
        auto connected = Own(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        OVERLAPPED pending{};
        pending.hEvent = connected.get();
        Check(!ConnectNamedPipe(pipe.get(), &pending) && GetLastError() == ERROR_IO_PENDING, "Pipe listener failed");
        AccessProbeWorker pipe_worker({ NAMEDPIPE, pipe_name }, {}, context);
        auto read = pipe_worker.Execute(AccessMethod::OPEN, FILE_READ_DATA);
        Check(read.status == AccessStatus::GRANTED && (read.granted & FILE_READ_DATA), "Pipe client read probe failed");
        DWORD transferred = 0;
        Check(GetOverlappedResult(pipe.get(), &pending, &transferred, TRUE) != FALSE, "Pipe connection did not complete");
        DisconnectNamedPipe(pipe.get());
        ResetEvent(connected.get());
        pending = {};
        pending.hEvent = connected.get();
        Check(!ConnectNamedPipe(pipe.get(), &pending) && GetLastError() == ERROR_IO_PENDING, "Pipe relisten failed");
        auto client = Own(CreateFileW(pipe_name.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr));
        Check(GetOverlappedResult(pipe.get(), &pending, &transferred, TRUE) != FALSE, "Second pipe connection did not complete");
        auto busy = pipe_worker.Execute(AccessMethod::OPEN, FILE_READ_DATA);
        Check(busy.status == AccessStatus::BUSY, "Occupied pipe not reported busy");
        client.reset();
        DisconnectNamedPipe(pipe.get());

        AccessProbeWorker null_device({ DEVICE, L"\\Device\\Null" }, {}, context);
        auto null_read = null_device.Execute(AccessMethod::OPEN, FILE_READ_DATA);
        Check(null_read.status == AccessStatus::GRANTED, "Native device read open failed");
        WinObj session_object{ SESSIONS, L"test session" };
        session_object.session_id = session;
        auto session_result = manager.Test(session_object);
        Check(Find(*session_result, L"QUERY_INFORMATION").observation.status == AccessStatus::GRANTED, "Session query failed");
        Check(Find(*session_result, L"LOGOFF").observation.status == AccessStatus::UNSUPPORTED, "Session mutation should not be attempted");

        DWORD before = 0, after = 0;
        GetProcessHandleCount(GetCurrentProcess(), &before);
        for (int i = 0; i < 5; ++i) {
            auto scan = manager.Test({ EVENT, native + L"-event" });
            Check(Find(*scan, L"EVENT_QUERY_STATE").observation.status == AccessStatus::GRANTED, "Repeated access scan failed");
        }
        GetProcessHandleCount(GetCurrentProcess(), &after);
        Check(after <= before + 1, "Access workers leaked parent handles");
        normal_event.reset();
        auto missing = manager.Test({ EVENT, native + L"-event" });
        Check(Find(*missing, L"EVENT_QUERY_STATE").observation.status == AccessStatus::UNAVAILABLE, "Removed object not reported unavailable");

        HANDLE raw_token = nullptr;
        Check(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &raw_token) != FALSE, "Token open failed");
        auto token = Own(raw_token);
        HANDLE raw_restricted = nullptr;
        unsigned char restricted_sid[SECURITY_MAX_SID_SIZE]{};
        DWORD sid_size = sizeof(restricted_sid);
        Check(CreateWellKnownSid(WinRestrictedCodeSid, nullptr, restricted_sid, &sid_size) != FALSE, "Restricted SID creation failed");
        SID_AND_ATTRIBUTES restricting{ restricted_sid, 0 };
        Check(CreateRestrictedToken(token.get(), DISABLE_MAX_PRIVILEGE, 0, nullptr, 0, nullptr, 1, &restricting, &raw_restricted) != FALSE,
            "Restricted token creation failed");
        auto restricted = Own(raw_restricted);
        HANDLE raw_impersonation = nullptr;
        Check(DuplicateTokenEx(restricted.get(), TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, nullptr,
            SecurityImpersonation, TokenImpersonation, &raw_impersonation) != FALSE, "Token duplication failed");
        auto impersonation = Own(raw_impersonation);
        Check(SetThreadToken(nullptr, impersonation.get()) != FALSE, "Impersonation failed");
        AccessManager impersonated_manager;
        RevertToSelf();
        Check(impersonated_manager.GetTokenInfo().error == ERROR_BAD_TOKEN_TYPE && impersonated_manager.GetTokenInfo().impersonating,
            "Impersonation was not refused");
        auto restricted_result = impersonated_manager.Test({ EVENT, native + L"-restricted" });
        const auto& rejected = Find(*restricted_result, L"EVENT_QUERY_STATE").observation;
        Check(rejected.status == AccessStatus::FAILED_PROBE && rejected.context_error && !rejected.opened && !rejected.has_granted,
            "Invalid context produced access evidence");
        Check(VerifyPrimaryContext(context.GetInfo().fingerprint) == 0, "User baseline changed during probes");
    }

    void TestAlpc() {
        auto module = GetModuleHandleW(L"ntdll.dll");
        auto create = reinterpret_cast<AlpcCreate>(GetProcAddress(module, "NtAlpcCreatePort"));
        auto receive = reinterpret_cast<AlpcReceive>(GetProcAddress(module, "NtAlpcSendWaitReceivePort"));
        auto accept = reinterpret_cast<AlpcAccept>(GetProcAddress(module, "NtAlpcAcceptConnectPort"));
        Check(create && receive && accept, "ALPC fixture APIs unavailable");
        auto path = L"\\RPC Control\\win-obj-access-" + std::to_wstring(GetCurrentProcessId());
        UNICODE_STRING name{};
        name.Buffer = path.data();
        name.Length = static_cast<USHORT>(path.size() * sizeof(wchar_t));
        name.MaximumLength = name.Length;
        OBJECT_ATTRIBUTES attributes{};
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
        NativePortAttributes port{};
        port.qos = { sizeof(SECURITY_QUALITY_OF_SERVICE), SecurityIdentification, SECURITY_STATIC_TRACKING, FALSE };
        port.max_message_length = 256;
        HANDLE raw = nullptr;
        Check(create(&raw, &attributes, &port) == 0, "ALPC fixture creation failed");
        auto server = Own(raw);
        auto done = Own(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        NTSTATUS server_status = 0;
        std::jthread listener([&] {
            alignas(NativePortMessage) unsigned char buffer[1024]{};
            auto message = reinterpret_cast<NativePortMessage*>(buffer);
            SIZE_T length = sizeof(buffer);
            LARGE_INTEGER timeout{};
            timeout.QuadPart = -30000000;
            server_status = receive(server.get(), 0, nullptr, nullptr, message, &length, nullptr, &timeout);
            if (server_status != 0) return;
            HANDLE client = nullptr;
            server_status = accept(&client, server.get(), 0, nullptr, &port, nullptr, message, nullptr, TRUE);
            UniqueHandle connection(client, CloseHandle);
            if (server_status == 0) WaitForSingleObject(done.get(), 3000);
        });
        AccessContext context;
        WinObj object{ ALPC, path };
        object.native_type = L"ALPC Port";
        AccessProbeWorker worker(object, {}, context);
        auto result = worker.Execute(AccessMethod::ALPC_CONNECT, 0);
        SetEvent(done.get());
        listener.join();
        if (server_status != 0 || result.status != AccessStatus::GRANTED)
            std::cerr << "ALPC server status 0x" << std::hex << static_cast<u32>(server_status)
                << ", client error 0x" << result.error << ", query 0x" << result.query_error << std::dec << std::endl;
        Check(server_status == 0, "ALPC server handshake failed");
        Check(result.status == AccessStatus::GRANTED && result.opened, "ALPC connection probe failed");

        AccessProbeWorker filter({ FLT, L"\\win-obj-nonexistent-filter-" + std::to_wstring(GetCurrentProcessId()) }, {}, context);
        auto missing = filter.Execute(AccessMethod::FILTER_CONNECT, 0);
        Check(missing.status == AccessStatus::UNAVAILABLE && missing.error_type == AccessErrorType::HRESULT_ERROR,
            "Missing filter port not reported with HRESULT");
    }

    void RPC_ENTRY RejectApplicationCall(PRPC_MESSAGE) {
        RpcRaiseException(RPC_S_CANNOT_SUPPORT);
    }

    void TestRpc() {
        RPC_SERVER_INTERFACE rpc_interface{};
        rpc_interface.Length = sizeof(rpc_interface);
        Check(UuidCreate(&rpc_interface.InterfaceId.SyntaxGUID) == RPC_S_OK, "RPC fixture UUID failed");
        rpc_interface.InterfaceId.SyntaxVersion.MajorVersion = 1;
        rpc_interface.TransferSyntax.SyntaxGUID = { 0x8a885d04, 0x1ceb, 0x11c9, { 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 } };
        rpc_interface.TransferSyntax.SyntaxVersion.MajorVersion = 2;
        RPC_DISPATCH_FUNCTION functions[] = { RejectApplicationCall };
        RPC_DISPATCH_TABLE dispatch{ 1, functions, 0 };
        rpc_interface.DispatchTable = &dispatch;
        auto endpoint = L"win-obj-access-rpc-" + std::to_wstring(GetCurrentProcessId());
        Check(RpcServerUseProtseqEpW(reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
            RPC_C_PROTSEQ_MAX_REQS_DEFAULT, reinterpret_cast<RPC_WSTR>(endpoint.data()), nullptr) == RPC_S_OK, "RPC endpoint creation failed");
        Check(RpcServerRegisterIf(&rpc_interface, nullptr, nullptr) == RPC_S_OK, "RPC rpc_interface registration failed");
        struct RpcCleanup {
            RPC_IF_HANDLE rpc_interface;
            ~RpcCleanup() { RpcMgmtStopServerListening(nullptr); RpcServerUnregisterIf(rpc_interface, nullptr, TRUE); }
        } cleanup{ &rpc_interface };
        Check(RpcServerRegisterAuthInfoW(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr) == RPC_S_OK, "RPC authentication setup failed");
        Check(RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE) == RPC_S_OK, "RPC listener failed");
        AccessContext context;
        AccessProbeWorker worker({ RPC, L"ncalrpc:[" + endpoint + L"]" }, {}, context);
        auto result = worker.Execute(AccessMethod::RPC_QUERY, 0);
        if (result.status != AccessStatus::GRANTED)
            std::cerr << "RPC fixture error " << result.error << std::endl;
        Check(result.status == AccessStatus::GRANTED && !result.has_granted, "RPC management evidence incorrect");
    }
}

int wmain(int argc, wchar_t* argv[]) {
    if (auto worker = win_obj::AccessWorkerMain(argc, argv, TestProbe)) return *worker;
    try {
        TestDriverRegression();
        TestFixtures();
        TestAlpc();
        TestRpc();
        std::cout << "Access tests passed" << std::endl;
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << error.what() << " (last error " << GetLastError() << ")" << std::endl;
        return 1;
    }
}
