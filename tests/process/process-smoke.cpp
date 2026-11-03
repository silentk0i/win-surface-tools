#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include "process/process-associator.h"
#include "process/process-worker.h"
#include "native/alpc.h"
#include <rpc.h>

#pragma comment(lib, "ws2_32.lib")

namespace {
	using namespace win_obj;
	void Check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
	std::optional<HandleNameResult> SlowQuery(u32, u64, uintptr_t handle) {
		if (handle != static_cast<uintptr_t>(-1)) return std::nullopt;
		Sleep(10000);
		return HandleNameResult{};
	}
	bool Has(const WinObj& object, u32 pid, const wchar_t* relation) {
		return std::any_of(object.processes.begin(), object.processes.end(), [&](const auto& association) {
			return association.process.pid == pid && association.relation == relation && !association.process.name.empty() && association.process.created;
		});
	}
	std::wstring Binding(const wchar_t* protocol, const wchar_t* address, const std::wstring& endpoint) {
		RPC_WSTR text = nullptr;
		auto status = RpcStringBindingComposeW(nullptr, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(protocol)),
			reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(address)), reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(endpoint.c_str())), nullptr, &text);
		Check(status == RPC_S_OK, "Cannot compose fixture RPC binding");
		std::wstring result(reinterpret_cast<wchar_t*>(text));
		RpcStringFreeW(&text);
		return result;
	}
}

int wmain(int argc, wchar_t* argv[]) {
	using namespace win_obj;
	if (auto result = ProcessWorkerMain(argc, argv, SlowQuery)) return *result;
	if (argc == 5 && std::wstring_view(argv[1]) == L"--hold-event") {
		UniqueHandle event(OpenEventW(SYNCHRONIZE, FALSE, argv[2]), CloseHandle);
		UniqueHandle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[3]), CloseHandle);
		UniqueHandle stop(OpenEventW(SYNCHRONIZE, FALSE, argv[4]), CloseHandle);
		if (!event || !ready || !stop) return 2;
		SetEvent(ready.get());
		return WaitForSingleObject(stop.get(), 60000) == WAIT_OBJECT_0 ? 0 : 2;
	}
	try {
		auto pid = GetCurrentProcessId();
		DWORD session = 0;
		Check(ProcessIdToSessionId(pid, &session) != FALSE, "Session lookup failed");
		auto suffix = L"win-obj-process-" + std::to_wstring(pid) + L"-" + std::to_wstring(GetTickCount64());
		auto local = L"Local\\" + suffix;
		auto native = L"\\Sessions\\" + std::to_wstring(session) + L"\\BaseNamedObjects\\" + suffix;
		WSADATA sockets{};
		Check(WSAStartup(MAKEWORD(2, 2), &sockets) == 0, "Winsock setup failed");
		struct SocketCleanup { SOCKET v4 = INVALID_SOCKET, v6 = INVALID_SOCKET; ~SocketCleanup() { closesocket(v4); closesocket(v6); WSACleanup(); } } sockets_cleanup;
		sockets_cleanup.v4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		sockets_cleanup.v6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		sockaddr_in v4{}; v4.sin_family = AF_INET; v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sockaddr_in6 v6{}; v6.sin6_family = AF_INET6; v6.sin6_addr = in6addr_loopback;
		Check(bind(sockets_cleanup.v4, reinterpret_cast<sockaddr*>(&v4), sizeof(v4)) == 0 && listen(sockets_cleanup.v4, 1) == 0, "IPv4 listener failed");
		Check(bind(sockets_cleanup.v6, reinterpret_cast<sockaddr*>(&v6), sizeof(v6)) == 0 && listen(sockets_cleanup.v6, 1) == 0, "IPv6 listener failed");
		int v4_size = sizeof(v4), v6_size = sizeof(v6);
		Check(getsockname(sockets_cleanup.v4, reinterpret_cast<sockaddr*>(&v4), &v4_size) == 0 &&
			getsockname(sockets_cleanup.v6, reinterpret_cast<sockaddr*>(&v6), &v6_size) == 0, "Listener ports unavailable");
		auto port_name = L"\\RPC Control\\" + suffix;
		UNICODE_STRING port_string{ static_cast<USHORT>(port_name.size() * sizeof(wchar_t)), static_cast<USHORT>((port_name.size() + 1) * sizeof(wchar_t)), port_name.data() };
		OBJECT_ATTRIBUTES attributes{};
		InitializeObjectAttributes(&attributes, &port_string, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
		auto create_port = reinterpret_cast<AlpcCreate>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAlpcCreatePort"));
		HANDLE raw_port = nullptr;
		Check(create_port && create_port(&raw_port, &attributes, nullptr) >= 0, "ALPC port fixture failed");
		UniqueHandle port(raw_port, CloseHandle);
		UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, local.c_str()), CloseHandle);
		UniqueHandle second(OpenEventW(SYNCHRONIZE, FALSE, local.c_str()), CloseHandle);
		UniqueHandle ready(CreateEventW(nullptr, TRUE, FALSE, (local + L"-ready").c_str()), CloseHandle);
		UniqueHandle stop(CreateEventW(nullptr, TRUE, FALSE, (local + L"-stop").c_str()), CloseHandle);
		UniqueHandle mutant(CreateMutexW(nullptr, FALSE, (local + L"-mutant").c_str()), CloseHandle);
		UniqueHandle semaphore(CreateSemaphoreW(nullptr, 1, 2, (local + L"-semaphore").c_str()), CloseHandle);
		UniqueHandle timer(CreateWaitableTimerW(nullptr, TRUE, (local + L"-timer").c_str()), CloseHandle);
		UniqueHandle job(CreateJobObjectW(nullptr, (local + L"-job").c_str()), CloseHandle);
		auto pipe_name = L"\\\\.\\pipe\\" + suffix;
		UniqueHandle pipe(CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 1024, 1024, 0, nullptr), CloseHandle);
		UniqueHandle null_device(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr), CloseHandle);
		Check(event && second && ready && stop && mutant && semaphore && timer && job && pipe.get() != INVALID_HANDLE_VALUE && null_device.get() != INVALID_HANDLE_VALUE, "Fixture creation failed");
		wchar_t executable[32768]{};
		Check(GetModuleFileNameW(nullptr, executable, std::size(executable)) != 0, "Executable path failed");
		auto command = L"\"" + std::wstring(executable) + L"\" --hold-event \"" + local + L"\" \"" + local + L"-ready\" \"" + local + L"-stop\"";
		STARTUPINFOW startup{ sizeof(startup) };
		PROCESS_INFORMATION information{};
		Check(CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information) != FALSE, "Holder launch failed");
		UniqueHandle child(information.hProcess, CloseHandle), thread(information.hThread, CloseHandle);
		struct StopChild { HANDLE stop, process; ~StopChild() { SetEvent(stop); if (WaitForSingleObject(process, 1000) != WAIT_OBJECT_0) TerminateProcess(process, 2); } } cleanup{ stop.get(), child.get() };
		Check(WaitForSingleObject(ready.get(), 5000) == WAIT_OBJECT_0, "Child holder not ready");
		ProcessAssociator associations((1u << (TIMER + 1)) - 1, 30000);
		Check(!associations.GetInfo().error, "Process snapshot failed");
		std::vector<WinObj> objects{
			{ EVENT, native }, { MUTANT, native + L"-mutant" }, { SEMAPHORE, native + L"-semaphore" },
			{ TIMER, native + L"-timer" }, { JOB, native + L"-job" }, { NAMEDPIPE, pipe_name },
			{ DEVICE, L"\\Device\\Null" }, { DEVICE, L"\\Device\\Nul" }, { SESSIONS, L"Current session" },
			{ EVENT, native + L"-missing" }, { RPC, Binding(L"ncacn_np", L"", L"\\pipe\\" + suffix) },
			{ RPC, Binding(L"ncacn_np", L"remote.invalid", L"\\pipe\\" + suffix) },
			{ ALPC, port_name }, { RPC, Binding(L"ncalrpc", L"", suffix) },
			{ RPC, Binding(L"ncacn_ip_tcp", L"127.0.0.1", std::to_wstring(ntohs(v4.sin_port))) },
			{ RPC, Binding(L"ncacn_ip_tcp", L"::1", std::to_wstring(ntohs(v6.sin6_port))) },
			{ RPC, Binding(L"ncacn_ip_tcp", L"203.0.113.1", std::to_wstring(ntohs(v4.sin_port))) }
		};
		objects[8].session_id = session;
		associations.Apply(objects);
		for (size_t i = 0; i < 5; ++i) Check(Has(objects[i], pid, L"handle-holder"), "Named synchronization/job holder missing");
		Check(Has(objects[0], information.dwProcessId, L"handle-holder"), "Second process holder missing");
		Check(std::count_if(objects[0].processes.begin(), objects[0].processes.end(), [&](const auto& item) { return item.process.pid == pid; }) == 1, "Repeated handles duplicated the process association");
		Check(Has(objects[5], pid, L"handle-holder"), "Named pipe holder missing");
		Check(Has(objects[5], pid, L"pipe-server"), "Verified pipe server missing");
		Check(Has(objects[6], pid, L"device-path-handle"), "Device path holder missing");
		Check(!Has(objects[7], pid, L"device-path-handle"), "Device prefix collision");
		Check(Has(objects[8], pid, L"session-member"), "Session member missing");
		Check(objects[9].processes.empty(), "Unknown object given an owner");
		Check(Has(objects[10], pid, L"rpc-endpoint-holder"), "Local pipe RPC association missing");
		Check(objects[11].processes.empty() && objects[11].process_status == L"unsupported-transport", "Remote RPC binding attributed locally");
		Check(Has(objects[12], pid, L"handle-holder"), "ALPC port holder missing");
		Check(Has(objects[13], pid, L"rpc-endpoint-holder"), "Local ALPC RPC association missing");
		Check(Has(objects[14], pid, L"tcp-listener"), "IPv4 RPC listener missing");
		Check(Has(objects[15], pid, L"tcp-listener"), "IPv6 RPC listener missing");
		Check(objects[16].processes.empty(), "Remote TCP endpoint attributed by port alone");
		associations.Apply(objects);
		Check(objects[0].processes.size() == 2, "Applying associations twice duplicates them");
		AccessContext context;
		HandleNameWorker worker(context, 1u << EVENT);
		auto wrong_process = worker.Query(pid, 1, reinterpret_cast<uintptr_t>(event.get()), 1000);
		Check(wrong_process.error && wrong_process.process_unavailable, "PID reuse validation missing");
		auto start = GetTickCount64();
		auto timed_out = worker.Query(pid, 1, static_cast<uintptr_t>(-1), 50);
		Check(timed_out.error == ERROR_TIMEOUT && GetTickCount64() - start < 3000, "Blocked query was not bounded");
		auto identity = objects[0].processes;
		auto current = std::find_if(identity.begin(), identity.end(), [&](const auto& value) { return value.process.pid == pid; });
		auto recovered = worker.Query(pid, current->process.created, reinterpret_cast<uintptr_t>(event.get()), 1000);
		Check(!recovered.error && recovered.type == L"Event" && recovered.name == native, "Worker did not recover after timeout");
		ProcessAssociator session_only(1u << SESSIONS);
		Check(session_only.GetInfo().complete && !session_only.GetInfo().queried, "Session-only scan unnecessarily queried handles");
		std::wcout << L"Process association tests passed (" << associations.GetInfo().queried << L" queries, " << associations.GetInfo().failed << L" unavailable/failed).\n";
		return 0;
	}
	catch (const std::exception& error) { std::cerr << error.what() << std::endl; return 1; }
}
