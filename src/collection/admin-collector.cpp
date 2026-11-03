#include <algorithm>
#include <map>
#include <thread>
#include "collection/admin-collector.h"
#include "core/enumerator-manager.h"
#include "enumerators/enumerators.h"
#include "process/process-associator.h"
#include "access/access-worker.h"
#include <shellapi.h>
#include <sddl.h>
#include <bcrypt.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace {
	using namespace win_obj;
	constexpr wchar_t pipe_prefix[] = L"\\\\.\\pipe\\win-obj-enum-collect-";
	constexpr u32 request_magic = 0x574f5231;
	constexpr u32 max_response = 128 * 1024 * 1024;
	struct Request { u32 magic = request_magic, types = 0, budget = 30000, processes = 1, debug = 0; };
	static_assert(sizeof(Request) == 20);

	u64 Now() { FILETIME value{}; GetSystemTimeAsFileTime(&value); return (static_cast<u64>(value.dwHighDateTime) << 32) | value.dwLowDateTime; }
	u64 Created(HANDLE process) {
		FILETIME value{}, exit{}, kernel{}, user{};
		return GetProcessTimes(process, &value, &exit, &kernel, &user) ? (static_cast<u64>(value.dwHighDateTime) << 32) | value.dwLowDateTime : 0;
	}
	std::wstring ImagePath(HANDLE process) {
		std::wstring path(32768, L'\0'); DWORD length = static_cast<DWORD>(path.size());
		if (!QueryFullProcessImageNameW(process, 0, path.data(), &length)) return {};
		path.resize(length); return path;
	}
	std::wstring Executable() {
		std::wstring path(32768, L'\0'); auto length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
		if (!length || length == path.size()) return {};
		path.resize(length); return path;
	}
	u64 ParseNumber(const wchar_t* text) {
		if (!text || !*text || std::wstring_view(text).find_first_not_of(L"0123456789") != std::wstring_view::npos) return 0;
		wchar_t* end = nullptr; auto value = _wcstoui64(text, &end, 10); return end && !*end ? value : 0;
	}
	u32 Remaining(u64 deadline) { auto now = GetTickCount64(); return now < deadline ? static_cast<u32>((std::min)(deadline - now, static_cast<u64>(MAXDWORD - 1))) : 0; }

	// Every pending operation is cancelled and drained before its OVERLAPPED dies.
	u32 FinishIo(HANDLE pipe, OVERLAPPED& operation, HANDLE peer, u64 deadline, DWORD& transferred) {
		HANDLE waits[] = { operation.hEvent, peer };
		auto wait = WaitForMultipleObjects(peer ? 2 : 1, waits, FALSE, Remaining(deadline));
		if (wait == WAIT_OBJECT_0) return GetOverlappedResult(pipe, &operation, &transferred, FALSE) ? 0 : GetLastError();
		auto error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : wait == WAIT_FAILED ? GetLastError() : ERROR_PROCESS_ABORTED;
		CancelIoEx(pipe, &operation); GetOverlappedResult(pipe, &operation, &transferred, TRUE); return error;
	}
	u32 Transfer(HANDLE pipe, bool write, void* buffer, size_t length, HANDLE peer, u64 deadline) {
		UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr), CloseHandle);
		if (!event) return GetLastError();
		size_t offset = 0;
		while (offset < length) {
			if (!Remaining(deadline)) return ERROR_TIMEOUT;
			ResetEvent(event.get()); OVERLAPPED operation{}; operation.hEvent = event.get(); DWORD transferred = 0;
			auto amount = static_cast<DWORD>((std::min)(length - offset, static_cast<size_t>(65536)));
			auto pointer = static_cast<unsigned char*>(buffer) + offset;
			auto done = write ? WriteFile(pipe, pointer, amount, &transferred, &operation) : ReadFile(pipe, pointer, amount, &transferred, &operation);
			if (!done) { auto error = GetLastError(); if (error != ERROR_IO_PENDING) return error; error = FinishIo(pipe, operation, peer, deadline, transferred); if (error) return error; }
			if (!transferred || transferred > amount) return ERROR_BROKEN_PIPE;
			offset += transferred;
		}
		return 0;
	}
	u32 Connect(HANDLE pipe, HANDLE peer, u64 deadline) {
		UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr), CloseHandle);
		if (!event) return GetLastError();
		OVERLAPPED operation{}; operation.hEvent = event.get();
		if (ConnectNamedPipe(pipe, &operation)) return 0;
		auto error = GetLastError(); if (error == ERROR_PIPE_CONNECTED) return 0;
		if (error != ERROR_IO_PENDING) return error;
		DWORD transferred = 0; return FinishIo(pipe, operation, peer, deadline, transferred);
	}

	CollectorData Collect(const Request& request, u32 parent_pid) {
		CollectorData result; result.requested = result.received = true; result.started = Now(); result.debug_requested = request.debug != 0;
		if (request.debug) {
			HANDLE raw = nullptr;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &raw)) result.debug_error = GetLastError();
			else {
				UniqueHandle token(raw, CloseHandle); TOKEN_PRIVILEGES privileges{}; privileges.PrivilegeCount = 1;
				if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &privileges.Privileges[0].Luid)) result.debug_error = GetLastError();
				else {
					privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
					SetLastError(ERROR_SUCCESS);
					if (!AdjustTokenPrivileges(raw, FALSE, &privileges, 0, nullptr, nullptr)) result.debug_error = GetLastError();
					else result.debug_error = GetLastError();
					result.debug_enabled = result.debug_error == ERROR_SUCCESS;
				}
			}
		}
		AccessContext context; result.token = context.GetInfo();
		if (result.token.error || !result.token.elevated) { result.error = result.token.error ? result.token.error : ERROR_ELEVATION_REQUIRED; result.error_operation = L"Elevated primary collector context"; result.finished = Now(); return result; }
		std::unique_ptr<ProcessAssociator> associations;
		if (request.processes) {
			associations = std::make_unique<ProcessAssociator>(request.types, request.budget, std::vector<u32>{ parent_pid, GetCurrentProcessId() });
			result.processes = associations->GetInfo();
		}
		EnumerationManager manager;
		manager.Register(std::make_unique<DeviceEnumerator>()); manager.Register(std::make_unique<AlpcEnumerator>()); manager.Register(std::make_unique<RpcEnumerator>());
		manager.Register(std::make_unique<FltEnumerator>()); manager.Register(std::make_unique<EventEnumerator>()); manager.Register(std::make_unique<JobEnumerator>());
		manager.Register(std::make_unique<MutantEnumerator>()); manager.Register(std::make_unique<NamedPipeEnumerator>()); manager.Register(std::make_unique<SemaphoreEnumerator>());
		manager.Register(std::make_unique<SessionsEnumerator>()); manager.Register(std::make_unique<TimerEnumerator>());
		std::map<std::pair<u32, u64>, std::wstring> paths;
		for (u32 type = DEVICE; type <= TIMER; ++type) {
			if (!(request.types & (1u << type))) continue;
			CollectedGroup group; group.type = static_cast<WinObjType>(type);
			auto objects = manager.Enumerate(group.type); group.discovered = objects.has_value(); group.issues = manager.GetIssues(group.type);
			if (objects) {
				if (associations) associations->Apply(*objects);
				for (auto& object : *objects) {
					object.discovery_sources = 2;
					for (auto& a : object.processes) {
						a.sources = 2;
						auto [path, inserted] = paths.emplace(std::pair{ a.process.pid, a.process.created }, L"");
						if (inserted) {
							UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, a.process.pid), CloseHandle);
							if (process && Created(process.get()) == a.process.created) path->second = ImagePath(process.get());
						}
						a.process.image_path = path->second;
					}
				}
				group.objects = std::move(*objects);
			}
			result.groups.push_back(std::move(group));
		}
		if (auto error = VerifyUnchangedPrimaryContext(result.token, true)) {
			result.error = error; result.error_operation = L"Collector primary context changed"; result.groups.clear();
		}
		result.finished = Now(); return result;
	}
}

namespace win_obj {
	CollectorData CollectAsAdministrator(const CollectorOptions& options) {
		CollectorData result; result.requested = true; result.debug_requested = options.debug_privilege;
		UniqueHandle pipe(nullptr, CloseHandle), helper(nullptr, CloseHandle);
		auto fail = [&](u32 error, const wchar_t* operation) {
			result.error = error; result.error_operation = operation;
			pipe.reset(); // The helper watchdog treats disconnection as cancellation.
			if (helper && WaitForSingleObject(helper.get(), 5000) != WAIT_OBJECT_0) result.cleanup_confirmed = false;
			return result;
		};
		AccessContext baseline;
		if (baseline.GetInfo().error || baseline.GetInfo().elevated) return fail(baseline.GetInfo().error ? baseline.GetInfo().error : ERROR_BAD_TOKEN_TYPE, L"User primary context required");
		if (!options.types || options.types >> (TIMER + 1) || !options.process_budget_ms || options.process_budget_ms > 300000) return fail(ERROR_INVALID_PARAMETER, L"Collector options");
		unsigned char random[32]{};
		if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return fail(ERROR_GEN_FAILURE, L"Collector pipe nonce");
		std::wstring pipe_name = pipe_prefix; constexpr wchar_t hex[] = L"0123456789abcdef";
		for (auto byte : random) { pipe_name += hex[byte >> 4]; pipe_name += hex[byte & 15]; }
		auto acl = L"D:P(A;;GA;;;" + baseline.GetInfo().user_sid + L")(A;;GA;;;BA)(A;;GA;;;SY)";
		PSECURITY_DESCRIPTOR descriptor = nullptr;
		if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) return fail(GetLastError(), L"Collector IPC descriptor");
		struct DescriptorCleanup { void* value; ~DescriptorCleanup() { LocalFree(value); } } descriptor_cleanup{ descriptor };
		SECURITY_ATTRIBUTES security{ sizeof(security), descriptor, FALSE };
		pipe.reset(CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, &security));
		if (pipe.get() == INVALID_HANDLE_VALUE) { pipe.release(); return fail(GetLastError(), L"Create collector pipe"); }
		auto executable = Executable(); if (executable.empty()) return fail(ERROR_FILE_NOT_FOUND, L"Collector executable");
		auto parameters = L"--admin-collector \"" + pipe_name + L"\" " + std::to_wstring(GetCurrentProcessId()) + L" " + std::to_wstring(Created(GetCurrentProcess()));
		auto com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
		struct ComCleanup { HRESULT status; ~ComCleanup() { if (SUCCEEDED(status)) CoUninitialize(); } } com_cleanup{ com };
		SHELLEXECUTEINFOW launch{ sizeof(launch) }; launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
		launch.lpVerb = L"runas"; launch.lpFile = executable.c_str(); launch.lpParameters = parameters.c_str(); launch.nShow = SW_HIDE;
		if (!ShellExecuteExW(&launch)) return fail(GetLastError(), L"Administrator elevation");
		helper.reset(launch.hProcess);
		if (!helper) return fail(ERROR_INVALID_HANDLE, L"Elevated helper process");
		auto deadline = GetTickCount64() + options.process_budget_ms + 120000;
		for (;;) {
			if (auto error = Connect(pipe.get(), helper.get(), deadline)) return fail(error, L"Connect elevated collector");
			ULONG client = 0;
			if (GetNamedPipeClientProcessId(pipe.get(), &client) && client == GetProcessId(helper.get()) && WaitForSingleObject(helper.get(), 0) == WAIT_TIMEOUT) break;
			DisconnectNamedPipe(pipe.get()); if (!Remaining(deadline)) return fail(ERROR_ACCESS_DENIED, L"Collector peer identity");
		}
		Request request{ request_magic, options.types, options.process_budget_ms, options.processes ? 1u : 0u, options.debug_privilege ? 1u : 0u };
		if (auto error = Transfer(pipe.get(), true, &request, sizeof(request), helper.get(), deadline)) return fail(error, L"Collector request");
		u32 size = 0;
		if (auto error = Transfer(pipe.get(), false, &size, sizeof(size), helper.get(), deadline)) return fail(error, L"Collector response header");
		if (!size || size > max_response) return fail(ERROR_INVALID_DATA, L"Collector response size");
		std::vector<unsigned char> response(size);
		if (auto error = Transfer(pipe.get(), false, response.data(), response.size(), helper.get(), deadline)) return fail(error, L"Collector response");
		CollectorData decoded;
		if (!DecodeCollectorData(response, decoded) || !decoded.token.elevated || decoded.token.impersonating || decoded.token.error) return fail(ERROR_INVALID_DATA, L"Collector response validation");
		u32 returned_types = 0; for (const auto& group : decoded.groups) returned_types |= 1u << group.type;
		if ((!decoded.error && returned_types != options.types) || decoded.debug_requested != options.debug_privilege) return fail(ERROR_INVALID_DATA, L"Collector response scope");
		u8 acknowledged = 1;
		if (auto error = Transfer(pipe.get(), true, &acknowledged, 1, helper.get(), deadline)) return fail(error, L"Collector acknowledgement");
		if (WaitForSingleObject(helper.get(), 5000) != WAIT_OBJECT_0) return fail(ERROR_TIMEOUT, L"Collector cleanup");
		DWORD exit = 0;
		if (!GetExitCodeProcess(helper.get(), &exit) || exit) return fail(ERROR_PROCESS_ABORTED, L"Collector exit");
		if (auto error = VerifyUnchangedPrimaryContext(baseline.GetInfo())) return fail(error, L"User context changed during collection");
		return decoded;
	}

	std::optional<int> AdminCollectorMain(int argc, wchar_t* argv[]) {
		if (argc < 2 || std::wstring_view(argv[1]) != L"--admin-collector") return std::nullopt;
		if (argc != 5) return 2;
		std::wstring pipe_name = argv[2]; auto parent_pid = ParseNumber(argv[3]), parent_created = ParseNumber(argv[4]);
		if (!pipe_name.starts_with(pipe_prefix) || pipe_name.size() != std::size(pipe_prefix) - 1 + 64 ||
			pipe_name.substr(std::size(pipe_prefix) - 1).find_first_not_of(L"0123456789abcdef") != std::wstring::npos || !parent_pid || parent_pid > MAXDWORD || !parent_created) return 2;
		AccessContext context; if (context.GetInfo().error || !context.GetInfo().elevated) return 2;
		UniqueHandle parent(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, static_cast<DWORD>(parent_pid)), CloseHandle);
		auto executable = Executable();
		if (!parent || Created(parent.get()) != parent_created || executable.empty() || _wcsicmp(ImagePath(parent.get()).c_str(), executable.c_str())) return 2;
		UniqueHandle pipe(nullptr, CloseHandle);
		auto connect_deadline = GetTickCount64() + 15000;
		while (Remaining(connect_deadline)) {
			pipe.reset(CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
				FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, nullptr));
			if (pipe.get() != INVALID_HANDLE_VALUE) break;
			auto error = GetLastError(); pipe.release(); if (error != ERROR_PIPE_BUSY) return 2;
			WaitNamedPipeW(pipe_name.c_str(), 500);
		}
		ULONG server = 0; if (!pipe || !GetNamedPipeServerProcessId(pipe.get(), &server) || server != parent_pid) return 2;
		Request request{};
		if (Transfer(pipe.get(), false, &request, sizeof(request), parent.get(), GetTickCount64() + 15000) || request.magic != request_magic ||
			!request.types || request.types >> (TIMER + 1) || !request.budget || request.budget > 300000 || request.processes > 1 || request.debug > 1) return 2;
		UniqueHandle stopped(CreateEventW(nullptr, TRUE, FALSE, nullptr), CloseHandle); if (!stopped) return 2;
		std::jthread watchdog([&] {
			HANDLE waits[] = { stopped.get(), parent.get() };
			auto deadline = GetTickCount64() + request.budget + 120000;
			for (;;) {
				auto wait = WaitForMultipleObjects(2, waits, FALSE, 250);
				if (wait == WAIT_OBJECT_0) return;
				if (wait != WAIT_TIMEOUT || !Remaining(deadline) || !PeekNamedPipe(pipe.get(), nullptr, 0, nullptr, nullptr, nullptr)) {
					TerminateProcess(GetCurrentProcess(), ERROR_TIMEOUT); return;
				}
			}
		});
		struct WatchdogCleanup { HANDLE event; ~WatchdogCleanup() { SetEvent(event); } } watchdog_cleanup{ stopped.get() };
		try {
			auto data = Collect(request, static_cast<u32>(parent_pid)); // All temporary target handles close before returning.
			auto response = EncodeCollectorData(data); auto size = static_cast<u32>(response.size()); auto deadline = GetTickCount64() + 30000;
			if (Transfer(pipe.get(), true, &size, sizeof(size), parent.get(), deadline) || Transfer(pipe.get(), true, response.data(), response.size(), parent.get(), deadline)) return 2;
			u8 acknowledged = 0;
			return !Transfer(pipe.get(), false, &acknowledged, 1, parent.get(), deadline) && acknowledged == 1 ? 0 : 2;
		}
		catch (const std::exception&) { return 2; }
	}
}
