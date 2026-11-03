#include <algorithm>
#include <limits>
#include <map>
#include "process/process-worker.h"
#include <winternl.h>

namespace {
	constexpr u32 worker_magic = 0x574F5032;
	struct SharedQuery {
		u32 magic = worker_magic;
		bool stop = false;
        wchar_t fingerprint[65]{};
		u32 types = 0;
		u32 pid = 0;
		u64 created = 0;
		uintptr_t handle = 0;
		u32 error = 0;
		bool process_unavailable = false;
		u32 server_pid = 0;
		u64 server_created = 0;
		wchar_t type[128]{};
		wchar_t name[32768]{};
	};

	HANDLE ParseHandle(const wchar_t* text) {
		wchar_t* end = nullptr;
		auto value = _wcstoui64(text, &end, 10);
		if (!value || !end || *end || value > (std::numeric_limits<uintptr_t>::max)()) return nullptr;
		return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(value));
	}

	u64 CreationTime(HANDLE process) {
		FILETIME created{}, exit{}, kernel{}, user{};
		if (!GetProcessTimes(process, &created, &exit, &kernel, &user)) return 0;
		return (static_cast<u64>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
	}

	using QueryObjectFunction = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
	u32 QueryString(HANDLE handle, ULONG information, wchar_t* output, size_t capacity) {
		static auto query = reinterpret_cast<QueryObjectFunction>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
		if (!query) return ERROR_PROC_NOT_FOUND;
		std::vector<unsigned char> buffer(1024);
		for (int attempt = 0; attempt < 4; ++attempt) {
			ULONG needed = 0;
			auto status = query(handle, information, buffer.data(), static_cast<ULONG>(buffer.size()), &needed);
			if (status >= 0) {
				auto& value = *reinterpret_cast<UNICODE_STRING*>(buffer.data());
				auto begin = reinterpret_cast<uintptr_t>(buffer.data());
				auto text = reinterpret_cast<uintptr_t>(value.Buffer);
				if (!value.Length) { output[0] = 0; return 0; }
				if (value.Length % sizeof(wchar_t) || text < begin || text > begin + buffer.size() ||
					value.Length > begin + buffer.size() - text || value.Length / sizeof(wchar_t) >= capacity)
					return ERROR_INVALID_DATA;
				if (std::find(value.Buffer, value.Buffer + value.Length / sizeof(wchar_t), L'\0') != value.Buffer + value.Length / sizeof(wchar_t))
					return ERROR_INVALID_NAME;
				std::copy_n(value.Buffer, value.Length / sizeof(wchar_t), output);
				output[value.Length / sizeof(wchar_t)] = 0;
				return 0;
			}
			if (needed <= buffer.size() || needed > 1024 * 1024) return static_cast<u32>(status);
			buffer.resize(needed);
		}
		return ERROR_INSUFFICIENT_BUFFER;
	}
}

namespace win_obj {
	bool RelevantHandleType(const std::wstring& type, u32 types) {
		auto selected = [&](WinObjType value) { return (types & (1u << value)) != 0; };
		return (type == L"Event" && selected(EVENT)) || (type == L"Job" && selected(JOB)) ||
			(type == L"Mutant" && selected(MUTANT)) || (type == L"Semaphore" && selected(SEMAPHORE)) ||
			(type == L"Timer" && selected(TIMER)) || ((type == L"ALPC Port" || type == L"Port") && (selected(ALPC) || selected(RPC))) ||
			((type == L"FilterConnectionPort" || type == L"FilterCommunicationPort") && selected(FLT)) ||
			(type == L"File" && (selected(DEVICE) || selected(NAMEDPIPE) || selected(RPC))) || (type == L"Device" && selected(DEVICE));
	}

	struct HandleNameWorker::State {
		const AccessContext& context;
		u32 types;
		UniqueHandle mapping{ nullptr, CloseHandle }, request{ nullptr, CloseHandle }, response{ nullptr, CloseHandle };
		UniqueHandle process{ nullptr, CloseHandle }, job{ nullptr, CloseHandle };
		SharedQuery* shared = nullptr;
		State(const AccessContext& identity, u32 selected) : context(identity), types(selected) {}
		~State() { Stop(); }

		void Stop() {
			if (process) {
				if (shared && request) { shared->stop = true; SetEvent(request.get()); }
				if (WaitForSingleObject(process.get(), 50) != WAIT_OBJECT_0) TerminateProcess(process.get(), ERROR_TIMEOUT);
			}
			job.reset();
			process.reset();
			if (shared) { UnmapViewOfFile(shared); shared = nullptr; }
			response.reset(); request.reset(); mapping.reset();
		}

		u32 Start() {
			if (context.GetInfo().error) return context.GetInfo().error;
			if (auto error = VerifyPrimaryContext(context.GetInfo().fingerprint, true)) return error;
			SECURITY_ATTRIBUTES security{ sizeof(security), nullptr, TRUE };
			mapping.reset(CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0, sizeof(SharedQuery), nullptr));
			if (!mapping) return GetLastError();
			request.reset(CreateEventW(&security, FALSE, FALSE, nullptr));
			if (!request) return GetLastError();
			response.reset(CreateEventW(&security, FALSE, FALSE, nullptr));
			if (!response) return GetLastError();
			shared = static_cast<SharedQuery*>(MapViewOfFile(mapping.get(), FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedQuery)));
			if (!shared) return GetLastError();
			new (shared) SharedQuery{};
			shared->types = types;
            wcscpy_s(shared->fingerprint, context.GetInfo().fingerprint.c_str());
			std::wstring executable(32768, L'\0');
			auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
			if (!length || length == executable.size()) return ERROR_FILENAME_EXCED_RANGE;
			executable.resize(length);
			auto command = L"\"" + executable + L"\" --process-worker";
			HANDLE inherited[] = { mapping.get(), request.get(), response.get() };
			for (auto handle : inherited) command += L" " + std::to_wstring(reinterpret_cast<uintptr_t>(handle));
			SIZE_T bytes = 0;
			InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
			std::vector<unsigned char> storage(bytes);
			auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
			if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) return GetLastError();
			struct Cleanup { LPPROC_THREAD_ATTRIBUTE_LIST value; ~Cleanup() { DeleteProcThreadAttributeList(value); } } cleanup{ attributes };
			if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr)) return GetLastError();
			job.reset(CreateJobObjectW(nullptr, nullptr));
			if (!job) return GetLastError();
			JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
			limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
			if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits))) return GetLastError();
			STARTUPINFOEXW startup{};
			startup.StartupInfo.cb = sizeof(startup);
			startup.lpAttributeList = attributes;
			PROCESS_INFORMATION information{};
			if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
				CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &information)) return GetLastError();
			process.reset(information.hProcess);
			UniqueHandle thread(information.hThread, CloseHandle);
			if (!AssignProcessToJobObject(job.get(), process.get())) return GetLastError();
			if (ResumeThread(thread.get()) == static_cast<DWORD>(-1)) return GetLastError();
			// Startup gets its own deadline; a slow loader must not consume every handle timeout.
			HANDLE waits[] = { response.get(), process.get() };
			return WaitForMultipleObjects(2, waits, FALSE, 2000) == WAIT_OBJECT_0 ? 0 : ERROR_PROCESS_ABORTED;
		}
	};

	HandleNameWorker::HandleNameWorker(const AccessContext& context, u32 types) : state_(std::make_unique<State>(context, types)) {}
	HandleNameWorker::~HandleNameWorker() = default;

	HandleNameResult HandleNameWorker::Query(u32 pid, u64 created, uintptr_t handle, u32 timeout_ms) {
		auto& state = *state_;
		if (!state.process) {
			auto error = state.Start();
			if (error) { state.Stop(); return { L"", L"", error, false, 0, 0, true }; }
		}
		auto& shared = *state.shared;
		shared.pid = pid; shared.created = created; shared.handle = handle;
		shared.error = 0; shared.process_unavailable = false; shared.server_pid = 0; shared.server_created = 0;
		shared.name[0] = 0; shared.type[0] = 0;
		if (!SetEvent(state.request.get())) { auto error = GetLastError(); state.Stop(); return { L"", L"", error, false, 0, 0, true }; }
		HANDLE waits[] = { state.response.get(), state.process.get() };
		auto wait = WaitForMultipleObjects(2, waits, FALSE, timeout_ms);
		if (wait == WAIT_OBJECT_0)
			return { shared.type, shared.name, shared.error, shared.process_unavailable, shared.server_pid, shared.server_created };
		auto error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : wait == WAIT_FAILED ? GetLastError() : ERROR_PROCESS_ABORTED;
		state.Stop();
		return { L"", L"", error, false, 0, 0, error != ERROR_TIMEOUT };
	}

	std::optional<int> ProcessWorkerMain(int argc, wchar_t* argv[], HandleQueryOverride function) {
		if (argc < 2 || std::wstring_view(argv[1]) != L"--process-worker") return std::nullopt;
		if (argc != 5) return 2;
		auto mapping = ParseHandle(argv[2]), request = ParseHandle(argv[3]), response = ParseHandle(argv[4]);
		if (!mapping || !request || !response) return 2;
		auto shared = static_cast<SharedQuery*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedQuery)));
		if (!shared) return 2;
		struct Cleanup { void* value; ~Cleanup() { UnmapViewOfFile(value); } } cleanup{ shared };
		if (shared->magic != worker_magic || shared->fingerprint[64] || wcslen(shared->fingerprint) != 64 || VerifyPrimaryContext(shared->fingerprint, true)) return 2;
		std::map<u32, UniqueHandle> sources;
		if (!SetEvent(response)) return 2;
		while (WaitForSingleObject(request, INFINITE) == WAIT_OBJECT_0) {
			if (shared->stop) break;
			if (function) {
				auto result = function(shared->pid, shared->created, shared->handle);
				if (result) {
					shared->error = result->error;
					shared->process_unavailable = result->process_unavailable;
					shared->server_pid = result->server_pid; shared->server_created = result->server_created;
					if (result->type.size() >= std::size(shared->type) || result->name.size() >= std::size(shared->name)) return 2;
					wcscpy_s(shared->type, result->type.c_str()); wcscpy_s(shared->name, result->name.c_str());
					if (!SetEvent(response)) return 2;
					continue;
				}
			}
			auto source = sources.find(shared->pid);
			if (source == sources.end()) {
				UniqueHandle process(OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, shared->pid), CloseHandle);
				if (!process || !shared->created || CreationTime(process.get()) != shared->created) {
					shared->error = process ? ERROR_INVALID_DATA : GetLastError();
					shared->process_unavailable = true;
				}
				else source = sources.emplace(shared->pid, std::move(process)).first;
			}
			if (!shared->error) {
				HANDLE raw = nullptr;
				if (!DuplicateHandle(source->second.get(), reinterpret_cast<HANDLE>(shared->handle), GetCurrentProcess(), &raw, 0, FALSE, DUPLICATE_SAME_ACCESS))
					shared->error = GetLastError();
				else {
					UniqueHandle duplicate(raw, CloseHandle);
					shared->error = QueryString(raw, 2, shared->type, std::size(shared->type));
					if (!shared->error && RelevantHandleType(shared->type, shared->types)) {
						shared->error = QueryString(raw, 1, shared->name, std::size(shared->name));
						if (!shared->error && std::wstring_view(shared->name).starts_with(L"\\Device\\NamedPipe\\")) {
							ULONG pid = 0;
							if (GetNamedPipeServerProcessId(raw, &pid)) {
								UniqueHandle server(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid), CloseHandle);
								if (server) { shared->server_pid = pid; shared->server_created = CreationTime(server.get()); }
							}
						}
					}
				}
			}
			if (!SetEvent(response)) return 2;
		}
		return 0;
	}
}
