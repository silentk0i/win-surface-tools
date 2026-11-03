#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <algorithm>
#include <cwctype>
#include <limits>
#include <set>
#include "process/process-associator.h"
#include "process/process-worker.h"
#include <winternl.h>
#include <rpc.h>

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {
	using namespace win_obj;
	// Native, pointer-sized layouts. Do not use the legacy 16-bit PID/handle snapshot.
	struct NativeProcess {
		ULONG next, threads;
		LARGE_INTEGER working_set;
		ULONG faults, high_watermark;
		ULONGLONG cycles;
		LARGE_INTEGER created, user, kernel;
		UNICODE_STRING name;
		LONG priority;
		HANDLE pid, parent;
		ULONG handles, session;
	};
	struct NativeHandle {
		PVOID object;
		ULONG_PTR pid, handle;
		ULONG access;
		USHORT backtrace, type;
		ULONG attributes, reserved;
	};
	struct NativeHandles { ULONG_PTR count, reserved; NativeHandle entries[1]; };
	struct NativeType {
		UNICODE_STRING name;
		ULONG counts[12];
		ULONG invalid_attributes;
		GENERIC_MAPPING mapping;
		ULONG valid_access;
		BOOLEAN security, maintain_count;
		UCHAR index, reserved;
		ULONG pool, paged_charge, nonpaged_charge;
	};
	static_assert(sizeof(NativeType) == (sizeof(void*) == 8 ? 104 : 96));
	static_assert(offsetof(NativeProcess, created) == 32);
	static_assert(offsetof(NativeProcess, session) == (sizeof(void*) == 8 ? 100 : 80));
	static_assert(sizeof(NativeHandle) == (sizeof(void*) == 8 ? 40 : 28));

	std::map<USHORT, std::wstring> TypeNames() {
		using QueryObject = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
		auto query = reinterpret_cast<QueryObject>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
		if (!query) return {};
		std::vector<unsigned char> buffer(65536);
		for (int attempt = 0; attempt < 4; ++attempt) {
			ULONG needed = 0;
			auto status = query(nullptr, 3, buffer.data(), static_cast<ULONG>(buffer.size()), &needed);
			if (status >= 0) {
				std::map<USHORT, std::wstring> names;
				auto count = *reinterpret_cast<ULONG*>(buffer.data());
				size_t offset = sizeof(void*);
				for (ULONG i = 0; i < count; ++i) {
					if (offset > buffer.size() || sizeof(NativeType) > buffer.size() - offset) return {};
					auto& type = *reinterpret_cast<NativeType*>(buffer.data() + offset);
					auto begin = reinterpret_cast<uintptr_t>(buffer.data()), name = reinterpret_cast<uintptr_t>(type.name.Buffer);
					if (type.name.Length % sizeof(wchar_t) || type.name.Length > type.name.MaximumLength || name < begin || name > begin + buffer.size() ||
						type.name.Length > begin + buffer.size() - name || type.name.MaximumLength > buffer.size() - offset - sizeof(NativeType)) return {};
					if (type.index) names.emplace(type.index, std::wstring(type.name.Buffer, type.name.Length / sizeof(wchar_t)));
					offset = (offset + sizeof(NativeType) + type.name.MaximumLength + sizeof(void*) - 1) & ~(sizeof(void*) - 1);
				}
				return names;
			}
			if (needed <= buffer.size() || needed > 1024 * 1024) return {};
			buffer.resize(needed);
		}
		return {};
	}

	using QuerySystemFunction = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
	u32 Snapshot(ULONG information, std::vector<unsigned char>& buffer) {
		auto query = reinterpret_cast<QuerySystemFunction>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
		if (!query) return 0xC0000002; // STATUS_NOT_IMPLEMENTED
		buffer.resize(1024 * 1024);
		for (int attempt = 0; attempt < 12; ++attempt) {
			ULONG needed = 0;
			auto status = query(information, buffer.data(), static_cast<ULONG>(buffer.size()), &needed);
			if (status >= 0) {
				if (needed && needed <= buffer.size()) buffer.resize(needed);
				return 0;
			}
			if (static_cast<u32>(status) != 0xC0000004 && static_cast<u32>(status) != 0xC0000023) return static_cast<u32>(status);
			auto size = (std::max)(static_cast<size_t>(needed) + 65536, buffer.size() * 2);
			if (size > 256 * 1024 * 1024) return 0xC000009A; // STATUS_INSUFFICIENT_RESOURCES
			buffer.resize(size);
		}
		return 0xC0000004;
	}

	std::wstring Lower(std::wstring value) {
		std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
		return value;
	}

	std::wstring Key(const std::wstring& type, const std::wstring& name) { return type + L"\n" + Lower(name); }

	void Add(std::vector<ProcessAssociation>& values, const ProcessIdentity& process, const std::wstring& relation) {
		if (std::none_of(values.begin(), values.end(), [&](const auto& value) {
			return value.process.pid == process.pid && value.process.created == process.created && value.relation == relation;
		})) values.push_back({ process, relation });
	}

	bool LocalAddress(const std::wstring& address) {
		if (address.empty() || address == L"." || address == L"localhost" || address == L"127.0.0.1" || address == L"::1") return true;
		wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
		DWORD length = std::size(computer);
		return GetComputerNameW(computer, &length) && address == Lower(computer);
	}

	std::wstring IpText(int family, const void* address, u32 scope = 0) {
		wchar_t text[INET6_ADDRSTRLEN]{};
		if (!InetNtopW(family, address, text, std::size(text))) return {};
		auto value = Lower(text);
		if (family == AF_INET6 && scope) value += L"%" + std::to_wstring(scope);
		return value;
	}

	std::wstring TcpKey(const std::wstring& address, u32 port) { return L"TCP\n" + address + L":" + std::to_wstring(port); }

	void CaptureTcp(std::map<std::wstring, std::vector<ProcessAssociation>>& named, const std::map<u32, ProcessIdentity>& processes, ProcessScanInfo& info) {
		std::map<int, std::set<std::wstring>> local;
		local[AF_INET].insert(L"127.0.0.1"); local[AF_INET6].insert(L"::1");
		std::vector<unsigned char> adapters(15000);
		ULONG error = 0;
		for (int attempt = 0; attempt < 4; ++attempt) {
			ULONG size = static_cast<ULONG>(adapters.size());
			error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr,
				reinterpret_cast<IP_ADAPTER_ADDRESSES*>(adapters.data()), &size);
			if (error != ERROR_BUFFER_OVERFLOW || size > 16 * 1024 * 1024) break;
			adapters.resize(size);
		}
		if (error && error != ERROR_NO_DATA) info.tcp_error = error;
		if (!error) for (auto adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(adapters.data()); adapter; adapter = adapter->Next) {
			for (auto unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
				auto address = unicast->Address.lpSockaddr;
				if (!address) continue;
				if (address->sa_family == AF_INET) local[AF_INET].insert(IpText(AF_INET, &reinterpret_cast<sockaddr_in*>(address)->sin_addr));
				else if (address->sa_family == AF_INET6) {
					auto v6 = reinterpret_cast<sockaddr_in6*>(address);
					local[AF_INET6].insert(IpText(AF_INET6, &v6->sin6_addr, v6->sin6_scope_id));
				}
			}
		}
		std::map<u32, bool> identities;
		auto add = [&](int family, const std::wstring& address, DWORD port, DWORD pid) {
			auto identity = processes.find(pid);
			if (identity == processes.end()) return;
			auto verified = identities.find(pid);
			if (verified == identities.end()) {
				UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid), CloseHandle);
				FILETIME created{}, exit{}, kernel{}, user{};
				bool same = process && GetProcessTimes(process.get(), &created, &exit, &kernel, &user) &&
					((static_cast<u64>(created.dwHighDateTime) << 32) | created.dwLowDateTime) == identity->second.created;
				verified = identities.emplace(pid, same).first;
				if (!same) info.tcp_error = ERROR_PARTIAL_COPY;
			}
			if (!verified->second) return;
			auto host_port = ((port & 0xff) << 8) | ((port >> 8) & 0xff);
			Add(named[TcpKey(L"local", host_port)], identity->second, L"tcp-listener");
			if (address == L"0.0.0.0" || address == L"::") {
				for (const auto& ip : local[family]) Add(named[TcpKey(ip, host_port)], identity->second, L"tcp-listener");
			}
			else Add(named[TcpKey(address, host_port)], identity->second, L"tcp-listener");
		};
		for (auto family : { AF_INET, AF_INET6 }) {
			std::vector<unsigned char> table(16384);
			for (int attempt = 0; attempt < 4; ++attempt) {
				DWORD size = static_cast<DWORD>(table.size());
				error = GetExtendedTcpTable(table.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0);
				if (error != ERROR_INSUFFICIENT_BUFFER || size > 64 * 1024 * 1024) break;
				table.resize(size);
			}
			if (error) { info.tcp_error = error; continue; }
			if (family == AF_INET) {
				auto value = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(table.data());
				if (value->dwNumEntries > (table.size() - offsetof(MIB_TCPTABLE_OWNER_PID, table)) / sizeof(MIB_TCPROW_OWNER_PID)) { info.tcp_error = ERROR_INVALID_DATA; continue; }
				for (DWORD i = 0; i < value->dwNumEntries; ++i) { auto& row = value->table[i]; add(family, IpText(family, &row.dwLocalAddr), row.dwLocalPort, row.dwOwningPid); }
			}
			else {
				auto value = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(table.data());
				if (value->dwNumEntries > (table.size() - offsetof(MIB_TCP6TABLE_OWNER_PID, table)) / sizeof(MIB_TCP6ROW_OWNER_PID)) { info.tcp_error = ERROR_INVALID_DATA; continue; }
				for (DWORD i = 0; i < value->dwNumEntries; ++i) { auto& row = value->table[i]; add(family, IpText(family, row.ucLocalAddr, row.dwLocalScopeId), row.dwLocalPort, row.dwOwningPid); }
			}
		}
	}

	std::optional<std::wstring> RpcKey(const std::wstring& binding) {
		RPC_WSTR protocol = nullptr, address = nullptr, endpoint = nullptr;
		auto status = RpcStringBindingParseW(reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(binding.c_str())), nullptr, &protocol, &address, &endpoint, nullptr);
		std::optional<std::wstring> result;
		if (status == RPC_S_OK && protocol && endpoint) {
			auto type = Lower(reinterpret_cast<wchar_t*>(protocol)), name = Lower(reinterpret_cast<wchar_t*>(endpoint));
			auto host = address ? Lower(reinterpret_cast<wchar_t*>(address)) : L"";
			if (LocalAddress(host)) {
				if (type == L"ncalrpc" && !name.empty()) result = Key(L"ALPC Port", L"\\RPC Control\\" + name);
				else if (type == L"ncacn_np" && name.starts_with(L"\\pipe\\")) result = Key(L"File", L"\\Device\\NamedPipe\\" + name.substr(6));
			}
			if (type == L"ncacn_ip_tcp" && !name.empty() && name.find_first_not_of(L"0123456789") == std::wstring::npos) {
				wchar_t* end = nullptr;
				auto port = wcstoul(name.c_str(), &end, 10);
				if (port && port <= 65535) {
					// Keep numeric addresses specific. Never attribute a remote binding by port alone.
					IN_ADDR v4{}; IN6_ADDR v6{};
					if (InetPtonW(AF_INET, host.c_str(), &v4) == 1) result = TcpKey(IpText(AF_INET, &v4), port);
					else if (InetPtonW(AF_INET6, host.c_str(), &v6) == 1) result = TcpKey(IpText(AF_INET6, &v6), port);
					else if (LocalAddress(host)) result = TcpKey(L"local", port);
				}
			}
		}
		if (protocol) RpcStringFreeW(&protocol);
		if (address) RpcStringFreeW(&address);
		if (endpoint) RpcStringFreeW(&endpoint);
		return result;
	}
}

namespace win_obj {
	ProcessAssociator::ProcessAssociator(u32 types, u32 budget_ms, const std::vector<u32>& excluded_pids) {
		info_.requested = true;
		FILETIME time{};
		GetSystemTimeAsFileTime(&time);
		info_.timestamp = (static_cast<u64>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
		std::vector<unsigned char> buffer;
		auto fail = [&](u32 error, const wchar_t* operation) { info_.error = error; info_.error_operation = operation; };
		if (auto error = Snapshot(5, buffer)) { fail(error, L"NtQuerySystemInformation(processes)"); return; }
		size_t offset = 0;
		for (;;) {
			if (offset > buffer.size() || buffer.size() - offset < sizeof(NativeProcess)) { fail(0xC0000004, L"Process snapshot layout"); return; }
			auto& entry = *reinterpret_cast<NativeProcess*>(buffer.data() + offset);
			auto begin = reinterpret_cast<uintptr_t>(buffer.data()), name = reinterpret_cast<uintptr_t>(entry.name.Buffer);
			if (entry.name.Length && (entry.name.Length % sizeof(wchar_t) || name < begin || name > begin + buffer.size() || entry.name.Length > begin + buffer.size() - name)) {
				fail(0xC0000004, L"Process name layout"); return;
			}
			auto pid = reinterpret_cast<uintptr_t>(entry.pid);
			if (pid <= (std::numeric_limits<u32>::max)()) {
				ProcessIdentity process{ static_cast<u32>(pid), entry.name.Length ? std::wstring(entry.name.Buffer, entry.name.Length / sizeof(wchar_t)) : L"System Idle Process",
					static_cast<u64>(entry.created.QuadPart), entry.session };
				processes_.emplace(process.pid, std::move(process));
			}
			if (!entry.next) break;
			if (entry.next < sizeof(NativeProcess) || entry.next > buffer.size() - offset || entry.next % sizeof(void*)) { fail(0xC0000004, L"Process snapshot chain"); return; }
			offset += entry.next;
		}
		for (auto pid : excluded_pids) processes_.erase(pid);
		if (types == (1u << SESSIONS)) { info_.complete = true; return; }
		if (types & (1u << RPC)) CaptureTcp(named_, processes_, info_);
		if (auto error = Snapshot(64, buffer)) { fail(error, L"NtQuerySystemInformation(handles)"); return; }
		if (buffer.size() < offsetof(NativeHandles, entries)) { fail(0xC0000004, L"Handle snapshot header"); return; }
		auto& handles = *reinterpret_cast<NativeHandles*>(buffer.data());
		if (handles.count > (buffer.size() - offsetof(NativeHandles, entries)) / sizeof(NativeHandle)) { fail(0xC0000004, L"Handle snapshot count"); return; }
		info_.handles = handles.count;
		AccessContext context;
		if (context.GetInfo().error) { fail(context.GetInfo().error, L"Process worker token"); return; }
		HandleNameWorker worker(context, types);
		auto type_names = TypeNames();
		std::set<u32> unavailable;
		auto start = GetTickCount64();
		for (size_t i = 0; i < handles.count; ++i) {
			if (GetTickCount64() - start >= budget_ms) { info_.budget_exhausted = true; break; }
			const auto& entry = handles.entries[i];
			if (entry.pid > (std::numeric_limits<u32>::max)()) continue;
			auto pid = static_cast<u32>(entry.pid);
			auto identity = processes_.find(pid);
			if (!pid || identity == processes_.end() || unavailable.contains(pid)) continue;
			auto type = type_names.find(entry.type);
			if (type != type_names.end() && !RelevantHandleType(type->second, types)) continue;
			++info_.queried;
			auto result = worker.Query(pid, identity->second.created, entry.handle, 100);
			// Recheck the actual type; source handle values can be reused after the snapshot.
			// Never learn type-index mappings from such a racy duplicate.
			if (result.error) {
				++info_.failed;
				if (result.process_unavailable) { unavailable.insert(pid); ++info_.inaccessible_processes; }
				if (result.error == ERROR_TIMEOUT) ++info_.timeouts;
				if (result.worker_failed) { fail(result.error, L"Process name worker"); break; }
				continue;
			}
			if (result.name.empty()) continue;
			auto& associations = named_[Key(result.type, result.name)];
			Add(associations, identity->second, L"handle-holder");
			auto server = processes_.find(result.server_pid);
			if (result.server_created && server != processes_.end() && server->second.created == result.server_created)
				Add(associations, server->second, L"pipe-server");
		}
		info_.complete = !info_.error && !info_.tcp_error && !info_.budget_exhausted && !info_.failed;
	}

	void ProcessAssociator::Apply(std::vector<WinObj>& objects) const {
		std::map<std::wstring, WinObj*> devices;
		for (auto& object : objects) {
			object.processes.clear();
			object.process_status = L"none-observed";
			if (object.type == SESSIONS) {
				if (object.session_id) for (const auto& [pid, process] : processes_)
					if (pid && process.session == *object.session_id) Add(object.processes, process, L"session-member");
				continue;
			}
			std::wstring key;
			if (object.type == RPC) {
				auto endpoint = RpcKey(object.name);
				if (!endpoint) { object.process_status = L"unsupported-transport"; continue; }
				key = *endpoint;
			}
			else if (object.type == NAMEDPIPE && object.name.starts_with(L"\\\\.\\pipe\\")) key = Key(L"File", L"\\Device\\NamedPipe\\" + object.name.substr(9));
			else {
				constexpr const wchar_t* native[] = { L"Device", L"ALPC Port", L"", L"FilterConnectionPort", L"Event", L"Job", L"Mutant", L"File", L"Semaphore", L"", L"Timer" };
				if (object.type > TIMER) { object.process_status = L"unsupported-type"; continue; }
				key = Key(object.native_type.empty() ? native[object.type] : object.native_type, object.name);
			}
			auto found = named_.find(key);
			if (found != named_.end()) for (const auto& association : found->second) {
				auto relation = object.type == RPC && association.relation == L"handle-holder" ? L"rpc-endpoint-holder" : association.relation;
				Add(object.processes, association.process, relation);
			}
			if (object.type == DEVICE) devices.emplace(Lower(object.name), &object);
		}
		// A File handle refers to an open on a device path, not its driver or creator.
		// Match the longest path at a component boundary (Foo must not match Foobar).
		if (!devices.empty()) for (const auto& [key, associations] : named_) {
			if (!key.starts_with(L"File\n")) continue;
			auto path = key.substr(5);
			while (!path.empty()) {
				auto device = devices.find(path);
				if (device != devices.end()) {
					for (const auto& association : associations) if (association.relation == L"handle-holder")
						Add(device->second->processes, association.process, L"device-path-handle");
					break;
				}
				auto slash = path.rfind(L'\\');
				if (slash == std::wstring::npos) break;
				path.resize(slash);
			}
		}
		for (auto& object : objects) {
			if (!object.processes.empty()) object.process_status = L"observed";
			else if (object.process_status == L"none-observed" && !info_.complete) object.process_status = L"unknown-partial-scan";
			std::sort(object.processes.begin(), object.processes.end(), [](const auto& a, const auto& b) {
				return a.process.pid < b.process.pid || (a.process.pid == b.process.pid && a.relation < b.relation);
			});
		}
	}
}
