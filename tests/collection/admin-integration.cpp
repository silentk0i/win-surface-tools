#include <algorithm>
#include <iostream>
#include <stdexcept>
#include "collection/admin-collector.h"
#include "core/access-manager.h"
#include "enumerators/event-enumerator.h"
#include "process/process-worker.h"
#include "native/nt.h"
#include <sddl.h>

namespace {
	using namespace win_obj;
	void Check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
	u64 Created(HANDLE process) { FILETIME c{}, e{}, k{}, u{}; Check(GetProcessTimes(process, &c, &e, &k, &u) != FALSE, "Process creation time failed"); return (static_cast<u64>(c.dwHighDateTime) << 32) | c.dwLowDateTime; }
	std::wstring Suffix(u32 pid, u64 created) { return L"win-obj-admin-test-" + std::to_wstring(pid) + L"-" + std::to_wstring(created); }
	std::wstring Executable() { std::wstring value(32768, L'\0'); auto size = GetModuleFileNameW(nullptr, value.data(), static_cast<DWORD>(value.size())); Check(size && size < value.size(), "Executable path failed"); value.resize(size); return value; }
	std::wstring ObjectName(u32 pid, u64 created) {
		DWORD session = 0; Check(ProcessIdToSessionId(pid, &session) != FALSE, "Session unavailable");
		return L"\\Sessions\\" + std::to_wstring(session) + L"\\BaseNamedObjects\\" + Suffix(pid, created);
	}
	int HoldFixture(u32 parent_pid, u64 created, HANDLE ready) {
		UniqueHandle parent(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parent_pid), CloseHandle);
		Check(parent && Created(parent.get()) == created, "Fixture parent identity mismatch");
		auto suffix = Suffix(parent_pid, created);
		UniqueHandle stop(OpenEventW(SYNCHRONIZE, FALSE, (L"Local\\" + suffix + L"-stop").c_str()), CloseHandle);
		Check(stop != nullptr, "Fixture stop event missing");
		PSECURITY_DESCRIPTOR descriptor = nullptr;
		Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;BA)(A;;GA;;;SY)", SDDL_REVISION_1, &descriptor, nullptr) != FALSE, "Fixture ACL failed");
		struct Cleanup { void* value; ~Cleanup() { LocalFree(value); } } cleanup{ descriptor };
		auto directory_name = ObjectName(parent_pid, created);
		UNICODE_STRING name{ static_cast<USHORT>(directory_name.size() * 2), static_cast<USHORT>((directory_name.size() + 1) * 2), directory_name.data() };
		OBJECT_ATTRIBUTES attributes{}; InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, nullptr, descriptor);
		using CreateDirectory = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
		using CreateNativeEvent = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN);
		auto module = GetModuleHandleW(L"ntdll.dll");
		auto create_directory = reinterpret_cast<CreateDirectory>(GetProcAddress(module, "NtCreateDirectoryObject"));
		auto create_event = reinterpret_cast<CreateNativeEvent>(GetProcAddress(module, "NtCreateEvent"));
		HANDLE raw = nullptr;
		Check(create_directory && create_event && create_directory(&raw, (STANDARD_RIGHTS_REQUIRED | 0xf), &attributes) >= 0, "Protected directory fixture failed");
		UniqueHandle directory(raw, CloseHandle);
		auto event_name = directory_name + L"\\OnlyAdmin";
		name = { static_cast<USHORT>(event_name.size() * 2), static_cast<USHORT>((event_name.size() + 1) * 2), event_name.data() };
		Check(create_event(&raw, EVENT_ALL_ACCESS, &attributes, 0, FALSE) >= 0, "Administrator-only event fixture failed");
		UniqueHandle event(raw, CloseHandle);
		Check(SetEvent(ready) != FALSE, "Fixture ready signal failed");
		HANDLE waits[] = { stop.get(), parent.get() };
		WaitForMultipleObjects(2, waits, FALSE, 90000); // Cleanup even if the test controller disappears.
		return 0;
	}
	void StartFixture(u32 parent_pid, u64 created) {
		SECURITY_ATTRIBUTES attributes{ sizeof(attributes), nullptr, TRUE };
		UniqueHandle ready(CreateEventW(&attributes, TRUE, FALSE, nullptr), CloseHandle);
		Check(ready != nullptr, "Ready event failed");
		auto executable = Executable();
		auto command = L"\"" + executable + L"\" --fixture-host " + std::to_wstring(parent_pid) + L" " + std::to_wstring(created) + L" " + std::to_wstring(reinterpret_cast<uintptr_t>(ready.get()));
		STARTUPINFOW startup{ sizeof(startup) }; PROCESS_INFORMATION information{};
		Check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information) != FALSE, "Elevated fixture host failed");
		UniqueHandle process(information.hProcess, CloseHandle), thread(information.hThread, CloseHandle);
		HANDLE waits[] = { ready.get(), process.get() };
		if (WaitForMultipleObjects(2, waits, FALSE, 10000) != WAIT_OBJECT_0) { TerminateProcess(process.get(), 2); throw std::runtime_error("Elevated fixture not ready"); }
	}
}

int wmain(int argc, wchar_t* argv[]) {
	using namespace win_obj;
	try {
		if (auto worker = AccessWorkerMain(argc, argv)) return *worker;
		if (auto worker = ProcessWorkerMain(argc, argv)) return *worker;
		if (argc == 5 && std::wstring_view(argv[1]) == L"--fixture-host")
			return HoldFixture(wcstoul(argv[2], nullptr, 10), _wcstoui64(argv[3], nullptr, 10), reinterpret_cast<HANDLE>(static_cast<uintptr_t>(_wcstoui64(argv[4], nullptr, 10))));
		if (argc == 5 && std::wstring_view(argv[1]) == L"--admin-collector") {
			AccessContext elevated; Check(!elevated.GetInfo().error && elevated.GetInfo().elevated, "Helper is not elevated");
			StartFixture(wcstoul(argv[3], nullptr, 10), _wcstoui64(argv[4], nullptr, 10));
			return AdminCollectorMain(argc, argv).value_or(2);
		}
		AccessContext baseline; Check(!baseline.GetInfo().error && !baseline.GetInfo().elevated, "Run this test from an unelevated terminal");
		auto pid = GetCurrentProcessId(); auto created = Created(GetCurrentProcess()); auto name = ObjectName(pid, created) + L"\\OnlyAdmin";
		auto acl = L"D:P(A;;GA;;;" + baseline.GetInfo().user_sid + L")(A;;GA;;;BA)(A;;GA;;;SY)(A;;0x100000;;;WD)";
		PSECURITY_DESCRIPTOR descriptor = nullptr;
		Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor, nullptr) != FALSE, "Stop ACL failed");
		struct DescriptorCleanup { void* value; ~DescriptorCleanup() { LocalFree(value); } } descriptor_cleanup{ descriptor };
		SECURITY_ATTRIBUTES attributes{ sizeof(attributes), descriptor, FALSE };
		UniqueHandle stop(CreateEventW(&attributes, TRUE, FALSE, (L"Local\\" + Suffix(pid, created) + L"-stop").c_str()), CloseHandle);
		Check(stop != nullptr, "Stop event failed");
		struct StopFixture { HANDLE event; ~StopFixture() { SetEvent(event); } } cleanup{ stop.get() };
		std::wcout << L"This test requests UAC elevation for temporary administrator-only objects. Access probes remain unelevated.\n" << std::flush;
		CollectorOptions options; options.types = 1u << EVENT; options.processes = false; options.debug_privilege = true;
		auto elevated = CollectAsAdministrator(options);
		if (elevated.error) std::wcerr << elevated.error_operation << L": " << elevated.error << L'\n';
		Check(elevated.received && !elevated.error && elevated.token.elevated, "Live administrator collection failed");
		Check(elevated.debug_enabled && !elevated.debug_error, "Collector debug privilege was not recorded");
		Check(VerifyPrimaryContext(baseline.GetInfo().fingerprint) == 0, "Elevated collector changed the user token");
		Check(elevated.groups.size() == 1 && std::any_of(elevated.groups[0].objects.begin(), elevated.groups[0].objects.end(), [&](const auto& object) { return object.name == name; }), "Administrator did not discover its protected fixture");
		EventEnumerator enumerator; auto objects = enumerator.Enumerate();
		Check(objects.has_value() && std::none_of(objects->begin(), objects->end(), [&](const auto& object) { return object.name == name; }), "User unexpectedly enumerated protected directory");
		MergeCollectorObjects(*objects, elevated.groups[0]);
		auto object = std::find_if(objects->begin(), objects->end(), [&](const auto& value) { return value.name == name; });
		Check(object != objects->end() && object->discovery_sources == 2, "Admin-only provenance missing");
		AccessProbeWorker worker(*object, {}, baseline);
		auto result = worker.Execute(AccessMethod::OPEN, 1); // EVENT_QUERY_STATE; owner READ_CONTROL is a different right.
		Check(result.status == AccessStatus::DENIED && !result.opened && !result.has_granted && result.context_verified && !result.context_error,
			"Administrator discovery contaminated the user's access result");
		Check(VerifyPrimaryContext(baseline.GetInfo().fingerprint) == 0, "User context changed after probing");
		std::wcout << L"Live administrator discovery / unchanged user access isolation test passed.\n"; return 0;
	}
	catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
