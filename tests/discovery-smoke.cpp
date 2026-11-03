#include <algorithm>
#include <iostream>
#include <memory>
#include <stdexcept>
#include "core/enumerator-manager.h"
#include "enumerators/enumerators.h"
#include "native/object-directory.h"
#include "native/nt.h"

namespace {
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;

    void Check(bool condition, const char* message) {
        if (!condition)
            throw std::runtime_error(message);
    }

    Handle Own(HANDLE value) {
        Check(value && value != INVALID_HANDLE_VALUE, "Could not create a discovery fixture");
        return Handle(value, CloseHandle);
    }

    Handle CreateNativeObject(const std::wstring& path, bool directory) {
        using CreateDirectory = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
        using CreateEvent = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, int, BOOLEAN);
        auto module = GetModuleHandleW(L"ntdll.dll");
        auto create_directory = reinterpret_cast<CreateDirectory>(GetProcAddress(module, "NtCreateDirectoryObject"));
        auto create_event = reinterpret_cast<CreateEvent>(GetProcAddress(module, "NtCreateEvent"));
        Check(create_directory && create_event, "Native fixture APIs missing");
        UNICODE_STRING name{};
        name.Buffer = const_cast<wchar_t*>(path.data());
        name.Length = static_cast<USHORT>(path.size() * sizeof(wchar_t));
        name.MaximumLength = name.Length;
        OBJECT_ATTRIBUTES attributes{};
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
        HANDLE handle = nullptr;
        auto status = directory ? create_directory(&handle, DIRECTORY_QUERY, &attributes) :
            create_event(&handle, SYNCHRONIZE, &attributes, 0, FALSE);
        Check(status >= 0, "Could not create native discovery fixture");
        return Own(handle);
    }

    void CheckFixture(win_obj::IWinObjEnumerator& enumerator, const std::wstring& suffix) {
        auto objects = enumerator.Enumerate();
        Check(objects.has_value(), "Enumeration failed");
        size_t matches = 0;
        for (const auto& object : *objects) {
            Check(object.type == enumerator.GetType(), "Incorrect object type");
            Check(object.status == win_obj::UNTESTED && object.access == 0, "Discovery must not claim access");
            if (object.name.ends_with(suffix))
                ++matches;
        }
        if (matches != 1) {
            std::wcerr << L"Fixture: " << suffix << L", matches: " << matches << std::endl;
            Check(false, "Named fixture missing or duplicated");
        }
    }
}

int main() {
    try {
        auto suffix = L"win-obj-enum-test-" + std::to_wstring(GetCurrentProcessId()) + L"-\u03a9";
        auto local = L"Local\\" + suffix;
        auto global = L"Global\\" + suffix;
        auto event = Own(CreateEventW(nullptr, TRUE, FALSE, (local + L"-event").c_str()));
        auto global_event = Own(CreateEventW(nullptr, TRUE, FALSE, (global + L"-global-event").c_str()));
        auto job = Own(CreateJobObjectW(nullptr, (local + L"-job").c_str()));
        auto mutant = Own(CreateMutexW(nullptr, FALSE, (local + L"-mutant").c_str()));
        auto semaphore = Own(CreateSemaphoreW(nullptr, 0, 1, (local + L"-semaphore").c_str()));
        auto timer = Own(CreateWaitableTimerW(nullptr, TRUE, (local + L"-timer").c_str()));
        auto pipe_name = L"\\\\.\\pipe\\" + suffix + L"-pipe";
        auto pipe = Own(CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT, 2, 1024, 1024, 0, nullptr));
        auto second_pipe = Own(CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT, 2, 1024, 1024, 0, nullptr));
        auto directory_name = L"\\BaseNamedObjects\\" + suffix + L"-directory";
        auto directory = CreateNativeObject(directory_name, true);
        auto nested_directory = CreateNativeObject(directory_name + L"\\nested", true);
        auto long_suffix = suffix + std::wstring(3000, L'x');
        auto long_event = CreateNativeObject(directory_name + L"\\nested\\" + long_suffix, false);

        win_obj::EventEnumerator events;
        win_obj::JobEnumerator jobs;
        win_obj::MutantEnumerator mutants;
        win_obj::SemaphoreEnumerator semaphores;
        win_obj::TimerEnumerator timers;
        win_obj::NamedPipeEnumerator pipes;
        CheckFixture(events, suffix + L"-event");
        CheckFixture(events, suffix + L"-global-event");
        CheckFixture(events, long_suffix);
        CheckFixture(jobs, suffix + L"-job");
        CheckFixture(mutants, suffix + L"-mutant");
        CheckFixture(semaphores, suffix + L"-semaphore");
        CheckFixture(timers, suffix + L"-timer");
        CheckFixture(pipes, suffix + L"-pipe");

        // Releasing the last handle removes the object; a later scan must be fresh.
        event.reset();
        auto refreshed = events.Enumerate();
        Check(refreshed.has_value(), "Repeat scan failed");
        Check(std::none_of(refreshed->begin(), refreshed->end(), [&](const win_obj::WinObj& object) {
            return object.name.ends_with(suffix + L"-event");
        }), "Scan returned a stale object");

        std::vector<win_obj::EnumerationIssue> issues;
        auto empty = win_obj::EnumerateObjectDirectory(win_obj::EVENT, { L"NonexistentTestObjectType" }, issues);
        Check(empty.has_value() && empty->empty(), "Empty scan was reported as failure");

        win_obj::SessionsEnumerator sessions;
        auto session_objects = sessions.Enumerate();
        Check(session_objects.has_value(), "Session enumeration failed");
        DWORD session_id = 0;
        Check(ProcessIdToSessionId(GetCurrentProcessId(), &session_id) != FALSE, "Cannot obtain current session");
        Check(std::any_of(session_objects->begin(), session_objects->end(), [&](const win_obj::WinObj& object) {
            return object.session_id == session_id;
        }), "Current session missing");

        win_obj::RpcEnumerator rpc;
        auto endpoints = rpc.Enumerate();
        Check(endpoints.has_value(), "RPC enumeration failed");
        for (const auto& object : *endpoints) {
            Check(object.rpc.has_value() && !object.rpc->interface_id.empty(), "RPC identity missing");
            Check(object.name.find(L':') != std::wstring::npos, "RPC binding missing");
        }

        win_obj::DeviceEnumerator devices;
        win_obj::AlpcEnumerator alpc;
        win_obj::FltEnumerator flt;
        Check(devices.Enumerate().has_value(), "Device enumeration failed");
        Check(alpc.Enumerate().has_value(), "ALPC enumeration failed");
        Check(flt.Enumerate().has_value(), "Filter port enumeration failed");

        DWORD before = 0;
        DWORD after = 0;
        Check(GetProcessHandleCount(GetCurrentProcess(), &before) != FALSE, "Cannot read handle count");
        for (int i = 0; i < 10; ++i) {
            Check(events.Enumerate().has_value(), "Repeated directory scan failed");
            CheckFixture(pipes, suffix + L"-pipe");
            Check(rpc.Enumerate().has_value(), "Repeated RPC scan failed");
            Check(sessions.Enumerate().has_value(), "Repeated session scan failed");
        }
        Check(GetProcessHandleCount(GetCurrentProcess(), &after) != FALSE, "Cannot read handle count");
        Check(after <= before + 2, "Repeated enumeration leaked handles");

        win_obj::EnumerationManager manager;
        Check(!manager.Enumerate(win_obj::EVENT), "Unregistered enumerator must fail");
        manager.Register(std::make_unique<win_obj::EventEnumerator>());
        Check(manager.Enumerate(win_obj::EVENT).has_value(), "Registered enumerator failed");
        std::cout << "Discovery smoke tests passed" << std::endl;
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << error.what() << std::endl;
        return 1;
    }
}
