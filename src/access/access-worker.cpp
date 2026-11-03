#include <algorithm>
#include <cwchar>
#include <limits>
#include "access/access-worker.h"
#include "access/native-probe.h"

namespace {
    constexpr u32 worker_magic = 0x574F4132;
    struct SharedProbe {
        u32 magic = worker_magic;
        u32 stop = 0;
        wchar_t fingerprint[65]{};
        u32 type = 0;
        u32 session_id = 0;
        u32 has_session = 0;
        u32 timeout_ms = 0;
        win_obj::AccessMethod method = win_obj::AccessMethod::OPEN;
        ACCESS_MASK access = 0;
        wchar_t name[32768]{};
        wchar_t native_type[64]{};
        win_obj::AccessObservation result;
    };

    std::wstring HandleArgument(HANDLE handle) {
        return std::to_wstring(reinterpret_cast<uintptr_t>(handle));
    }

    HANDLE ParseHandle(const wchar_t* text) {
        wchar_t* end = nullptr;
        auto value = _wcstoui64(text, &end, 10);
        if (!value || !end || *end || value > (std::numeric_limits<uintptr_t>::max)())
            return nullptr;
        return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(value));
    }
}

namespace win_obj {
    struct AccessProbeWorker::State {
        WinObj object;
        AccessOptions options;
        const AccessContext& context;
        UniqueHandle mapping{ nullptr, CloseHandle };
        UniqueHandle request{ nullptr, CloseHandle };
        UniqueHandle response{ nullptr, CloseHandle };
        UniqueHandle process{ nullptr, CloseHandle };
        UniqueHandle job{ nullptr, CloseHandle };
        SharedProbe* shared = nullptr;

        State(const WinObj& value, const AccessOptions& settings, const AccessContext& identity) :
            object(value), options(settings), context(identity) {}

        void Stop() {
            if (process) {
                if (shared && request) {
                    shared->stop = 1;
                    SetEvent(request.get());
                }
                if (WaitForSingleObject(process.get(), 100) != WAIT_OBJECT_0)
                    TerminateProcess(process.get(), ERROR_TIMEOUT);
            }
            job.reset(); // Kill-on-close applies only to this probe's worker.
            process.reset();
            if (shared) {
                UnmapViewOfFile(shared);
                shared = nullptr;
            }
            response.reset();
            request.reset();
            mapping.reset();
        }

        ~State() { Stop(); }

        u32 Start() {
            if (context.GetInfo().error)
                return context.GetInfo().error;
            if (auto error = VerifyUnchangedPrimaryContext(context.GetInfo())) return error;
            if (object.name.size() >= 32768 || object.native_type.size() >= 64 ||
                object.name.find(L'\0') != std::wstring::npos)
                return ERROR_INVALID_NAME;
            SECURITY_ATTRIBUTES security{ sizeof(security), nullptr, TRUE };
            mapping.reset(CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0, sizeof(SharedProbe), nullptr));
            if (!mapping)
                return GetLastError();
            request.reset(CreateEventW(&security, FALSE, FALSE, nullptr));
            if (!request)
                return GetLastError();
            response.reset(CreateEventW(&security, FALSE, FALSE, nullptr));
            if (!response)
                return GetLastError();
            shared = static_cast<SharedProbe*>(MapViewOfFile(mapping.get(), FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedProbe)));
            if (!shared)
                return GetLastError();
            new (shared) SharedProbe{};
            wcscpy_s(shared->fingerprint, context.GetInfo().fingerprint.c_str());
            shared->type = object.type;
            shared->has_session = object.session_id.has_value();
            shared->session_id = object.session_id.value_or(0);
            shared->timeout_ms = options.timeout_ms;
            std::copy(object.name.begin(), object.name.end(), shared->name);
            std::copy(object.native_type.begin(), object.native_type.end(), shared->native_type);

            std::wstring executable(32768, L'\0');
            auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
            if (!length || length == executable.size())
                return ERROR_FILENAME_EXCED_RANGE;
            executable.resize(length);
            auto command = L"\"" + executable + L"\" --access-worker " + HandleArgument(mapping.get()) + L" " +
                HandleArgument(request.get()) + L" " + HandleArgument(response.get());

            SIZE_T bytes = 0;
            InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
            std::vector<unsigned char> storage(bytes);
            auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes))
                return GetLastError();
            struct AttributeCleanup {
                LPPROC_THREAD_ATTRIBUTE_LIST value;
                ~AttributeCleanup() { DeleteProcThreadAttributeList(value); }
            } cleanup{ attributes };
            HANDLE inherited[] = { mapping.get(), request.get(), response.get() };
            if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                inherited, sizeof(inherited), nullptr, nullptr))
                return GetLastError();

            job.reset(CreateJobObjectW(nullptr, nullptr));
            if (!job)
                return GetLastError();
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
                return GetLastError();
            STARTUPINFOEXW startup{};
            startup.StartupInfo.cb = sizeof(startup);
            startup.lpAttributeList = attributes;
            PROCESS_INFORMATION information{};
            if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                nullptr, nullptr, &startup.StartupInfo, &information))
                return GetLastError();
            process.reset(information.hProcess);
            UniqueHandle thread(information.hThread, CloseHandle);
            if (!AssignProcessToJobObject(job.get(), process.get()))
                return GetLastError();
            if (ResumeThread(thread.get()) == static_cast<DWORD>(-1))
                return GetLastError();
            return ERROR_SUCCESS;
        }
    };

    AccessProbeWorker::AccessProbeWorker(const WinObj& object, const AccessOptions& options, const AccessContext& context) :
        state_(std::make_unique<State>(object, options, context)) {}

    AccessProbeWorker::~AccessProbeWorker() = default;

    AccessObservation AccessProbeWorker::Execute(AccessMethod method, ACCESS_MASK access) {
        auto start = GetTickCount64();
        auto& state = *state_;
        auto finish = [&](AccessObservation result) {
            result.elapsed_ms = GetTickCount64() - start;
            return result;
        };
        if (state.context.GetInfo().error) return finish(ContextFailure(state.context.GetInfo().error));
        if (auto error = VerifyUnchangedPrimaryContext(state.context.GetInfo())) return finish(ContextFailure(error));
        if (!state.options.timeout_ms || state.options.timeout_ms > 60000)
            return finish(AccessFailure(ERROR_INVALID_PARAMETER, AccessErrorType::WIN32_ERROR));
        if (!state.process) {
            auto error = state.Start();
            if (error) {
                state.Stop();
                return finish(AccessFailure(error, AccessErrorType::WIN32_ERROR));
            }
        }
        state.shared->method = method;
        state.shared->access = access;
        state.shared->result = {};
        if (!SetEvent(state.request.get())) {
            auto error = GetLastError();
            state.Stop();
            return finish(AccessFailure(error, AccessErrorType::WIN32_ERROR));
        }
        HANDLE waits[] = { state.response.get(), state.process.get() };
        auto wait = WaitForMultipleObjects(2, waits, FALSE, state.options.timeout_ms);
        if (wait == WAIT_OBJECT_0) {
            auto result = state.shared->result;
            if (auto error = VerifyUnchangedPrimaryContext(state.context.GetInfo())) result = ContextFailure(error);
            if (result.context_error) state.Stop();
            return finish(result);
        }
        auto error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : wait == WAIT_FAILED ? GetLastError() : ERROR_PROCESS_ABORTED;
        state.Stop();
        // A later explicit request starts a fresh worker; no error suppresses it.
        return finish(AccessFailure(error, AccessErrorType::WIN32_ERROR));
    }

    std::optional<int> AccessWorkerMain(int argc, wchar_t* argv[], AccessProbeFunction function) {
        if (argc < 2 || std::wstring_view(argv[1]) != L"--access-worker")
            return std::nullopt;
        if (argc != 5)
            return 2;
        auto mapping = ParseHandle(argv[2]);
        auto request = ParseHandle(argv[3]);
        auto response = ParseHandle(argv[4]);
        if (!mapping || !request || !response)
            return 2;
        auto shared = static_cast<SharedProbe*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedProbe)));
        if (!shared)
            return 2;
        struct ViewCleanup {
            void* value;
            ~ViewCleanup() { UnmapViewOfFile(value); }
        } cleanup{ shared };
        if (shared->magic != worker_magic || shared->fingerprint[64] || wcslen(shared->fingerprint) != 64 || shared->type > TIMER || shared->name[32767] || shared->native_type[63])
            return 2;
        WinObj object{ static_cast<u8>(shared->type), shared->name };
        object.native_type = shared->native_type;
        if (shared->has_session)
            object.session_id = shared->session_id;
        const std::wstring fingerprint = shared->fingerprint;
        AccessContext worker_context;
        const auto startup_error = VerifyPrimaryContext(fingerprint);
        while (WaitForSingleObject(request, INFINITE) == WAIT_OBJECT_0) {
            if (shared->stop)
                break;
            if (auto before_error = startup_error ? startup_error : VerifyUnchangedPrimaryContext(worker_context.GetInfo())) shared->result = ContextFailure(before_error);
            else {
                auto result = (function ? function : ProbeNativeObject)(object, shared->method, shared->access, shared->timeout_ms);
                if (auto error = VerifyUnchangedPrimaryContext(worker_context.GetInfo())) result = ContextFailure(error);
                else result.context_verified = 1;
                shared->result = result;
            }
            if (!SetEvent(response))
                return 2;
        }
        return 0;
    }
}
