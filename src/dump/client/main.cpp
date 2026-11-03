#include "dump/pe/pe-rebuild.h"
#include "native/handle.h"
#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <fcntl.h>
#include <io.h>

#pragma comment(lib, "advapi32.lib")

namespace {
    using namespace win_obj;
    using namespace win_obj::dump;

    [[noreturn]] void Error(const char* operation) {
        throw std::runtime_error(std::string(operation) + " failed (Win32 " + std::to_string(GetLastError()) + ").");
    }
    std::string Hex(ULONGLONG value) { std::ostringstream out; out << "0x" << std::hex << value; return out.str(); }
    std::string Json(const std::string& value) {
        std::ostringstream out;
        out << '"';
        for (unsigned char c : value) {
            if (c == '"' || c == '\\') out << '\\' << c;
            else if (c < 32 || c >= 127) out << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(c);
            else out << c;
        }
        out << '"';
        return out.str();
    }
    std::wstring Widen(const std::string& value) { return { value.begin(), value.end() }; }
    std::string BaseName(const Module& module) {
        std::string name(module.path);
        auto slash = name.find_last_of("\\/");
        return slash == std::string::npos ? name : name.substr(slash + 1);
    }
    std::string Lower(std::string value) {
        for (auto& c : value) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        return value;
    }

    class DebugPrivilege {
        UniqueHandle token_{ nullptr, CloseHandle };
        TOKEN_PRIVILEGES previous_{};
        bool changed_ = false;
    public:
        DebugPrivilege() {
            HANDLE token = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) Error("OpenProcessToken");
            token_.reset(token);
            TOKEN_PRIVILEGES requested{};
            requested.PrivilegeCount = 1;
            if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &requested.Privileges[0].Luid)) Error("LookupPrivilegeValue");
            requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            DWORD returned = 0;
            SetLastError(ERROR_SUCCESS);
            if (!AdjustTokenPrivileges(token_.get(), FALSE, &requested, sizeof(previous_), &previous_, &returned)) Error("AdjustTokenPrivileges");
            if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) throw std::runtime_error("SeDebugPrivilege is required. Run from an elevated administrator terminal.");
            changed_ = true;
        }
        ~DebugPrivilege() { if (changed_) AdjustTokenPrivileges(token_.get(), FALSE, &previous_, 0, nullptr, nullptr); }
    };

    class Driver {
        UniqueHandle handle_{ nullptr, CloseHandle };
        void Ioctl(ULONG code, const void* request, DWORD request_size, void* output, DWORD size, DWORD& returned) {
            if (!DeviceIoControl(handle_.get(), code, const_cast<void*>(request), request_size, output, size, &returned, nullptr)) Error("Driver request");
        }
    public:
        Driver() {
            auto handle = CreateFileW(device_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot open WinObjDump (Win32 " + std::to_string(GetLastError()) +
                "). Load the signed win-obj-dump-driver.sys service first; see docs/driver-dumping.md.");
            handle_.reset(handle);
        }
        std::vector<Module> List() {
            std::vector<unsigned char> bytes(sizeof(ModuleList) + max_modules * sizeof(Module));
            DWORD returned = 0;
            Ioctl(ioctl_list, &protocol_version, sizeof(protocol_version), bytes.data(), static_cast<DWORD>(bytes.size()), returned);
            if (returned < sizeof(ModuleList)) throw std::runtime_error("Truncated module list.");
            auto header = reinterpret_cast<const ModuleList*>(bytes.data());
            if (header->version != protocol_version || header->count > max_modules || returned != sizeof(ModuleList) + header->count * sizeof(Module))
                throw std::runtime_error("Invalid module list response.");
            auto first = reinterpret_cast<const Module*>(header + 1);
            std::vector<Module> modules(first, first + header->count);
            for (const auto& module : modules) if (module.path[255]) throw std::runtime_error("Unterminated module path.");
            return modules;
        }
        Module Query(const Request& request) {
            Module result{};
            DWORD returned = 0;
            Ioctl(ioctl_query, &request, sizeof(request), &result, sizeof(result), returned);
            if (returned != sizeof(result) || !result.base || !result.size || result.size > max_image_size || result.path[255])
                throw std::runtime_error("Invalid module query response.");
            return result;
        }
        Snapshot CaptureImage(Request request) {
            auto module = Query(request);
            request.expected_base = module.base;
            request.expected_size = module.size;
            std::vector<unsigned char> buffer(CaptureSize(module.size));
            DWORD returned = 0;
            Ioctl(ioctl_capture, &request, sizeof(request), buffer.data(), static_cast<DWORD>(buffer.size()), returned);
            if (returned != buffer.size()) throw std::runtime_error("Truncated capture response.");
            auto header = reinterpret_cast<const Capture*>(buffer.data());
            if (header->version != protocol_version || header->module.base != module.base || header->module.size != module.size ||
                header->module.path[255] || header->pages != PageCount(module.size) || header->image_offset != ImageOffset(module.size))
                throw std::runtime_error("Invalid capture response.");
            Snapshot result;
            result.module = header->module;
            result.started = header->started;
            result.finished = header->finished;
            auto pages = reinterpret_cast<const Page*>(header + 1);
            result.pages.assign(pages, pages + header->pages);
            for (size_t i = 0; i < result.pages.size(); ++i)
                if (result.pages[i].copied > (std::min)(page_size, module.size - static_cast<ULONG>(i) * page_size))
                    throw std::runtime_error("Invalid page coverage response.");
            result.image.assign(buffer.begin() + header->image_offset, buffer.end());
            return result;
        }
    };

    Request MakeRequest(const std::wstring& name) {
        if (name.empty() || name.size() >= target_characters) throw std::runtime_error("Target name is empty or too long.");
        Request request{};
        request.version = protocol_version;
        request.kind = name[0] == L'\\' ? TargetKind::DEVICE : TargetKind::MODULE;
        std::copy(name.begin(), name.end(), request.name);
        return request;
    }

    class Exports {
        Driver& driver_;
        std::vector<Module> modules_;
        std::map<std::string, std::vector<ExportSymbol>> cache_;
        const Module& Find(std::string name) {
            name = Lower(name);
            const Module* found = nullptr;
            for (const auto& module : modules_) {
                auto base = Lower(BaseName(module));
                auto dot = base.find_last_of('.');
                bool match = base == name || (name.find('.') == std::string::npos && base.substr(0, dot) == name);
                if (match) {
                    if (found) throw std::runtime_error("Ambiguous loaded dependency module name.");
                    found = &module;
                }
            }
            if (!found) throw std::runtime_error("Import dependency is not in the loaded module list: " + name);
            return *found;
        }
        const std::vector<ExportSymbol>& Symbols(const std::string& name) {
            const auto& module = Find(name);
            auto key = Lower(BaseName(module));
            auto found = cache_.find(key);
            if (found != cache_.end()) return found->second;
            auto request = MakeRequest(Widen(BaseName(module)));
            request.expected_base = module.base;
            request.expected_size = module.size;
            auto snapshot = driver_.CaptureImage(request);
            return cache_.emplace(key, ReadExports(snapshot)).first->second;
        }
        ULONGLONG Address(const ExportSymbol& symbol, unsigned depth) {
            if (symbol.forwarder.empty()) return symbol.address;
            if (depth >= 16) return 0;
            auto dot = symbol.forwarder.find_last_of('.');
            if (dot == std::string::npos) return 0;
            auto module = symbol.forwarder.substr(0, dot);
            auto name = symbol.forwarder.substr(dot + 1);
            bool ordinal = !name.empty() && name[0] == '#';
            unsigned long number = 0;
            if (ordinal) {
                size_t parsed = 0;
                number = std::stoul(name.substr(1), &parsed);
                if (parsed != name.size() - 1 || number > 65535) return 0;
            }
            for (const auto& item : Symbols(module))
                if ((ordinal && item.symbol.ordinal == number) || (!ordinal && item.symbol.name == name)) return Address(item, depth + 1);
            return 0;
        }
    public:
        explicit Exports(Driver& driver) : driver_(driver), modules_(driver.List()) {}
        std::optional<ImportSymbol> Resolve(const std::string& module, ULONGLONG address) {
            const auto& symbols = Symbols(module);
            for (const auto& item : symbols)
                if (item.forwarder.empty() && item.address == address) return item.symbol;
            for (const auto& item : symbols) {
                if (item.forwarder.empty()) continue;
                try { if (Address(item, 0) == address) return item.symbol; }
                catch (const std::exception&) { /* An unrelated missing forwarder must not hide other exports. */ }
            }
            return std::nullopt;
        }
    };

    void WriteNew(const std::filesystem::path& path, const void* data, size_t size) {
        auto file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) Error("Create output file");
        UniqueHandle handle(file, CloseHandle);
        DWORD written = 0;
        if (size > MAXDWORD || !WriteFile(handle.get(), data, static_cast<DWORD>(size), &written, nullptr) || written != size || !FlushFileBuffers(handle.get())) {
            auto error = GetLastError();
            handle.reset();
            DeleteFileW(path.c_str());
            SetLastError(error);
            Error("Write output file");
        }
    }

    void WriteIdaHelper(const std::filesystem::path& path) {
        auto module = GetModuleHandleW(nullptr);
        auto resource = FindResourceW(module, MAKEINTRESOURCEW(101), RT_RCDATA);
        if (!resource) Error("Find IDA helper resource");
        auto loaded = LoadResource(module, resource);
        if (!loaded) Error("Load IDA helper resource");
        auto bytes = LockResource(loaded);
        auto size = SizeofResource(module, resource);
        if (!bytes || !size) throw std::runtime_error("Empty IDA helper resource.");
        WriteNew(path, bytes, size);
    }

    std::string Manifest(const Snapshot& snapshot, const std::optional<RebuiltImage>& rebuilt, const std::string& failure) {
        std::ostringstream out;
        out << "{\n  \"format\":\"WINOBJ_MEMORY_DUMP\",\"version\":1,\"source\":\"loaded kernel virtual memory\",\n"
            << "  \"module\":" << Json(snapshot.module.path) << ",\"loaded_base\":" << Json(Hex(snapshot.module.base))
            << ",\"size\":" << snapshot.module.size << ",\"started_filetime\":" << snapshot.started << ",\"finished_filetime\":" << snapshot.finished
            << ",\n  \"complete_memory\":" << (snapshot.Available(0, snapshot.image.size()) ? "true" : "false")
            << ",\"pe_written\":" << (rebuilt ? "true" : "false") << ",\"rebuild_error\":" << Json(failure) << ",\n  \"missing_ranges\":[";
        bool comma = false;
        for (size_t i = 0; i < snapshot.pages.size(); ++i) {
            const auto& page = snapshot.pages[i];
            auto count = (std::min)(static_cast<size_t>(page_size), snapshot.image.size() - i * page_size);
            if (page.copied == count) continue;
            if (comma) out << ',';
            comma = true;
            out << "\n    {\"rva\":" << i * page_size + page.copied << ",\"size\":" << count - page.copied
                << ",\"status\":" << Json(Hex(static_cast<ULONG>(page.status))) << '}';
        }
        out << "\n  ]";
        if (rebuilt) {
            out << ",\n  \"preferred_base\":" << Json(Hex(rebuilt->preferred_base)) << ",\"output_base\":" << Json(Hex(rebuilt->output_base))
                << ",\"relocations_reversed\":" << rebuilt->relocations_reversed << ",\n  \"warnings\":[";
            for (size_t i = 0; i < rebuilt->warnings.size(); ++i) { if (i) out << ','; out << Json(rebuilt->warnings[i]); }
            out << "],\n  \"imports\":[";
            for (size_t i = 0; i < rebuilt->imports.size(); ++i) {
                const auto& entry = rebuilt->imports[i];
                if (i) out << ',';
                out << "\n    {\"module\":" << Json(entry.module) << ",\"name\":" << Json(entry.symbol.name)
                    << ",\"ordinal\":" << entry.symbol.ordinal << ",\"by_ordinal\":" << (entry.symbol.by_ordinal ? "true" : "false")
                    << ",\"iat_rva\":" << entry.iat_rva << ",\"live_address\":" << Json(Hex(entry.live_address))
                    << ",\"from_exports\":" << (entry.recovered ? "true" : "false") << '}';
            }
            out << "\n  ]";
        }
        out << "\n}\n";
        return out.str();
    }

    void Usage() {
        std::wcout << L"win-obj-dump list\nwin-obj-dump dump <module.sys|\\Device\\name> [--out file.sys] [--base loaded|preferred]\n"
            << L"Requires the signed WinObjDump driver and an elevated administrator token.\n"
            << L"Writes an analysis PE, .memory.bin raw capture, .json evidence, and .ida.py analysis helper.\n"
            << L"After loading the PE/PDB in IDA, run the .ida.py helper to resolve runtime-patched calls.\n"
            << L"Device targets select the driver at the top of the named device stack.\n";
    }
}

int wmain(int argc, wchar_t* argv[]) {
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);
    try {
        if (argc == 2 && (std::wstring_view(argv[1]) == L"--help" || std::wstring_view(argv[1]) == L"-h")) { Usage(); return 0; }
        if (argc < 2) { Usage(); return 1; }
        std::wstring command = argv[1];
        if (command == L"list" && argc == 2) {
            DebugPrivilege privilege;
            Driver driver;
            for (const auto& module : driver.List())
                std::wcout << Widen(Hex(module.base)) << L" " << module.size << L" " << Widen(module.path) << L'\n';
            return 0;
        }
        if (command != L"dump" || argc < 3) { Usage(); return 1; }
        auto request = MakeRequest(argv[2]);
        std::filesystem::path output;
        bool preferred = false;
        bool base_set = false;
        for (int i = 3; i < argc; ++i) {
            std::wstring option = argv[i];
            if (option == L"--out" && i + 1 < argc && output.empty()) output = argv[++i];
            else if (option == L"--base" && i + 1 < argc && !base_set) {
                std::wstring value = argv[++i];
                if (value != L"loaded" && value != L"preferred") throw std::runtime_error("--base must be loaded or preferred.");
                preferred = value == L"preferred";
                base_set = true;
            }
            else throw std::runtime_error("Unknown, duplicate, or incomplete option.");
        }
        DebugPrivilege privilege;
        Driver driver;
        auto module = driver.Query(request);
        if (output.empty()) output = Widen(BaseName(module)) + L".dump.sys";
        output = std::filesystem::absolute(output);
        auto raw = std::filesystem::path(output.wstring() + L".memory.bin");
        auto manifest = std::filesystem::path(output.wstring() + L".json");
        auto ida_helper = std::filesystem::path(output.wstring() + L".ida.py");
        for (const auto& path : { output, raw, manifest, ida_helper }) {
            if (!std::filesystem::is_directory(path.parent_path()) || std::filesystem::exists(path))
                throw std::runtime_error("Output directory must exist and all output paths must be unused.");
        }
        request.expected_base = module.base;
        request.expected_size = module.size;
        std::wcout << L"Capturing " << Widen(module.path) << L" at " << Widen(Hex(module.base)) << L" (" << module.size << L" bytes)\n";
        auto snapshot = driver.CaptureImage(request);
        WriteNew(raw, snapshot.image.data(), snapshot.image.size());
        std::wcout << L"Saved raw capture: " << raw.wstring() << L'\n';
        std::optional<RebuiltImage> rebuilt;
        std::string failure;
        try {
            Exports exports(driver);
            rebuilt = RebuildImage(snapshot, preferred, [&](const std::string& name, ULONGLONG address) { return exports.Resolve(name, address); });
            WriteNew(output, rebuilt->bytes.data(), rebuilt->bytes.size());
        }
        catch (const std::exception& error) { failure = error.what(); rebuilt.reset(); }
        auto text = Manifest(snapshot, rebuilt, failure);
        WriteNew(manifest, text.data(), text.size());
        WriteIdaHelper(ida_helper);
        std::wcout << L"Saved manifest: " << manifest.wstring() << L'\n';
        if (!rebuilt) { std::wcerr << L"PE reconstruction failed: " << Widen(failure) << L'\n'; return 2; }
        std::wcout << L"Saved analysis PE: " << output.wstring() << L"\nImports: " << rebuilt->imports.size()
            << L"; reversed relocations: " << rebuilt->relocations_reversed << L'\n';
        std::wcout << L"After loading the PE and matching PDB in IDA, run: " << ida_helper.wstring() << L'\n';
        for (const auto& warning : rebuilt->warnings) std::wcerr << Widen(warning) << L'\n';
        return snapshot.Available(0, snapshot.image.size()) ? 0 : 2;
    }
    catch (const std::exception& error) { std::wcerr << Widen(error.what()) << L'\n'; return 1; }
}
