#include <algorithm>
#include <limits>
#include <memory>
#include <unordered_set>
#include "native/object-directory.h"
#include "native/nt.h"

namespace win_obj {
    void SortObjects(std::vector<WinObj>& objects) {
        std::sort(objects.begin(), objects.end(), [](const WinObj& left, const WinObj& right) {
            return left.name < right.name;
        });
        objects.erase(std::unique(objects.begin(), objects.end(), [](const WinObj& left, const WinObj& right) {
            return left.type == right.type && left.name == right.name;
        }), objects.end());
    }

    std::optional<std::vector<WinObj>> EnumerateObjectDirectory(
        WinObjType type,
        std::initializer_list<std::wstring_view> native_types,
        std::vector<EnumerationIssue>& issues
    ) {
        issues.clear();
        std::vector<WinObj> objects{};
        auto module = GetModuleHandleW(L"ntdll.dll");
        auto open_directory = reinterpret_cast<decltype(&NtOpenDirectoryObject)>(
            module ? GetProcAddress(module, "NtOpenDirectoryObject") : nullptr);
        auto query_directory = reinterpret_cast<decltype(&NtQueryDirectoryObject)>(
            module ? GetProcAddress(module, "NtQueryDirectoryObject") : nullptr);

        if (!open_directory || !query_directory) {
            issues.push_back({ L"ntdll.dll", ERROR_PROC_NOT_FOUND, EnumerationErrorType::WIN32_ERROR });
            return std::nullopt;
        }

        constexpr NTSTATUS no_more_entries = static_cast<NTSTATUS>(0x8000001A);
        constexpr NTSTATUS buffer_too_small = static_cast<NTSTATUS>(0xC0000023);
        constexpr NTSTATUS buffer_overflow = static_cast<NTSTATUS>(0x80000005);
        constexpr NTSTATUS info_length_mismatch = static_cast<NTSTATUS>(0xC0000004);
        struct PendingDirectory {
            std::wstring path;
            bool optional = false;
        };
        std::vector<PendingDirectory> directories{ { L"\\" } };
        // A session directory can deny listing while its named-object directories
        // remain traversable. Seed these known paths independently of the parent.
        auto add_session = [&](const std::wstring& path) {
            directories.push_back({ path + L"\\BaseNamedObjects", true });
            directories.push_back({ path + L"\\AppContainerNamedObjects", true });
        };
        DWORD session_id = 0;
        if (ProcessIdToSessionId(GetCurrentProcessId(), &session_id))
            add_session(L"\\Sessions\\" + std::to_wstring(session_id));
        std::unordered_set<std::wstring> visited;
        std::vector<unsigned char> buffer(4096);

        while (!directories.empty()) {
            auto directory = std::move(directories.back());
            directories.pop_back();
            auto& path = directory.path;
            if (!visited.insert(path).second)
                continue;

            if (path.size() > (std::numeric_limits<USHORT>::max)() / sizeof(wchar_t)) {
                issues.push_back({ path, ERROR_FILENAME_EXCED_RANGE, EnumerationErrorType::WIN32_ERROR });
                continue;
            }

            UNICODE_STRING name{};
            name.Buffer = path.data();
            name.Length = static_cast<USHORT>(path.size() * sizeof(wchar_t));
            name.MaximumLength = name.Length;
            OBJECT_ATTRIBUTES attributes{};
            InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            HANDLE raw_handle = nullptr;
            auto status = open_directory(&raw_handle, DIRECTORY_QUERY, &attributes);
            if (status < 0) {
                constexpr NTSTATUS name_not_found = static_cast<NTSTATUS>(0xC0000034);
                constexpr NTSTATUS path_not_found = static_cast<NTSTATUS>(0xC000003A);
                if (directory.optional && (status == name_not_found || status == path_not_found))
                    continue;
                issues.push_back({ path, static_cast<u32>(status), EnumerationErrorType::NT_ERROR });
                if (path == L"\\")
                    return std::nullopt;
                continue;
            }

            std::unique_ptr<void, decltype(&CloseHandle)> handle(raw_handle, CloseHandle);
            ULONG context = 0;
            BOOLEAN restart = TRUE;
            while (true) {
                ULONG length = 0;
                auto previous_context = context;
                status = query_directory(handle.get(), buffer.data(), static_cast<ULONG>(buffer.size()),
                    TRUE, restart, &context, &length);
                if (status == no_more_entries)
                    break;

                if (status == buffer_too_small || status == buffer_overflow || status == info_length_mismatch) {
                    // A single entry contains at most two USHORT-length strings.
                    constexpr size_t max_buffer = 256 * 1024;
                    auto size = (std::max)(buffer.size() * 2, static_cast<size_t>(length));
                    if (size <= max_buffer) {
                        buffer.resize(size);
                        context = previous_context;
                        continue;
                    }
                }

                if (status != 0) {
                    issues.push_back({ path, static_cast<u32>(status), EnumerationErrorType::NT_ERROR });
                    if (path == L"\\" && restart)
                        return std::nullopt;
                    break;
                }

                restart = FALSE;
                auto entry = reinterpret_cast<const OBJECT_DIRECTORY_INFORMATION*>(buffer.data());
                std::wstring entry_name(entry->Name.Buffer, entry->Name.Length / sizeof(wchar_t));
                std::wstring_view entry_type(entry->TypeName.Buffer, entry->TypeName.Length / sizeof(wchar_t));
                auto full_name = path == L"\\" ? path + entry_name : path + L"\\" + entry_name;

                // Symbolic links are not followed: they can alias ancestors or other namespaces.
                if (entry_type == L"Directory") {
                    directories.push_back({ full_name });
                    if (path == L"\\Sessions" && !entry_name.empty() &&
                        entry_name.find_first_not_of(L"0123456789") == std::wstring::npos)
                        add_session(full_name);
                }

                if (std::find(native_types.begin(), native_types.end(), entry_type) != native_types.end()) {
                    WinObj object{ static_cast<u8>(type), std::move(full_name) };
                    object.native_type = entry_type;
                    objects.push_back(std::move(object));
                }
            }
        }

        SortObjects(objects);
        return objects;
    }
}
