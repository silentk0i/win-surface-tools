#include <memory>
#include "enumerators/namedpipe-enumerator.h"
#include "native/object-directory.h"

namespace win_obj {
    std::optional<std::vector<WinObj>> NamedPipeEnumerator::Enumerate() {
        issues_.clear();
        std::vector<WinObj> objects{};
        WIN32_FIND_DATAW data{};
        auto raw_handle = FindFirstFileW(L"\\\\.\\pipe\\*", &data);
        if (raw_handle == INVALID_HANDLE_VALUE) {
            auto error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_NO_MORE_FILES)
                return objects;

            issues_.push_back({ L"\\\\.\\pipe", error, EnumerationErrorType::WIN32_ERROR });
            return std::nullopt;
        }

        std::unique_ptr<void, decltype(&FindClose)> handle(raw_handle, FindClose);
        do {
            objects.push_back({ static_cast<u8>(GetType()), std::wstring(L"\\\\.\\pipe\\") + data.cFileName });
        } while (FindNextFileW(handle.get(), &data));

        auto error = GetLastError();
        if (error != ERROR_NO_MORE_FILES)
            issues_.push_back({ L"\\\\.\\pipe", error, EnumerationErrorType::WIN32_ERROR });

        SortObjects(objects);
        return objects;
    }
}
