#pragma once

#include <initializer_list>
#include <string_view>
#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    // Only directories are opened. Matching objects are recorded by name.
    std::optional<std::vector<WinObj>> EnumerateObjectDirectory(
        WinObjType type,
        std::initializer_list<std::wstring_view> native_types,
        std::vector<EnumerationIssue>& issues
    );

    void SortObjects(std::vector<WinObj>& objects);
}
