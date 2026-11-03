#include "enumerators/job-enumerator.h"
#include "native/object-directory.h"

namespace win_obj {
    std::optional<std::vector<WinObj>> JobEnumerator::Enumerate() {
        return EnumerateObjectDirectory(GetType(), { L"Job" }, issues_);
    }
}

