#include "enumerators/event-enumerator.h"
#include "native/object-directory.h"

namespace win_obj {
    std::optional<std::vector<WinObj>> EventEnumerator::Enumerate() {
        return EnumerateObjectDirectory(GetType(), { L"Event" }, issues_);
    }
}

