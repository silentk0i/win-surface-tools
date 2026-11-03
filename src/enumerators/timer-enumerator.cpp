#include "enumerators/timer-enumerator.h"
#include "native/object-directory.h"

namespace win_obj {
    std::optional<std::vector<WinObj>> TimerEnumerator::Enumerate() {
        return EnumerateObjectDirectory(GetType(), { L"Timer" }, issues_);
    }
}

