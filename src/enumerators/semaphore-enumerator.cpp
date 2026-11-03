#include "enumerators/semaphore-enumerator.h"
#include "native/object-directory.h"

namespace win_obj {
    std::optional<std::vector<WinObj>> SemaphoreEnumerator::Enumerate() {
        return EnumerateObjectDirectory(GetType(), { L"Semaphore" }, issues_);
    }
}

