#include "enumerators/mutant-enumerator.h"
#include "native/object-directory.h"

namespace win_obj {
    std::optional<std::vector<WinObj>> MutantEnumerator::Enumerate() {
        return EnumerateObjectDirectory(GetType(), { L"Mutant" }, issues_);
    }
}

