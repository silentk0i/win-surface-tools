#include "enumerators/alpc-enumerator.h"
#include "native/object-directory.h"

namespace win_obj {
    std::optional<std::vector<WinObj>> AlpcEnumerator::Enumerate() {
        return EnumerateObjectDirectory(GetType(), { L"ALPC Port", L"Port" }, issues_);
    }
}
