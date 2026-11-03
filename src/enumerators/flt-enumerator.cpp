#include "enumerators/flt-enumerator.h"
#include "native/object-directory.h"

namespace win_obj {
    std::optional<std::vector<WinObj>> FltEnumerator::Enumerate() {
        return EnumerateObjectDirectory(GetType(), { L"FilterConnectionPort", L"FilterCommunicationPort" }, issues_);
    }
}

