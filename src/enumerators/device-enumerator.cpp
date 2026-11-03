#include "enumerators/device-enumerator.h"
#include "native/object-directory.h"

namespace win_obj {
    std::optional<std::vector<WinObj>> DeviceEnumerator::Enumerate() {
        return EnumerateObjectDirectory(GetType(), { L"Device" }, issues_);
    }
}
