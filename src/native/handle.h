#pragma once

#include <memory>
#include <windows.h>

namespace win_obj {
    using UniqueHandle = std::unique_ptr<void, decltype(&CloseHandle)>;
}
