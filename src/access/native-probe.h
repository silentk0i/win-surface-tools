#pragma once

#include "core/access-result.h"

namespace win_obj {
    AccessObservation ProbeNativeObject(const WinObj& object, AccessMethod method, ACCESS_MASK access, u32 timeout_ms);
    AccessObservation AccessFailure(u32 error, AccessErrorType type);
}
