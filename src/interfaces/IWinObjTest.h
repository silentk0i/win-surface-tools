#pragma once

#include "core/access-result.h"

namespace win_obj {
    class IAccessProbe {
    public:
        virtual ~IAccessProbe() = default;
        virtual AccessObservation Execute(AccessMethod method, ACCESS_MASK access) = 0;
    };

    class IWinObjTest {
    public:
        virtual ~IWinObjTest() = default;
        virtual WinObjType GetType() const noexcept = 0;
        virtual AccessTestResult Test(const WinObj& object, const AccessOptions& options, IAccessProbe& probe) = 0;
    };
}
