#pragma once

#include "interfaces/IWinObjTest.h"

namespace win_obj {
    // Shared policy, with a rights catalog and probe method selected by type.
    class ObjectAccessTest final : public IWinObjTest {
    public:
        explicit ObjectAccessTest(WinObjType type) : type_(type) {}

        WinObjType GetType() const noexcept override { return type_; }
        AccessTestResult Test(const WinObj& object, const AccessOptions& options, IAccessProbe& probe) override;

    private:
        WinObjType type_;
    };
}
