#pragma once

#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    class SessionsEnumerator final : public IWinObjEnumerator {
    public:
        WinObjType GetType() const noexcept override {
            return WinObjType::SESSIONS;
        }

        std::optional<std::vector<WinObj>> Enumerate() override;
    };
}

