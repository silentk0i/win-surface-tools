#pragma once

#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    class TimerEnumerator final : public IWinObjEnumerator {
    public:
        WinObjType GetType() const noexcept override {
            return WinObjType::TIMER;
        }

        std::optional<std::vector<WinObj>> Enumerate() override;
    };
}

