#pragma once

#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    class EventEnumerator final : public IWinObjEnumerator {
    public:
        WinObjType GetType() const noexcept override {
            return WinObjType::EVENT;
        }

        std::optional<std::vector<WinObj>> Enumerate() override;
    };
}

