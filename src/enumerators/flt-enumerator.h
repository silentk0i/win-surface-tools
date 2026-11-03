#pragma once

#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    class FltEnumerator final : public IWinObjEnumerator {
    public:
        WinObjType GetType() const noexcept override {
            return WinObjType::FLT;
        }

        std::optional<std::vector<WinObj>> Enumerate() override;
    };
}

