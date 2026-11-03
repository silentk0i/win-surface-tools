#pragma once

#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    class AlpcEnumerator final : public IWinObjEnumerator {
    public:
        WinObjType GetType() const noexcept override {
            return WinObjType::ALPC;
        }

        std::optional<std::vector<WinObj>> Enumerate() override;
    };
}
