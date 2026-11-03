#pragma once

#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    class MutantEnumerator final : public IWinObjEnumerator {
    public:
        WinObjType GetType() const noexcept override {
            return WinObjType::MUTANT;
        }

        std::optional<std::vector<WinObj>> Enumerate() override;
    };
}

