#pragma once

#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    class JobEnumerator final : public IWinObjEnumerator {
    public:
        WinObjType GetType() const noexcept override {
            return WinObjType::JOB;
        }

        std::optional<std::vector<WinObj>> Enumerate() override;
    };
}

