#pragma once

#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    class SemaphoreEnumerator final : public IWinObjEnumerator {
    public:
        WinObjType GetType() const noexcept override {
            return WinObjType::SEMAPHORE;
        }

        std::optional<std::vector<WinObj>> Enumerate() override;
    };
}

