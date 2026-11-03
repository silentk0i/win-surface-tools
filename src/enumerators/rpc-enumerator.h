#pragma once

#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    class RpcEnumerator final : public IWinObjEnumerator {
    public:
        WinObjType GetType() const noexcept override {
            return WinObjType::RPC;
        }

        std::optional<std::vector<WinObj>> Enumerate() override;
    };
}

