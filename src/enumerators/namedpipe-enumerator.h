#pragma once

#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    class NamedPipeEnumerator final : public IWinObjEnumerator {
    public:
        WinObjType GetType() const noexcept override {
            return WinObjType::NAMEDPIPE;
        }

        std::optional<std::vector<WinObj>> Enumerate() override;
    };
}

