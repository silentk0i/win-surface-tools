#pragma once

#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    class DeviceEnumerator final : public IWinObjEnumerator {
    public:
        WinObjType GetType() const noexcept override {
            return WinObjType::DEVICE;
        }

        std::optional<std::vector<WinObj>> Enumerate() override;
    };
}
