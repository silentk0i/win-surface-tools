#pragma once

#include <unordered_map>
#include "access/access-worker.h"
#include "access/access-tests.h"

namespace win_obj {
    class AccessManager {
    public:
        AccessManager() {
            for (u8 type = DEVICE; type <= TIMER; ++type)
                Register(std::make_unique<ObjectAccessTest>(static_cast<WinObjType>(type)));
        }

        void Register(std::unique_ptr<IWinObjTest> test) {
            auto type = test->GetType();
            tests_[type] = std::move(test);
        }

        const AccessTokenInfo& GetTokenInfo() const noexcept { return context_.GetInfo(); }

        std::optional<AccessTestResult> Test(const WinObj& object, const AccessOptions& options = {}) {
            auto it = tests_.find(static_cast<WinObjType>(object.type));
            if (it == tests_.end())
                return std::nullopt;
            AccessProbeWorker probe(object, options, context_);
            return it->second->Test(object, options, probe);
        }

    private:
        AccessContext context_;
        std::unordered_map<WinObjType, std::unique_ptr<IWinObjTest>> tests_;
    };
}
