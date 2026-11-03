#pragma once

#include <memory>
#include <unordered_map>
#include "core/win-obj.h"
#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
    class EnumerationManager {
    public:
        void Register(std::unique_ptr<IWinObjEnumerator> enumerator) {
            auto type = enumerator->GetType();
            enumerators_[type] = std::move(enumerator);
        }

        std::optional<std::vector<WinObj>> Enumerate(WinObjType type) {
            auto it = enumerators_.find(type);

            if (it == enumerators_.end()) {
                return {};
            }

            return it->second->Enumerate();
        }

        const std::vector<EnumerationIssue>& GetIssues(WinObjType type) const {
            auto it = enumerators_.find(type);
            if (it == enumerators_.end()) {
                static const std::vector<EnumerationIssue> empty{};
                return empty;
            }

            return it->second->GetIssues();
        }

    private:
        std::unordered_map<
            WinObjType,
            std::unique_ptr<IWinObjEnumerator>
        > enumerators_;
    };
}
