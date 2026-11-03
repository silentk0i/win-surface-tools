#pragma once
#include "core/win-obj.h"

namespace win_obj {
    enum class EnumerationErrorType {
        WIN32_ERROR,
        NT_ERROR,
        RPC_ERROR
    };

    struct EnumerationIssue {
        std::wstring name;
        u32 error;
        EnumerationErrorType type;
    };

    class IWinObjEnumerator {
    public:
        virtual ~IWinObjEnumerator() = default;

        virtual WinObjType GetType() const noexcept = 0;

        // An empty vector is a successful empty scan; nullopt is a failed scan.
        // A partial scan returns its results with details in GetIssues().
        virtual std::optional<std::vector<WinObj>> Enumerate() = 0;

        const std::vector<EnumerationIssue>& GetIssues() const noexcept {
            return issues_;
        }

    protected:
        std::vector<EnumerationIssue> issues_;
    };
}
