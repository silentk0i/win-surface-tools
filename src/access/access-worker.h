#pragma once

#include "interfaces/IWinObjTest.h"
#include "native/handle.h"

namespace win_obj {
    class AccessContext {
    public:
        AccessContext();
        const AccessTokenInfo& GetInfo() const noexcept { return info_; }

    private:
        AccessTokenInfo info_;
    };

    // Never adjusts privileges, changes a token, or silently reverts impersonation.
    u32 VerifyPrimaryContext(const std::wstring& fingerprint, bool allow_elevated = false);
    u32 VerifyUnchangedPrimaryContext(const AccessTokenInfo& baseline, bool allow_elevated = false);
    AccessObservation ContextFailure(u32 error);

    class AccessProbeWorker final : public IAccessProbe {
    public:
        AccessProbeWorker(const WinObj& object, const AccessOptions& options, const AccessContext& context);
        ~AccessProbeWorker();
        AccessObservation Execute(AccessMethod method, ACCESS_MASK access) override;

    private:
        struct State;
        std::unique_ptr<State> state_;
    };

    // Both the CLI and integration-test executable dispatch this before other work.
    using AccessProbeFunction = AccessObservation(*)(const WinObj&, AccessMethod, ACCESS_MASK, u32);
    std::optional<int> AccessWorkerMain(int argc, wchar_t* argv[], AccessProbeFunction function = nullptr);
}
