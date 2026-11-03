#include "access/access-worker.h"
#include <algorithm>
#include <sddl.h>
#include <bcrypt.h>
#include <sstream>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace win_obj {
    AccessContext::AccessContext() {
        HANDLE raw = nullptr;
        if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
            CloseHandle(raw);
            info_.impersonating = true;
            info_.error = ERROR_BAD_TOKEN_TYPE;
            info_.error_operation = L"Primary context requires no thread token";
            return;
        }
        if (GetLastError() != ERROR_NO_TOKEN) {
            info_.error = GetLastError();
            info_.error_operation = L"OpenThreadToken";
            return;
        }
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) {
            info_.error = GetLastError(); info_.error_operation = L"OpenProcessToken"; return;
        }
        UniqueHandle token(raw, CloseHandle);
        std::wostringstream canonical;
        auto query = [&](TOKEN_INFORMATION_CLASS type, bool optional = false) {
            DWORD bytes = 0;
            GetTokenInformation(token.get(), type, nullptr, 0, &bytes);
            auto initial_error = GetLastError();
            if (!bytes && optional && (initial_error == ERROR_INVALID_PARAMETER || initial_error == ERROR_NOT_SUPPORTED || initial_error == ERROR_CALL_NOT_IMPLEMENTED)) {
                canonical << type << L"=unsupported:" << initial_error << L';';
                return std::vector<unsigned char>{};
            }
            std::vector<unsigned char> buffer(bytes <= 1024 * 1024 ? bytes : 0);
            if (buffer.empty() || !GetTokenInformation(token.get(), type, buffer.data(), bytes, &bytes)) {
                info_.error = buffer.empty() ? ERROR_INVALID_DATA : GetLastError();
                info_.error_operation = L"GetTokenInformation(" + std::to_wstring(type) + L")";
                buffer.clear();
            }
            return buffer;
        };
        auto sid_text = [&](PSID sid) {
            LPWSTR value = nullptr;
            if (!sid || !ConvertSidToStringSidW(sid, &value)) {
                info_.error = ERROR_INVALID_SID; info_.error_operation = L"Token SID"; return std::wstring();
            }
            std::wstring result(value); LocalFree(value); return result;
        };
        auto scalar = [&](TOKEN_INFORMATION_CLASS type) {
            auto bytes = query(type);
            DWORD value = 0;
            if (bytes.size() >= sizeof(value)) memcpy(&value, bytes.data(), sizeof(value));
            canonical << type << L'=' << value << L';';
            return value;
        };
        auto user = query(TokenUser);
        if (user.empty()) return;
        auto& user_info = *reinterpret_cast<TOKEN_USER*>(user.data());
        info_.user_sid = sid_text(user_info.User.Sid);
        canonical << info_.user_sid << L':' << user_info.User.Attributes << L';';
        if (scalar(TokenType) != TokenPrimary) { info_.error = ERROR_BAD_TOKEN_TYPE; info_.error_operation = L"TokenType"; return; }
        auto statistics = query(TokenStatistics);
        if (statistics.empty()) return;
        auto& authentication = reinterpret_cast<TOKEN_STATISTICS*>(statistics.data())->AuthenticationId;
        auto luid_text = [](const LUID& value) { return std::to_wstring(value.HighPart) + L":" + std::to_wstring(value.LowPart); };
        info_.token_id = luid_text(reinterpret_cast<TOKEN_STATISTICS*>(statistics.data())->TokenId);
        info_.modified_id = luid_text(reinterpret_cast<TOKEN_STATISTICS*>(statistics.data())->ModifiedId);
        info_.authentication_id = std::to_wstring(authentication.HighPart) + L":" + std::to_wstring(authentication.LowPart);
        canonical << info_.authentication_id << L';';
        info_.session_id = scalar(TokenSessionId);
        info_.elevated = scalar(TokenElevation) != 0;
        info_.elevation_type = scalar(TokenElevationType);
        info_.app_container = scalar(TokenIsAppContainer) != 0;
        info_.restricted = scalar(TokenHasRestrictions) != 0;
        scalar(TokenMandatoryPolicy); scalar(TokenUIAccess); scalar(TokenSandBoxInert);
        scalar(TokenVirtualizationAllowed); scalar(TokenVirtualizationEnabled);
        auto integrity = query(TokenIntegrityLevel);
        if (integrity.empty()) return;
        auto& label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(integrity.data())->Label;
        canonical << sid_text(label.Sid) << L':' << label.Attributes << L';';
        info_.integrity_level = *GetSidSubAuthority(label.Sid, *GetSidSubAuthorityCount(label.Sid) - 1);
        for (auto type : { TokenOwner, TokenPrimaryGroup, TokenAppContainerSid }) {
            auto bytes = query(type);
            if (bytes.empty()) return;
            auto sid = *reinterpret_cast<PSID*>(bytes.data());
            canonical << type << L'=' << (sid ? sid_text(sid) : L"none") << L';';
        }
        auto groups = [&](TOKEN_INFORMATION_CLASS type, std::vector<std::wstring>& values) {
            auto bytes = query(type, type == TokenDeviceGroups || type == TokenRestrictedDeviceGroups);
            if (bytes.empty()) return;
            auto list = reinterpret_cast<TOKEN_GROUPS*>(bytes.data());
            for (DWORD i = 0; i < list->GroupCount; ++i)
                values.push_back(sid_text(list->Groups[i].Sid) + L":" + std::to_wstring(list->Groups[i].Attributes));
            std::sort(values.begin(), values.end());
            canonical << type << L'=';
            for (const auto& value : values) canonical << value << L',';
            canonical << L';';
        };
        groups(TokenGroups, info_.groups); groups(TokenRestrictedSids, info_.restricted_sids); groups(TokenCapabilities, info_.capabilities);
        std::vector<std::wstring> device_groups, restricted_device_groups;
        groups(TokenDeviceGroups, device_groups); groups(TokenRestrictedDeviceGroups, restricted_device_groups);
        auto privileges = query(TokenPrivileges);
        if (privileges.empty()) return;
        auto list = reinterpret_cast<TOKEN_PRIVILEGES*>(privileges.data());
        for (DWORD i = 0; i < list->PrivilegeCount; ++i) {
            auto& privilege = list->Privileges[i];
            auto luid = std::to_wstring(privilege.Luid.HighPart) + L":" + std::to_wstring(privilege.Luid.LowPart);
            // USED_FOR_ACCESS is accounting, not a change to the effective privilege state.
            info_.privilege_states.push_back(luid + L":" + std::to_wstring(privilege.Attributes & ~SE_PRIVILEGE_USED_FOR_ACCESS));
            if (!(privilege.Attributes & SE_PRIVILEGE_ENABLED)) continue;
            DWORD length = 0;
            LookupPrivilegeNameW(nullptr, &privilege.Luid, nullptr, &length);
            std::wstring name(length + 1, L'\0');
            if (!LookupPrivilegeNameW(nullptr, &privilege.Luid, name.data(), &length)) name = L"LUID(" + luid + L")";
            else name.resize(length);
            info_.enabled_privileges.push_back(std::move(name));
        }
        std::sort(info_.privilege_states.begin(), info_.privilege_states.end());
        for (const auto& value : info_.privilege_states) canonical << value << L',';
        auto final_statistics = query(TokenStatistics);
        if (final_statistics.empty()) return;
        if (luid_text(reinterpret_cast<TOKEN_STATISTICS*>(final_statistics.data())->ModifiedId) != info_.modified_id) {
            info_.error = ERROR_INVALID_DATA; info_.error_operation = L"Primary token changed during snapshot";
        }
        if (info_.error) return;
        auto value = canonical.str();
        unsigned char digest[32]{};
        if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, reinterpret_cast<PUCHAR>(value.data()),
            static_cast<ULONG>(value.size() * sizeof(wchar_t)), digest, sizeof(digest)) < 0) {
            info_.error = ERROR_INVALID_DATA; info_.error_operation = L"Token fingerprint"; return;
        }
        constexpr wchar_t hex[] = L"0123456789abcdef";
        for (auto byte : digest) { info_.fingerprint += hex[byte >> 4]; info_.fingerprint += hex[byte & 15]; }
    }

    u32 VerifyPrimaryContext(const std::wstring& fingerprint, bool allow_elevated) {
        AccessContext current;
        const auto& info = current.GetInfo();
        if (info.error) return info.error;
        if (info.elevated && !allow_elevated) return ERROR_ELEVATION_REQUIRED;
        return !fingerprint.empty() && fingerprint == info.fingerprint ? 0 : ERROR_INVALID_DATA;
    }

    AccessObservation ContextFailure(u32 error) {
        AccessObservation result{};
        result.status = AccessStatus::FAILED_PROBE;
        result.error_type = AccessErrorType::WIN32_ERROR;
        result.error = result.context_error = error;
        return result;
    }

    u32 VerifyUnchangedPrimaryContext(const AccessTokenInfo& baseline, bool allow_elevated) {
        if (baseline.error) return baseline.error;
        AccessContext current;
        const auto& info = current.GetInfo();
        if (info.error) return info.error;
        if (info.elevated && !allow_elevated) return ERROR_ELEVATION_REQUIRED;
        return !baseline.fingerprint.empty() && baseline.fingerprint == info.fingerprint &&
            baseline.token_id == info.token_id && baseline.modified_id == info.modified_id ? 0 : ERROR_INVALID_DATA;
    }
}

