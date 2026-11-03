#include <algorithm>
#include <tuple>
#include "enumerators/rpc-enumerator.h"
#include <rpc.h>

#pragma comment(lib, "rpcrt4.lib")

namespace {
    struct RpcInquiry {
        RPC_EP_INQ_HANDLE handle = nullptr;

        ~RpcInquiry() {
            if (handle)
                RpcMgmtEpEltInqDone(&handle);
        }
    };

    struct RpcBinding {
        RPC_BINDING_HANDLE handle = nullptr;

        ~RpcBinding() {
            if (handle)
                RpcBindingFree(&handle);
        }
    };

    struct RpcString {
        RPC_WSTR value = nullptr;

        ~RpcString() {
            if (value)
                RpcStringFreeW(&value);
        }
    };
}

namespace win_obj {
    std::optional<std::vector<WinObj>> RpcEnumerator::Enumerate() {
        issues_.clear();
        std::vector<WinObj> objects{};
        RpcInquiry inquiry;
        auto status = RpcMgmtEpEltInqBegin(nullptr, RPC_C_EP_ALL_ELTS, nullptr,
            RPC_C_VERS_ALL, nullptr, &inquiry.handle);
        if (status != RPC_S_OK) {
            issues_.push_back({ L"RpcMgmtEpEltInqBegin", static_cast<u32>(status), EnumerationErrorType::RPC_ERROR });
            return std::nullopt;
        }

        bool found_entry = false;
        while (true) {
            RPC_IF_ID interface_id{};
            UUID object_id{};
            RpcBinding binding;
            status = RpcMgmtEpEltInqNextW(inquiry.handle, &interface_id, &binding.handle, &object_id, nullptr);
            if (status == RPC_X_NO_MORE_ENTRIES)
                break;

            if (status != RPC_S_OK) {
                issues_.push_back({ L"RpcMgmtEpEltInqNextW", static_cast<u32>(status), EnumerationErrorType::RPC_ERROR });
                if (!found_entry)
                    return std::nullopt;
                break;
            }

            found_entry = true;
            RpcString name;
            RpcString interface_name;
            RpcString object_name;
            status = RpcBindingToStringBindingW(binding.handle, &name.value);
            if (status == RPC_S_OK)
                status = UuidToStringW(&interface_id.Uuid, &interface_name.value);
            if (status == RPC_S_OK)
                status = UuidToStringW(&object_id, &object_name.value);
            if (status != RPC_S_OK) {
                issues_.push_back({ L"RPC endpoint identity", static_cast<u32>(status), EnumerationErrorType::RPC_ERROR });
                continue;
            }

            WinObj object{ static_cast<u8>(GetType()), reinterpret_cast<const wchar_t*>(name.value) };
            object.rpc = RpcEndpointInfo{
                reinterpret_cast<const wchar_t*>(interface_name.value),
                interface_id.VersMajor,
                interface_id.VersMinor,
                reinterpret_cast<const wchar_t*>(object_name.value)
            };
            objects.push_back(std::move(object));
        }

        // Several interfaces may share one binding. Keep their identities distinct.
        auto identity = [](const WinObj& object) {
            return std::tie(object.name, object.rpc->interface_id, object.rpc->major_version,
                object.rpc->minor_version, object.rpc->object_id);
        };
        std::sort(objects.begin(), objects.end(), [&](const WinObj& left, const WinObj& right) {
            return identity(left) < identity(right);
        });
        objects.erase(std::unique(objects.begin(), objects.end(), [&](const WinObj& left, const WinObj& right) {
            return identity(left) == identity(right);
        }), objects.end());
        return objects;
    }
}
