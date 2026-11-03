#include <memory>
#include "enumerators/sessions-enumerator.h"
#include "native/object-directory.h"
#include <wtsapi32.h>

#pragma comment(lib, "wtsapi32.lib")

namespace win_obj {
    std::optional<std::vector<WinObj>> SessionsEnumerator::Enumerate() {
        issues_.clear();
        std::vector<WinObj> objects{};
        PWTS_SESSION_INFOW sessions = nullptr;
        DWORD count = 0;
        if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
            issues_.push_back({ L"WTSEnumerateSessionsW", GetLastError(), EnumerationErrorType::WIN32_ERROR });
            return std::nullopt;
        }

        std::unique_ptr<void, decltype(&WTSFreeMemory)> memory(sessions, WTSFreeMemory);
        for (DWORD i = 0; i < count; ++i) {
            WinObj object{ static_cast<u8>(GetType()), L"Session " + std::to_wstring(sessions[i].SessionId) };
            if (sessions[i].pWinStationName && sessions[i].pWinStationName[0])
                object.name += L" (" + std::wstring(sessions[i].pWinStationName) + L")";
            object.session_id = sessions[i].SessionId;
            objects.push_back(std::move(object));
        }

        SortObjects(objects);
        return objects;
    }
}
