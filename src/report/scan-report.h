#pragma once

#include "core/access-result.h"
#include "interfaces/IWinObjEnumerator.h"
#include "collection/collector-data.h"

namespace win_obj {
    struct ReportObject {
        WinObj object;
        std::optional<AccessTestResult> access;
        std::wstring error;
    };

    struct ReportGroup {
        WinObjType type;
        bool discovered = false;
        bool probes_completed = true;
        size_t total = 0;
        std::vector<ReportObject> objects;
        std::vector<EnumerationIssue> issues;
        bool user_discovered = false;
        size_t user_total = 0;
        bool admin_discovered = false;
        size_t admin_total = 0;
        std::vector<EnumerationIssue> admin_issues;
    };

    struct ScanReport {
        std::wstring started;
        std::wstring finished;
        std::wstring selection;
        std::wstring match;
        bool access_requested = false;
        bool completed = false;
        AccessOptions options;
        std::optional<AccessTokenInfo> token;
        std::vector<ReportGroup> groups;
        ProcessScanInfo processes;
        CollectorData admin;
        u32 user_context_error = 0;
    };
}
