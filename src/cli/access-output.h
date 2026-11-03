#pragma once

#include "core/access-result.h"
#include "collection/collector-data.h"

namespace win_obj {
    std::wstring JsonString(const std::wstring& value);
    std::wstring ProcessJson(const ProcessIdentity& process);
    std::wstring ProcessScanJson(const ProcessScanInfo& info);
    std::wstring AccessTokenJson(const AccessTokenInfo& token);
    std::wstring CollectorSummaryJson(const CollectorData& collector);
    void PrintAccessToken(const AccessTokenInfo& token, bool json);
    void PrintAccessResult(const AccessTestResult& result, bool json);
}
