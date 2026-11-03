#pragma once

#include "report/scan-report.h"

namespace win_obj {
    enum class ReportFormat { HTML, LLM };

    std::wstring ReportTime();
    const wchar_t* ObjectTypeName(WinObjType type);
    std::wstring RenderReport(const ScanReport& report, ReportFormat format);
    // Publish through a temporary sibling file; existing reports survive failed writes.
    bool WriteReport(const std::wstring& path, const ScanReport& report, ReportFormat format, std::wstring& error);
}
