#pragma once

#include <map>
#include "core/win-obj.h"

namespace win_obj {
	class ProcessAssociator {
	public:
		// Capture before access probes create any handles. The budget bounds name queries.
		explicit ProcessAssociator(u32 types, u32 budget_ms = 30000, const std::vector<u32>& excluded_pids = {});
		void Apply(std::vector<WinObj>& objects) const;
		const ProcessScanInfo& GetInfo() const noexcept { return info_; }
	private:
		ProcessScanInfo info_;
		std::map<u32, ProcessIdentity> processes_;
		std::map<std::wstring, std::vector<ProcessAssociation>> named_;
	};
}
