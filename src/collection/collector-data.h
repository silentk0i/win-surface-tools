#pragma once

#include "core/access-result.h"
#include "interfaces/IWinObjEnumerator.h"

namespace win_obj {
	struct CollectedGroup {
		WinObjType type = EVENT;
		bool discovered = false;
		std::vector<WinObj> objects;
		std::vector<EnumerationIssue> issues;
	};

	// This protocol deliberately has no access attempts, granted masks, or handles.
	struct CollectorData {
		bool requested = false;
		bool received = false;
		bool cleanup_confirmed = true; // Set by the unelevated parent, never trusted from IPC.
		u32 error = 0;
		std::wstring error_operation;
		u64 started = 0;
		u64 finished = 0;
		bool debug_requested = false;
		bool debug_enabled = false;
		u32 debug_error = 0;
		AccessTokenInfo token;
		ProcessScanInfo processes;
		std::vector<CollectedGroup> groups;
	};

	std::vector<unsigned char> EncodeCollectorData(const CollectorData& data);
	bool DecodeCollectorData(const std::vector<unsigned char>& bytes, CollectorData& data);
	void MergeCollectorObjects(std::vector<WinObj>& objects, const CollectedGroup& elevated);
}
