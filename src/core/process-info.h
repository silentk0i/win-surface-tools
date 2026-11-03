#pragma once

#include <string>
#include "core/types.h"

namespace win_obj {
	inline const wchar_t* CollectionSourceName(u32 sources) {
		return sources == 1 ? L"user" : sources == 2 ? L"administrator" : sources == 3 ? L"both" : L"unknown";
	}
	struct ProcessIdentity {
		u32 pid = 0;
		std::wstring name;
		u64 created = 0; // FILETIME; distinguishes reused PIDs in a snapshot.
		u32 session = 0;
		std::wstring image_path;
	};

	struct ProcessAssociation {
		ProcessIdentity process;
		std::wstring relation; // Evidence, never an inferred creator.
		u32 sources = 1; // 1=user collector, 2=administrator collector, 3=both.
	};

	struct ProcessScanInfo {
		bool requested = false;
		bool complete = false; // Snapshot traversal, not universal attribution.
		bool budget_exhausted = false;
		u64 timestamp = 0;
		u64 handles = 0;
		u64 queried = 0;
		u64 failed = 0;
		u64 timeouts = 0;
		u64 inaccessible_processes = 0;
		u32 tcp_error = 0; // Win32/IP Helper error, independent of handle traversal.
		u32 error = 0; // NTSTATUS for snapshot failures; Win32 for worker startup.
		std::wstring error_operation;
	};
}
