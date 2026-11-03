#pragma once

#include "collection/collector-data.h"

namespace win_obj {
	struct CollectorOptions {
		u32 types = 0;
		u32 process_budget_ms = 30000;
		bool processes = true;
		bool debug_privilege = false;
	};

	// UAC elevates only this helper. The calling process never changes its token.
	CollectorData CollectAsAdministrator(const CollectorOptions& options);
	std::optional<int> AdminCollectorMain(int argc, wchar_t* argv[]);
}
