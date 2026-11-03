#pragma once
#include <vector>
#include <optional>
#include <windows.h>
#include <string>
#include "core/types.h"
#include "core/process-info.h"

namespace win_obj {

	enum WinObjStatus {
		INACTIVE,
		ACTIVE,
		UNTESTED
	};

	enum WinObjType {
		DEVICE,
		ALPC,
		RPC,
		FLT,
		EVENT,
		JOB,
		MUTANT,
		NAMEDPIPE,
		SEMAPHORE,
		SESSIONS,
		TIMER
	};

	struct RpcEndpointInfo {
		std::wstring interface_id;
		u16 major_version = 0;
		u16 minor_version = 0;
		std::wstring object_id;
	};

	struct WinObj {
		u8 type;
		std::wstring name;
		u8 status = UNTESTED;
		ACCESS_MASK access = 0; // Not evaluated until an access probe runs.
		std::optional<RpcEndpointInfo> rpc;
		std::optional<u32> session_id;
		std::wstring native_type; // Preserve distinctions such as Port versus ALPC Port.
		std::vector<ProcessAssociation> processes;
		std::wstring process_status = L"not-collected";
		u32 discovery_sources = 1; // Independent of every access observation.
	};
}
