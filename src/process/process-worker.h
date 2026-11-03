#pragma once

#include "access/access-worker.h"

namespace win_obj {
	struct HandleNameResult {
		std::wstring type;
		std::wstring name;
		u32 error = 0;
		bool process_unavailable = false;
		u32 server_pid = 0;
		u64 server_created = 0;
		bool worker_failed = false;
	};

	bool RelevantHandleType(const std::wstring& type, u32 types);

	class HandleNameWorker {
	public:
		HandleNameWorker(const AccessContext& context, u32 types);
		~HandleNameWorker();
		HandleNameResult Query(u32 pid, u64 created, uintptr_t handle, u32 timeout_ms);
	private:
		struct State;
		std::unique_ptr<State> state_;
	};

	using HandleQueryOverride = std::optional<HandleNameResult>(*)(u32, u64, uintptr_t);
	std::optional<int> ProcessWorkerMain(int argc, wchar_t* argv[], HandleQueryOverride function = nullptr);
}
