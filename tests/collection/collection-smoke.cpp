#include <iostream>
#include <stdexcept>
#include "collection/collector-data.h"

namespace {
	using namespace win_obj;
	void Check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
}

int main() {
	using namespace win_obj;
	try {
		CollectorData source; source.token.elevated = true; source.token.user_sid = L"S-1-5-21-fixture";
		source.token.fingerprint = std::wstring(64, L'a'); source.token.authentication_id = L"0:1234";
		source.token.groups = { L"S-1-5-32-544:7" }; source.token.privilege_states = { L"0:20:2" };
		source.started = 100; source.finished = 200; source.processes.requested = true; source.processes.failed = 2;
		CollectedGroup group; group.type = EVENT; group.discovered = true;
		group.issues.push_back({ L"\\Denied", 5, EnumerationErrorType::WIN32_ERROR });
		WinObj shared{ EVENT, L"\\BaseNamedObjects\\Shared-\u03a9" }; shared.native_type = L"Event";
		shared.access = EVENT_ALL_ACCESS; shared.status = ACTIVE; // Must never cross the wire.
		shared.processes.push_back({ { 123, L"<script>.exe", 123456789, 2, L"C:\\test\\<script>.exe" }, L"handle-holder", 2 });
		shared.process_status = L"observed";
		WinObj only_admin{ EVENT, L"\\BaseNamedObjects\\AdminOnly" }; only_admin.native_type = L"Event";
		group.objects = { shared, only_admin }; source.groups.push_back(group);
		auto encoded = EncodeCollectorData(source);
		CollectorData decoded;
		Check(DecodeCollectorData(encoded, decoded), "Collector round trip failed");
		Check(decoded.received && decoded.token.elevated && decoded.token.groups == source.token.groups, "Collector identity lost");
		Check(decoded.groups[0].objects[0].access == 0 && decoded.groups[0].objects[0].status == UNTESTED, "Privileged access crossed the metadata protocol");
		Check(decoded.groups[0].objects[0].processes[0].sources == 2 && decoded.groups[0].objects[0].discovery_sources == 2, "Administrator provenance lost");
		Check(decoded.groups[0].objects[0].processes[0].process.image_path == shared.processes[0].process.image_path, "Process path lost");
		WinObj user = shared; user.discovery_sources = 1; user.access = 1; user.processes[0].sources = 1; user.processes[0].process.image_path.clear();
		std::vector<WinObj> merged{ user };
		MergeCollectorObjects(merged, decoded.groups[0]);
		Check(merged.size() == 2 && merged[0].discovery_sources == 3 && merged[1].discovery_sources == 2, "Discovery union incorrect");
		Check(merged[0].access == 1 && merged[1].access == 0, "Administrator metadata changed user access");
		Check(merged[0].processes.size() == 1 && merged[0].processes[0].sources == 3, "Process provenance merge incorrect");
		MergeCollectorObjects(merged, decoded.groups[0]);
		Check(merged.size() == 2 && merged[0].processes.size() == 1, "Merge not idempotent");
		WinObj rpc1{ RPC, L"ncalrpc:[shared]" }; rpc1.rpc = RpcEndpointInfo{ L"one", 1, 0, L"object" };
		WinObj rpc2 = rpc1; rpc2.rpc->interface_id = L"two";
		CollectedGroup rpc; rpc.type = RPC; rpc.discovered = true; rpc.objects = { rpc2 };
		std::vector<WinObj> endpoints{ rpc1 }; MergeCollectorObjects(endpoints, rpc);
		Check(endpoints.size() == 2, "RPC interfaces sharing a binding collapsed");
		for (size_t size = 0; size < encoded.size(); ++size) {
			std::vector<unsigned char> truncated(encoded.begin(), encoded.begin() + size);
			Check(!DecodeCollectorData(truncated, decoded), "Truncated IPC message accepted");
		}
		auto bad = encoded; bad[0] ^= 0xff; Check(!DecodeCollectorData(bad, decoded), "Wrong protocol accepted");
		bad = encoded; bad.push_back(0); Check(!DecodeCollectorData(bad, decoded), "Trailing payload accepted");
		Check(decoded.groups[0].objects.size() == 2, "Failed decoding changed previous metadata");
		std::cout << "Collector protocol, provenance, and access isolation tests passed\n"; return 0;
	}
	catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
