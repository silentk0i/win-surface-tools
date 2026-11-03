#include <algorithm>
#include <cwctype>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include "collection/collector-data.h"

namespace {
	using namespace win_obj;
	constexpr size_t max_bytes = 128 * 1024 * 1024;
	struct Writer {
		std::vector<unsigned char> bytes;
		template<class T> void Number(T value) {
			static_assert(std::is_integral_v<T>);
			if (bytes.size() > max_bytes - sizeof(value)) throw std::runtime_error("Collector response too large");
			auto data = reinterpret_cast<const unsigned char*>(&value);
			bytes.insert(bytes.end(), data, data + sizeof(value));
		}
		void Flag(bool value) { Number<u8>(value ? 1 : 0); }
		void Text(const std::wstring& value) {
			if (value.size() > 32768 || value.find(L'\0') != std::wstring::npos) throw std::runtime_error("Invalid collector string");
			Number<u32>(static_cast<u32>(value.size()));
			for (auto character : value) Number<u16>(character);
		}
		template<class T, class F> void List(const std::vector<T>& values, F function) {
			if (values.size() > 1000000) throw std::runtime_error("Collector list too large");
			Number<u32>(static_cast<u32>(values.size()));
			for (const auto& value : values) function(value);
		}
		void Strings(const std::vector<std::wstring>& values) { List(values, [&](const auto& value) { Text(value); }); }
	};
	struct Reader {
		const std::vector<unsigned char>& bytes;
		size_t offset = 0;
		template<class T> T Number() {
			if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) throw std::runtime_error("Truncated collector response");
			T value; memcpy(&value, bytes.data() + offset, sizeof(value)); offset += sizeof(value); return value;
		}
		bool Flag() { auto value = Number<u8>(); if (value > 1) throw std::runtime_error("Invalid flag"); return value != 0; }
		std::wstring Text() {
			auto length = Number<u32>();
			if (length > 32768 || length > (bytes.size() - offset) / 2) throw std::runtime_error("Invalid string length");
			std::wstring value;
			value.reserve(length);
			for (u32 i = 0; i < length; ++i) { auto character = Number<u16>(); if (!character) throw std::runtime_error("Embedded null"); value += static_cast<wchar_t>(character); }
			return value;
		}
		u32 Count(u32 limit = 1000000) { auto n = Number<u32>(); if (n > limit || n > bytes.size() - offset) throw std::runtime_error("Invalid count"); return n; }
		std::vector<std::wstring> Strings() { std::vector<std::wstring> values; auto n = Count(65536); for (u32 i = 0; i < n; ++i) values.push_back(Text()); return values; }
	};

	void WriteToken(Writer& w, const AccessTokenInfo& t) {
		w.Text(t.user_sid); w.Number(t.integrity_level); w.Flag(t.elevated); w.Flag(t.restricted); w.Flag(t.app_container); w.Flag(t.impersonating);
		w.Strings(t.enabled_privileges); w.Number(t.error); w.Text(t.error_operation); w.Text(t.fingerprint); w.Text(t.authentication_id); w.Text(t.token_id); w.Text(t.modified_id);
		w.Number(t.session_id); w.Number(t.elevation_type); w.Strings(t.groups); w.Strings(t.privilege_states); w.Strings(t.restricted_sids); w.Strings(t.capabilities);
	}
	AccessTokenInfo ReadToken(Reader& r) {
		AccessTokenInfo t;
		t.user_sid = r.Text(); t.integrity_level = r.Number<u32>(); t.elevated = r.Flag(); t.restricted = r.Flag(); t.app_container = r.Flag(); t.impersonating = r.Flag();
		t.enabled_privileges = r.Strings(); t.error = r.Number<u32>(); t.error_operation = r.Text(); t.fingerprint = r.Text(); t.authentication_id = r.Text(); t.token_id = r.Text(); t.modified_id = r.Text();
		t.session_id = r.Number<u32>(); t.elevation_type = r.Number<u32>(); t.groups = r.Strings(); t.privilege_states = r.Strings(); t.restricted_sids = r.Strings(); t.capabilities = r.Strings();
		return t;
	}
	void WriteCoverage(Writer& w, const ProcessScanInfo& p) {
		w.Flag(p.requested); w.Flag(p.complete); w.Flag(p.budget_exhausted); w.Number(p.timestamp); w.Number(p.handles); w.Number(p.queried);
		w.Number(p.failed); w.Number(p.timeouts); w.Number(p.inaccessible_processes); w.Number(p.tcp_error); w.Number(p.error); w.Text(p.error_operation);
	}
	ProcessScanInfo ReadCoverage(Reader& r) {
		ProcessScanInfo p;
		p.requested = r.Flag(); p.complete = r.Flag(); p.budget_exhausted = r.Flag(); p.timestamp = r.Number<u64>(); p.handles = r.Number<u64>(); p.queried = r.Number<u64>();
		p.failed = r.Number<u64>(); p.timeouts = r.Number<u64>(); p.inaccessible_processes = r.Number<u64>(); p.tcp_error = r.Number<u32>(); p.error = r.Number<u32>(); p.error_operation = r.Text();
		return p;
	}
	std::wstring Fold(std::wstring value) { std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); }); return value; }
	auto Identity(const WinObj& object) {
		return std::tuple{ object.type, Fold(object.name), object.native_type, object.session_id,
			object.rpc ? Fold(object.rpc->interface_id) : L"", object.rpc ? object.rpc->major_version : 0,
			object.rpc ? object.rpc->minor_version : 0, object.rpc ? Fold(object.rpc->object_id) : L"" };
	}
}

namespace win_obj {
	std::vector<unsigned char> EncodeCollectorData(const CollectorData& data) {
		Writer w;
		w.Number<u32>(0x574f4331); w.Number(data.error); w.Text(data.error_operation); w.Number(data.started); w.Number(data.finished);
		w.Flag(data.debug_requested); w.Flag(data.debug_enabled); w.Number(data.debug_error); WriteToken(w, data.token); WriteCoverage(w, data.processes);
		w.List(data.groups, [&](const CollectedGroup& group) {
			w.Number<u32>(group.type); w.Flag(group.discovered);
			w.List(group.issues, [&](const EnumerationIssue& issue) { w.Text(issue.name); w.Number(issue.error); w.Number<u32>(static_cast<u32>(issue.type)); });
			w.List(group.objects, [&](const WinObj& object) {
				w.Text(object.name); w.Text(object.native_type); w.Flag(object.session_id.has_value()); if (object.session_id) w.Number(*object.session_id);
				w.Flag(object.rpc.has_value()); if (object.rpc) { w.Text(object.rpc->interface_id); w.Number(object.rpc->major_version); w.Number(object.rpc->minor_version); w.Text(object.rpc->object_id); }
				w.Text(object.process_status);
				w.List(object.processes, [&](const ProcessAssociation& a) {
					w.Number(a.process.pid); w.Text(a.process.name); w.Number(a.process.created); w.Number(a.process.session); w.Text(a.process.image_path); w.Text(a.relation);
				});
			});
		});
		return std::move(w.bytes);
	}

	bool DecodeCollectorData(const std::vector<unsigned char>& bytes, CollectorData& data) {
		if (bytes.size() > max_bytes) return false;
		try {
			Reader r{ bytes };
			if (r.Number<u32>() != 0x574f4331) return false;
			CollectorData result; result.requested = result.received = true;
			result.error = r.Number<u32>(); result.error_operation = r.Text(); result.started = r.Number<u64>(); result.finished = r.Number<u64>();
			result.debug_requested = r.Flag(); result.debug_enabled = r.Flag(); result.debug_error = r.Number<u32>(); result.token = ReadToken(r); result.processes = ReadCoverage(r);
			auto count = r.Count(TIMER + 1); std::set<u32> types;
			for (u32 i = 0; i < count; ++i) {
				auto type = r.Number<u32>(); if (type > TIMER || !types.insert(type).second) return false;
				CollectedGroup group; group.type = static_cast<WinObjType>(type); group.discovered = r.Flag();
				auto issues = r.Count();
				for (u32 j = 0; j < issues; ++j) {
					EnumerationIssue issue; issue.name = r.Text(); issue.error = r.Number<u32>(); auto domain = r.Number<u32>();
					if (domain > static_cast<u32>(EnumerationErrorType::RPC_ERROR)) return false;
					issue.type = static_cast<EnumerationErrorType>(domain); group.issues.push_back(std::move(issue));
				}
				auto objects = r.Count();
				if (objects && !group.discovered) return false;
				for (u32 j = 0; j < objects; ++j) {
					WinObj object{ static_cast<u8>(type), r.Text() }; object.native_type = r.Text(); object.discovery_sources = 2;
					if (r.Flag()) object.session_id = r.Number<u32>();
					if (r.Flag()) { RpcEndpointInfo rpc; rpc.interface_id = r.Text(); rpc.major_version = r.Number<u16>(); rpc.minor_version = r.Number<u16>(); rpc.object_id = r.Text(); object.rpc = std::move(rpc); }
					object.process_status = r.Text();
					auto associations = r.Count(65536);
					for (u32 k = 0; k < associations; ++k) {
						ProcessAssociation a; a.sources = 2; a.process.pid = r.Number<u32>(); a.process.name = r.Text(); a.process.created = r.Number<u64>();
						a.process.session = r.Number<u32>(); a.process.image_path = r.Text(); a.relation = r.Text(); object.processes.push_back(std::move(a));
					}
					group.objects.push_back(std::move(object));
				}
				result.groups.push_back(std::move(group));
			}
			if (r.offset != bytes.size()) return false;
			data = std::move(result); return true;
		}
		catch (const std::exception&) { return false; }
	}

	void MergeCollectorObjects(std::vector<WinObj>& objects, const CollectedGroup& elevated) {
		std::map<decltype(Identity(WinObj{})), size_t> indices;
		for (size_t i = 0; i < objects.size(); ++i) indices.emplace(Identity(objects[i]), i);
		for (const auto& extra : elevated.objects) {
			auto [entry, inserted] = indices.emplace(Identity(extra), objects.size());
			if (inserted) {
				auto copy = extra; copy.discovery_sources = 2; copy.access = 0; copy.status = UNTESTED;
				for (auto& a : copy.processes) a.sources = 2;
				objects.push_back(std::move(copy)); continue;
			}
			auto& object = objects[entry->second]; object.discovery_sources |= 2;
			for (const auto& a : extra.processes) {
				auto found = std::find_if(object.processes.begin(), object.processes.end(), [&](const auto& b) { return a.process.pid == b.process.pid && a.process.created == b.process.created && a.relation == b.relation; });
				if (found == object.processes.end()) { auto copy = a; copy.sources = 2; object.processes.push_back(std::move(copy)); }
				else { found->sources |= 2; if (!a.process.image_path.empty()) found->process.image_path = a.process.image_path; }
			}
			if (!object.processes.empty()) object.process_status = L"observed";
		}
	}
}
