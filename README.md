# win-obj-enum

Discovers Windows objects through the existing `IWinObjEnumerator` and
`EnumerationManager` interfaces. Discovery alone does not open matching objects.
Process enrichment associates existing handles and local endpoint/session evidence
with process names and PIDs. Creator attribution remains unknown.
Optional access probes report explicit handle rights, connection outcomes, and
supported query operations separately.

## Repository layout

```text
src/
  cli/          Command-line entry point
  core/         Object types and enumeration manager
  interfaces/   Enumerator and access-test interfaces
  enumerators/  Concrete enumerators and aggregate header
  access/       Access policies, native probes, token snapshots, and workers
  native/       Native Windows declarations and shared directory scanner
  collection/   Elevated metadata collector, bounded IPC, and provenance merge
  process/      Process snapshots, handle correlation, and bounded query worker
  report/       Offline HTML and compact LLM file exporters
  dump/         Separate dump client, kernel driver, shared protocol, and PE rebuilder
tests/          Discovery smoke test and runner
docs/           Access-testing behavior and coverage
build/          Generated binaries, intermediate files, and test outputs
```

The Visual Studio solution and project remain at the repository root. Project
headers use paths relative to `src`, which is the compiler include directory.
Visual Studio filters mirror the source directories.

## Dump loaded driver images

The solution also contains `win-obj-dump.exe` and `win-obj-dump-driver.sys` (x64).
They capture loaded kernel image bytes and reconstruct an IDA-oriented PE with
imports, disk section layout, and loaded/preferred image-base handling. Original
image files are not used as the byte source. A raw memory capture and JSON evidence
manifest accompany the reconstructed file.
An accompanying `.ida.py` helper restores analysis of runtime-patched import/CFG
calls after the PE and its matching PDB have loaded in IDA.

```powershell
.\win-obj-dump.exe dump PEAuth.sys --out PEAuth.memory.sys
.\win-obj-dump.exe dump '\Device\PEAuth' --out PEAuth.device.sys
```

Requires the WDK to build the driver, an accepted driver signature to load it, and
an elevated administrator token. The build does not load the driver or change
signing policy. See [driver dumping](docs/driver-dumping.md) for build/deployment,
device-stack semantics, missing-page handling, reconstruction limits, and tests.

## Build and run

Open `win-obj-enum.slnx` in Visual Studio with the v145 C++ toolset and Windows SDK,
or run from a Visual Studio Developer Command Prompt:

```bat
msbuild win-obj-enum.vcxproj /p:Configuration=Release /p:Platform=x64
build\bin\x64\Release\win-obj-enum.exe all
build\bin\x64\Release\win-obj-enum.exe event
```

Options: `all`, `device`, `alpc`, `rpc`, `flt`, `event`, `job`, `mutant`,
`namedpipe`, `semaphore`, `sessions`, `timer`.

Results go to stdout; discovery issues go to stderr with the native error code
and its domain. Exit status is 0 for a completed scan and 1 for invalid arguments,
failed scans, or partial scans. Partial scans still print discovered objects.
Redirected CLI output uses UTF-8.

## Save reports

```bat
build\bin\x64\Release\win-obj-enum.exe all --html objects.html --llm objects.llm.txt
build\bin\x64\Release\win-obj-enum.exe event --access --html access.html --llm access.llm.txt
```

Both exports use the same scan and work with discovery alone or access testing.
The HTML report opens locally in a modern browser and provides text search,
type/outcome/right filters, a process name or exact PID filter, sortable columns,
pagination, and detailed per-object observations. It is self-contained and makes no network requests.

The LLM format stores rights and repeated outcome profiles once, then references
them from object rows. It preserves actual masks, errors, skipped/unsupported
checks, token context, and discovery failures, while omitting per-attempt timing
and repeated prose. See [report formats](docs/report-formats.md) for the schema.

Process associations are enabled by default. `--no-processes` skips collection;
`--process-budget <ms>` changes the 30-second handle traversal budget. The report
distinguishes handle holders, pipe servers, TCP listeners, device users, and session
members, and shows partial process coverage separately. These observations cannot
establish who originally created an object. See [process associations](docs/process-associations.md).

Paths may contain spaces and Unicode; quote them as needed. Parent directories
must exist. Existing report files are replaced only after the new file has been
written successfully. Partial scans still produce reports and retain exit status
1. When exporting, the normal console shows summaries instead of individual rows;
`--json` retains the existing JSON Lines stream and can be combined with exports.

## Administrator-assisted collection

Start from a normal user terminal. Elevate only the collector with:

```bat
build\bin\x64\Release\win-obj-enum.exe all --access --admin-collect --html objects.html --llm objects.llm.txt
```

Access tests still run under the original user primary token with no thread
impersonation or privilege changes. `--admin-debug` additionally enables
`SeDebugPrivilege` in the elevated collector only. Reports distinguish discovery
and metadata sources from verified user access. UAC cancellation keeps user
results and reports the missing administrator coverage. See
[administrator collection](docs/administrator-collection.md) for boundaries and tests.

## Access testing

```bat
build\bin\x64\Release\win-obj-enum.exe event --access --match MyEvent
build\bin\x64\Release\win-obj-enum.exe device --access --devices --match Null
build\bin\x64\Release\win-obj-enum.exe namedpipe --access --connect --match MyPipe
build\bin\x64\Release\win-obj-enum.exe all --access --json > access.jsonl
```

Explicit rights are always probed independently, before `MAXIMUM_ALLOWED`.
The maximum-access result is advisory and never contributes to the explicit
summary. A driver returning failure or zero rights for that request cannot
suppress valid read, query, or other specific requests. `--no-maximum` omits it.

`--devices` enables device opens. `--connect` enables pipe client opens, ALPC and
filter connections, and RPC management queries. `--timeout <ms>` sets the worker
response deadline per attempt (1–60000, default 2000). `--match <text>` filters
discovered names by a case-sensitive substring. `--json` emits JSON Lines and
requires `--access`; probe options also require `--access`.

See [access-testing details](docs/access-testing.md) for rights coverage, evidence
semantics, token handling, and limitations. A denial is a completed access result;
timeouts, busy/unavailable objects, and probe errors produce exit status 1, as do
partial discovery results. Explicitly skipped or unsupported capabilities are
listed in the report and do not independently change the exit code.

## Discovery sources

| Type | Source and returned identity |
| --- | --- |
| DEVICE | Object Manager `Device` entries; full NT object path |
| ALPC | Object Manager `ALPC Port` and legacy `Port` entries; full NT object path |
| FLT | Object Manager `FilterConnectionPort` and `FilterCommunicationPort` entries; full NT object path |
| EVENT, JOB, MUTANT, SEMAPHORE, TIMER | Corresponding Object Manager types; full NT object path |
| NAMEDPIPE | Local `\\.\pipe\*` directory; Win32 pipe path, one entry per name |
| RPC | Local RPC endpoint mapper; string binding plus interface UUID/version and object UUID |
| SESSIONS | Local WTS desktop/RDP sessions; descriptive name plus numeric session ID |

The Object Manager scanner walks directories starting at `\`, rather than just
hard-coded locations such as `\Device` or `\RPC Control`. It also visits known
`BaseNamedObjects` and `AppContainerNamedObjects` paths for the current session
and session IDs listed under `\Sessions`: these can be readable even when their
parent directory cannot be listed. It does not follow symbolic links. Matching
objects are never opened; only directories are opened for enumeration.

`FLT` means communication ports, not loaded minifilter drivers. `SESSIONS` means
desktop/RDP sessions, not LSA authentication logon sessions or Object Manager
directories. Those directories are traversed by the shared scanner instead.

## Result contract

- An engaged optional containing an empty vector means no matching objects were
  found. `std::nullopt` means the discovery source could not be enumerated.
- `GetIssues()` describes failures from the most recent call. Results accompanied
  by issues are partial, including when the result vector is empty. The manager
  exposes the same information through `GetIssues(type)`.
- Every discovered object starts with `status == UNTESTED` and `access == 0`.
  Zero is a placeholder, not evidence of denied access. Future access probes can
  use the full name, `rpc` metadata, or `session_id` without rediscovering identity.
- Results are sorted and deduplicated. RPC deduplication includes interface and
  object UUIDs and interface versions, so interfaces sharing a binding survive.
- Each call obtains a fresh snapshot. Enumerators hold their most recent issues,
  so concurrent calls on the same instance require external synchronization.

## Coverage limits

Discovery is limited by the calling token and the visibility of each namespace.
Inaccessible directories are reported and do not prevent other directories from
being scanned. Privileges are not enabled or changed. Missing optional session
directories are ignored, while denied access to them is reported.

This is discovery of named, visible objects, not a kernel-wide inventory of every
allocation. Unnamed objects, private namespaces that cannot be listed, objects
hidden behind inaccessible ancestors, and unregistered RPC interfaces cannot be
guaranteed by these sources. Device results are native device objects, not a PnP
device/interface inventory or a list of DOS symbolic-link aliases. RPC endpoint
map entries may be stale and are not proof that a server is reachable. No target
endpoint is contacted to validate a result. Objects can appear or disappear
during a scan; scans are not atomic.

## Verification

From an **x64 Visual Studio Developer Command Prompt**, run:

```bat
tests\run.cmd
```

Application outputs are in `build/bin/<Platform>/<Configuration>`, intermediate
files in `build/obj/<Platform>/<Configuration>`, and test outputs in
`build/tests/x64`.

The smoke test creates and cleans up its own local/global named objects and pipe
instances. It checks Unicode names, nested directories, buffer growth for long
native names, per-type discovery, deduplication, fresh scans, empty results,
session IDs, RPC metadata, manager dispatch, and handle counts across repeated
scans. It requires permission to create the fixtures and query WTS and the local
endpoint mapper; permission-dependent directory results may remain partial.

The runner also executes `tests/access/access-smoke.cpp`. These tests cover a
simulated driver rejecting or stripping maximum access, controlled ACLs, individual
versus combined grants, worker recovery after timeouts, effective-token snapshots,
pipe contention, native device opens, and owned ALPC/RPC servers. The filter-port
test verifies a missing port; a successful live minifilter connection requires an
appropriate driver and is not exercised by the automated suite. The token fixture
requires an environment that permits creating restricted tokens.

Report tests require Node.js in addition to the C++ tools. The runner validates
UTF-8 exports, script-safe data embedding, failed-write preservation, compact
profile round trips, and the report's JavaScript sorting/filtering behavior using
a dependency-free DOM test double. Fixtures are saved in `build/tests/reports`.

API references: [NtQueryDirectoryObject](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntquerydirectoryobject),
[RPC endpoint inquiries](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcmgmtepeltinqbegin),
[WTSEnumerateSessionsW](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsw),
[FindFirstFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew).
