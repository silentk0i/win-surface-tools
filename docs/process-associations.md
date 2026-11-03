# Process associations

Process collection is enabled by default, with or without `--access`:

```bat
win-obj-enum.exe all --html objects.html --llm objects.llm.txt
win-obj-enum.exe event --process-budget 60000 --html events.html
win-obj-enum.exe all --no-processes
```

The HTML **Process name or PID** filter accepts a case-insensitive name fragment
or an exact decimal PID. It searches every association across the report, combines
with the other filters, and resets pagination. The associated processes column is
sortable; Inspect shows the same evidence. Values render as text, never markup.

## Meaning of the associations

Windows does not generally retain a queryable creator PID for an existing named
object. Processes can transfer or inherit handles and exit while another process
keeps an object alive. The security owner SID is not a creator process. This
feature records observed relationships and leaves `creator` null.

| Relationship | Evidence |
| --- | --- |
| `handle-holder` | A process holds a handle matching the native type and name. Covers synchronization objects, jobs, ALPC/legacy ports, filter ports, pipes, and direct device handles when available. |
| `pipe-server` | `GetNamedPipeServerProcessId` succeeded on an existing pipe handle; server creation time matched the process snapshot. |
| `device-path-handle` | A File handle matches the device path or a descendant. Identifies a device user, not its driver/creator. Matching uses the longest component boundary. |
| `rpc-endpoint-holder` | A local RPC pipe/ALPC endpoint matches a named handle. Transport evidence does not prove registration of a particular interface UUID. |
| `tcp-listener` | A local IPv4/IPv6 listener matches the RPC endpoint address and port. Wildcard listeners match local adapter addresses. This does not prove interface registration. |
| `session-member` | A process belongs to the session according to the process snapshot. |

Multiple processes and relationships are retained. Repeated handles do not repeat
the same relationship. PIDs are paired with creation FILETIMEs to distinguish
reused PIDs; times are strings in HTML/JSON to preserve integer precision.

## Collection and limits

The CLI captures process and extended-handle snapshots before discovery/access
probes. It duplicates existing handles under the collector's primary token, queries
native type/name, and closes the duplicates. It does not request new object access
rights or connect to devices, pipes, or endpoints. Duplication temporarily adds an
object reference. No user privileges are changed; no driver is needed. An optional administrator
collector can enable its own debug privilege only with `--admin-debug`.

Potentially blocking handle queries run in a hidden worker with an explicit
inheritance list, a verified primary context, and a kill-on-close job. Each query has a
100 ms deadline. A timed-out worker is terminated; later queries restart it.
The handle traversal budget defaults to 30,000 ms; `--process-budget` accepts
1–300,000 ms. Snapshot/TCP APIs, worker startup (up to two seconds per restart),
and cleanup are additional to that budget. `--no-processes` disables enrichment.

Protected processes, denied duplication, process exit, closed/reused handles,
timeouts, or exhausted budgets can leave associations unknown. Native layouts are
validated, but these APIs are not a stable public ABI. Remote process creation
times are verified before using handles or TCP listener identities. Snapshots are
not atomic: named objects can disappear or be recreated between collection and
discovery. These observations are not a historical audit or permanent ownership.

Kernel-only objects, unnamed handles, and ports without accessible process handles
can have no association. Job membership and arbitrary kernel references are not
collected. Remote RPC bindings, unknown hostnames, scoped IPv6 binding strings,
and unsupported transports remain unresolved. No DNS lookup or remote connection
is made. Numeric remote TCP bindings cannot match a local port alone.

Process coverage is independent of discovery/access completion and does not alter
existing CLI exit-status rules. HTML exposes failed queries, inaccessible
processes, timeouts, budget exhaustion, and TCP/snapshot errors. Empty always
means unknown, never "no process". `none-observed` means traversal finished without
a match; `unknown-partial-scan` means incomplete coverage. Unsupported bindings
and disabled collection have separate statuses. Even complete traversal cannot
establish a creator.

JSONL adds `process_scan` coverage and associations on access records. HTML/LLM
deduplicate identities in shared dictionaries. See [report formats](report-formats.md).

References: [DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle),
[pipe server PID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid),
[TCP tables](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable),
[adapter addresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses),
[native system information](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation),
[native object layouts](https://github.com/winsiderss/phnt/blob/master/ntobapi.h).

With `--admin-collect`, user and administrator collection have independent coverage
records. Each process association records user, administrator, or both sources.
Process image paths resolved by the elevated collector are labeled accordingly.
Scanner and collector PIDs are excluded from their association snapshots; probe
workers start afterward. See [administrator collection](administrator-collection.md).
