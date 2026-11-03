# Administrator-assisted collection

Run the scanner from the intended user's unelevated terminal:

```bat
win-obj-enum.exe all --access --admin-collect --html objects.html --llm objects.llm.txt
win-obj-enum.exe event --access --admin-collect --admin-debug --html events.html
```

`--admin-collect` requests UAC elevation for a separate instance of the executable
in its internal collector mode. The original scanner stays unelevated and owns
all access workers and report writes. Starting the normal scanner elevated or
with thread impersonation is refused. The tool does not guess a desktop user,
borrow another process's token, manufacture a filtered administrator token, or
change the user token to reconstruct a different identity.

`--admin-debug` requires `--admin-collect`. It enables only `SeDebugPrivilege`, only
in the collector. The collector records whether activation succeeded and its
resulting token/privileges. User privileges, including privileges already enabled
at launch, remain unchanged. No services or drivers are installed or loaded.

## What is collected

Both contexts enumerate the selected object types. The inventories are merged by
native identity, including RPC interface/version/object UUID and session identity
where applicable. Administrator discovery can add objects in directories the user
could not list. Each object records whether user collection, administrator
collection, or both discovered it.

The elevated collector can inspect additional process handles and resolve process
image paths. Each process association carries independent source bits; finding a
name through administrator collection does not change the user access result.
The collector excludes its own PID and the original scanner PID. User process
snapshots are captured before access workers start. The collector completes and exits before user access tests begin; no handles to tested objects
cross into the user workers. Normal discovery and collector discovery are separate
observations, so objects can disappear or change between them.

The collector performs inventory/metadata operations only. It does not run access
probes, change target ACLs, claim a creator PID, execute arbitrary driver requests,
or infer driver ownership from the current handle holder. Kernel driver ownership,
security-descriptor analysis, historical creation tracing, and protocol-specific
operation coverage remain separate work. Elevation does not remove protected
process restrictions or guarantee that a driver name query will complete.

## Isolation and IPC

The normal parent launches the helper with `ShellExecuteExW` and `runas`. The
helper communicates over a random local named pipe created before elevation, with
an explicit DACL for the initiating user, administrators, and SYSTEM. Remote
clients are rejected. The parent validates the connecting PID against the process
handle returned by elevation. The helper validates the server PID, parent creation
time, and executable path. Its pipe connection uses anonymous security QoS so the
unelevated server cannot impersonate the administrator.

The request contains only selected types, process collection options, and the
explicit debug-privilege switch. The response is a versioned binary metadata
schema with bounded strings/counts and a 128 MiB limit. It has no access-grant or
target-handle fields. Malformed, truncated, out-of-scope, and trailing data are
rejected before merging. UAC cancellation, transport failures, or validation
failures retain the user scan and produce explicit administrator coverage errors.

IPC deadlines and a helper watchdog bound collection after UAC completes. The
watchdog terminates the helper if its original parent exits or its total deadline
expires, or its IPC connection closes. If the parent cannot confirm helper exit
after an error, it skips user access probes and explicitly reports the reason.
Individual handle-name queries retain their separate worker deadlines.
Closing a worker cannot undo driver callbacks or promise instantaneous cleanup of
stuck kernel work. The elevation prompt itself waits for Windows/user consent.

All user access attempts run in primary-token child processes created by the
unelevated scanner. Read-only token snapshots and before/after verification detect
thread impersonation, changed identity/privilege/group states, primary-token
replacement, and changes to the token modification ID. Context failures invalidate
open/grant evidence rather than being classified as target access denied. See
[access testing](access-testing.md) for fingerprint fields and worker limitations.

## Reports

HTML adds discovery source, process evidence source, and user access verification
filters, a discovery column, and independent user/administrator coverage. Process
and evidence-source filters match the same association; outcome/right/context
filters match the same attempt. Inspect shows process paths and per-attempt context
verification. The collector's identity is displayed separately from the user.

JSONL/LLM preserve the same provenance. No administrator metadata changes explicit
user access masks or `MAXIMUM_ALLOWED` behavior. Denials remain valid denials even
when administrator collection resolves the object's name. Unsupported operations,
timeouts, disappeared objects, and incomplete metadata remain distinct.

Exit status 1 covers failed requested administrator collection, failed requested
debug activation, invalid user context, and existing discovery/access failures.
Process association coverage still has its own partial-status fields; successful
execution does not imply universal object attribution.

## Validation

`tests\run.cmd` tests primary-token execution, refusal of impersonation, detection
of privilege/context changes, malformed collector messages, metadata-only merging,
and report filtering/provenance. It requires no elevation.

Run `tests\collection\run-admin-integration.cmd` from an **unelevated** x64
Visual Studio Developer Command Prompt for the live UAC test. It creates a bounded
administrator fixture host with a protected directory and event. The test proves
that administrator collection finds the event, user discovery cannot list it,
and the original user's independent query open is still denied with its primary
context verified. The host releases its fixtures on completion, parent exit, or
timeout. This test is deliberately separate from the unattended suite.

References: [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
[ShellExecuteExW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw),
[DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle),
[process access restrictions](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
