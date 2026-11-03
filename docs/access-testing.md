# Access testing

Access probes are separate from enumeration. `AccessManager` dispatches through
`IWinObjTest`, with a shared `ObjectAccessTest` rights catalog for all eleven
`WinObjType` values. `IAccessProbe` separates policy from execution and allows
deterministic driver-behavior regression tests.

## Explicit rights are authoritative

Each applicable specific and standard right gets its own open attempt, followed
by generic requests, a combined full-access request, and a zero-access baseline.
`ACCESS_SYSTEM_SECURITY` is requested separately. Privileges are never enabled.
No failed request suppresses subsequent requests.

`MAXIMUM_ALLOWED` runs last, unless disabled with `--no-maximum`. Drivers can reject
this request or return less access than a specific request would obtain. Its
success, failure, and returned mask are preserved as a separate observation. They
never determine which specific probes run or populate `observed_explicit`.

Successful opens are inspected with `NtQueryObject(ObjectBasicInformation)`.
For specific masks, a returned mask lacking requested bits is labeled `reduced`.
Generic requests expose the raw granted mask without guessing the driver's
generic mapping. Successful zero-access opens do not establish useful access.

`observed_explicit` is the union of actual handle masks observed across explicit
opens, including generic/combined requests. It is not proof that the union can be
obtained on one handle. Individual observations remain authoritative. Connection
handles and maximum-access requests are excluded from that union. `WinObj` remains
the discovery record; its legacy status/access fields are not overwritten.

## Coverage

| Object | Implemented checks | Limits |
| --- | --- | --- |
| Event | Native query/modify bits, standard rights, generic/combined requests | Does not signal, reset, pulse, or wait on the target |
| Mutant | Native query bit, standard rights, generic/combined requests | Does not acquire or release the target |
| Semaphore | Native query/modify bits and other handle rights | Does not alter the count |
| Timer | Native query/modify bits and other handle rights | Does not arm or cancel the timer |
| Job | Query, assign, set attributes, terminate, legacy security, impersonate, other handle rights | Version-dependent bits can be rejected; no job operation is executed |
| Device | Explicit file read/write/data/EA/attribute/execute/append masks and other handle rights | Requires `--devices`; no IOCTL, data read, or data write |
| Named pipe | Client read/write/attribute/EA masks and other handle rights | Requires `--connect`; server-instance creation is explicitly unsupported |
| ALPC | Synchronous connection handshake and returned client-handle information | Requires `--connect`; legacy LPC ports unsupported; no application payload |
| Filter port | `FilterConnectCommunicationPort` with empty context, client-handle information | Requires `--connect`; only connection ports; custom contexts require an adapter |
| RPC | Authenticated management listening query | Requires `--connect`; not an interface or procedure authorization test |
| Session | `WTSUserName` query for the numeric session ID | Other session rights are individually listed as unsupported; no session mutations |

Device/pipe handles describe file-object grants, not permission to execute every
driver operation. A client pipe mask containing `FILE_CREATE_PIPE_INSTANCE` does
not validate the ability to create a server instance. Connection handle masks
belong to the client endpoint, not the discovered server object.

RPC queries use the current token, Windows authentication, packet privacy, and
identification impersonation level. Results apply to that authentication profile
and the management query only. Anonymous access and other authentication profiles
are not inferred. RPC interfaces/procedures, IOCTLs, and protocol-specific ALPC or
filter messages require dedicated adapters. Security-descriptor assessment is not
implemented in this version; unavailable server-object masks remain unsupported.

## Execution and identity

The scanner runs under the original unelevated user's primary token. Starting
with a thread impersonation token or an elevated primary token is refused. Use
`--admin-collect` to elevate only inventory collection, as described in
[administrator collection](administrator-collection.md).

`AccessManager` reads the primary token with `TOKEN_QUERY` only. It never creates
an impersonation token or enables/disables user privileges. The baseline records
SID, logon ID, session, integrity, elevation, group attributes, restriction SIDs,
capabilities, and privilege states (including disabled privileges). A SHA-256
fingerprint compares these fields between parent and child. Unsupported optional
device-group queries are represented explicitly in that fingerprint; the hash
is a context consistency check, not a signature or a complete serialization of
all token claims.

Each object uses a hidden worker launched by the unelevated parent with
`CreateProcessW`. Only the required IPC handles are inherited; no token or target
object handles are passed. The worker runs with its primary token and verifies
that no thread token exists, its baseline attributes match, and its primary token
ID and modification ID remain unchanged. The latter catches token modifications
beyond the fields included in the fingerprint. Verification runs before and after
every attempt; the parent is checked too. Failure discards any open/grant evidence,
records `context_error`, and cannot contribute to the explicit-access union.
`context_verified=1` is set only after both checks succeed.

Probe attempts are serial. A parent-side response deadline and a kill-on-close job
bound stalled workers. After timeout/crash, the next explicit attempt starts a
fresh worker. Startup and cleanup add overhead beyond the response timeout;
termination cannot undo driver/server effects or guarantee immediate completion
of stuck kernel work.

Workers have their own PIDs and run in a job. Driver/server policies depending on
process identity, executable identity, or job membership may differ from another
application run by the same user. These are actual opens from the scanner's user
workers, not a claim about every application with the same account SID.

Opening a device, pipe, or port can invoke driver/server callbacks even without
application data; these probes have explicit CLI switches. Native ALPC and file
opens use identification-level security QoS. Object lifetimes and ACLs can change
between attempts, so a scan is not an atomic access snapshot.

## Results and verification

Every attempt records its method, requested mask, status, optional granted mask,
whether a handle was opened, raw error and domain, handle-query NTSTATUS, elapsed
time, and explanatory detail. Unknown granted masks are distinct from zero.
Denied, reduced, privilege-required, busy, unavailable, timeout, unsupported,
skipped, and probe errors are separate outcomes. Error status is not proof of
absence or lack of permission unless the API actually reports that condition.

JSON Lines includes a token record, one access record per object, discovery issues,
and type summaries. The numeric object type uses the existing `WinObjType` order;
method values follow `AccessMethod`. Access records preserve RPC interface/version
metadata and session IDs. Skipped/unsupported rows make incomplete coverage
visible even when the process exits successfully.

Run `tests\run.cmd` in an x64 Visual Studio Developer Command Prompt. The access
suite uses controlled ACLs and owned servers, plus an injected probe to simulate
failed, zero-grant, and overbroad maximum-access responses. It also checks that
successful individual requests do not imply a successful combined request,
timeouts do not suppress later probes, repeated workers release handles, and
thread impersonation is refused, and changes to a worker thread token or primary
privilege state invalidate the result without changing the parent token.

References: [NtOpenFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntopenfile),
[NtQueryObject](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject),
[filter connections](https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filterconnectcommunicationport),
[RPC management query](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcmgmtisserverlistening),
[native ALPC declarations](https://github.com/winsiderss/phnt/blob/master/ntlpcapi.h).
