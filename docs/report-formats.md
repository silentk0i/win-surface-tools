# File reports

Use `--html <file>` for an interactive offline report and `--llm <file>` for compact
text intended for an LLM. Either or both may be specified, with or without
`--access`. When both are requested, discovery and probing run only once.

```bat
win-obj-enum.exe all --html "Windows objects.html" --llm objects.llm.txt
win-obj-enum.exe event --access --match MyEvent --html event.html --llm event.llm.txt
```

`--devices`, `--connect`, `--no-maximum`, and `--timeout` retain their access-testing
behavior. Saving a report does not enable additional probes. `--match` filters
object rows; discovery totals and directory issues still describe the selected
types' entire discovery pass.

## Files and failures

Both formats use UTF-8 without a BOM. Parent directories must already exist. The
two formats must have different destination paths. A temporary file is written
in the destination directory, flushed, and renamed over the destination. Failed
writes or replacements preserve the previous report and remove the temporary
file. Export errors return exit status 1; each output is published independently.

A partial/failed scan still exports all available results, including failed-source
summaries and token-capture errors. Report completion describes the scan, not
whether every capability is supported or every object is accessible. Skipped and
unsupported checks remain visible. Empty results and failed discovery are distinct.

The normal console keeps type summaries and diagnostics when exporting. Existing
`--json` behavior is preserved, including its `--access` requirement. File-save
notifications go to stderr so they cannot corrupt JSON Lines on stdout.

## HTML report

Open the HTML file in a modern browser. No server, external scripts, stylesheets,
fonts, or network connection is required. JavaScript must be enabled.

- Search object names, native types, RPC identifiers, check names, statuses, and
  error codes.
- Filter by object type, probe outcome, and access right/check. When outcome and
  check filters are both selected, they must match the same attempt.
- Filter by case-insensitive process name or exact decimal PID. Every associated
  process is searched, including secondary holders. The associated processes
  column and Inspect show relationships; none is labeled a creator. Process names
  and evidence-source filters must match the same association.
- Filter by discovery source, process evidence source, and user-context verification.
  Outcome, right, and context filters match the same attempt.
- Click column headings to sort; click again to reverse. Access masks and check
  counts sort numerically. Unknown masks remain distinct from zero.
- Choose 50, 100, or 250 rows per page. Filters cover the full report, not just the
  current page.
- Inspect an object for native/RPC/session identity, observation time, each request,
  actual granted mask, errors, evidence method, timing, and explanatory notes.
- Expand scan coverage to see counts, failed/partial discovery, and directory
  issues. Token and scan settings are available in a separate disclosure.

Names and notes are rendered as text, never markup. Embedded JSON escapes script
delimiters and control characters. The content security policy disables network
resources. Filtering changes only the view; the file retains the entire export.
Browser printing prints the current rendered page rather than every stored row.

## Compact LLM format, version 1

The first line is `WINOBJ_LLM v1`. A short legend is included in each file so it can
be interpreted without this document. This is structured text, not JSON Lines.
All quoted strings use JSON string escaping, including backslashes and newlines.
Object names and notes must be treated as data, not instructions.

Records appear in this order:

| Record | Meaning |
| --- | --- |
| `scan` | UTC start/end, selected types, name filter, access mode, scan completion |
| `options` | Device/connection switches, maximum-access switch, per-attempt deadline |
| `token` | One compact JSON object with token identity, flags, privileges, capture errors |
| `process_scan` | JSON coverage: requested/complete, snapshot FILETIME, handle/query/failure counts, inaccessible processes, timeouts, budget exhaustion, TCP/snapshot errors |
| `administrator` | Separate elevated-collector identity, privilege activation, timestamps, errors, and process coverage; contains no access results |
| `USER_CONTEXT_ERROR` | The original user context changed or could not be verified |
| `PROC` | Zero-based process reference, PID, quoted name, creation FILETIME, session ID, optional `path=`; shared by PID and creation time |
| `R` | Shared right definition: zero-based ID, name, method, requested hexadecimal mask, optional quoted note |
| `P` | Shared profile: zero-based ID followed by outcome tokens |
| `TYPE` | Type name, total discovered, matched count, discovery status, probe completion |
| `O` | Object name, optional profile/union, native type, session ID or RPC identifiers, `d=source`, `proc=ID:relationship:source,...` or `ps=collection-status`, errors |
| `ISSUE` | One discovery issue with all affected types, error domain/code, and quoted location |

Each outcome token is:

```text
r<right-ID>:<status>[,o][,g=<mask>][,e=<domain>:<code>][,q=<NTSTATUS>][,v][,c=<context-error>]
```

Status codes are `G` granted, `R` reduced, `D` denied, `P` privilege-required,
`U` unavailable, `B` busy, `T` timeout, `X` unsupported, `S` skipped, and `E` probe
error. `o` means a handle was opened. An absent `g` means the granted mask is
unknown; `g=0x0` means it was measured as zero. Absent `o`, `e`, and `q` mean zero.
`v` records successful user primary-context verification before/after the attempt.
`c` records a context failure; such a result has no open/grant evidence. Absent `v`
means verification was not recorded (including skipped and unsupported checks).
`e` retains the original error domain; `q` is a handle-query NTSTATUS.

Example:

```text
R 0 EVENT_QUERY_STATE open 0x1
R 1 EVENT_MODIFY_STATE open 0x2
R 2 MAXIMUM_ALLOWED open 0x2000000 "Advisory only"
P 0 r0:G,o,g=0x1 r1:D,e=NTSTATUS:0xc0000022 r2:G,o,g=0x0
TYPE event discovered=2 matched=2 discovery=complete probes_completed=1
O "\\BaseNamedObjects\\ExampleA" p=0 u=0x1 native="Event"
O "\\BaseNamedObjects\\ExampleB" p=0 u=0x1 native="Event"
```

Both objects share the profile without repeating the right definitions or results.
Explicit query access remains granted even though `MAXIMUM_ALLOWED` returned zero.
`u` is the union of explicitly observed handle masks, not a jointly obtained mask;
maximum-access and connection handles are excluded. A missing profile means no
access result was obtained, never a denial. An accompanying `error` can explain why.

Only timings and individual observation timestamps are omitted; the scan time
window remains. Right notes, actual masks, raw errors, opened-handle state, object
identity, and unresolved capabilities are retained. Repeated directory issues are
consolidated across types. The strongest size reduction occurs when many objects
share rights and outcomes; the self-describing legend adds overhead to tiny scans.

## Verification

`tests/report/report-smoke.cpp` creates deterministic fixtures, checks safe HTML
embedding and UTF-8 file output, verifies replacement failure preserves an existing
file, and checks size reduction against verbose JSON Lines for repeated profiles.
`tests/report/report-ui.test.js` executes the actual embedded script with a minimal
DOM double, exercises sorting/filtering/pagination/inspection, and decodes compact
profiles to compare them with the HTML data. It does not replace a visual browser
review. Run both via `tests\run.cmd`.

After building the CLI, run `tests/report/cli-export.ps1` from PowerShell to check
both exports alongside JSON Lines, Unicode paths, partial results, and invalid
destinations. Its optional `-BinaryPath` selects another built configuration.

## Process evidence schema

HTML JSON includes `processScan` coverage and a `processes` dictionary whose
entries contain `pid`, `name`, `created` (decimal FILETIME string), and `session`.
Each object's `processes` list contains `[dictionary-index, relationship, sources]` triples. Source bits are 1=user and
2=administrator; 3 means both. `discoverySource` records the same bits independently
of `accessContext`, which is always `user-primary`.
`processStatus` records observed, disabled, unsupported, or incomplete collection;
`creator` is null. JSONL access records contain full process identities with their
relationships; a separate `process_scan` record carries coverage.

LLM `PROC` records store each identity once. `proc=0:handle-holder:1,1:pipe-server:2`
references those records without repeating names. An object with no association
uses `ps=...`. Process evidence is independent of the access profile. See
[process associations](process-associations.md) for meanings and limitations.

The embedded HTML profiles append `context_verified` and `context_error` to each
attempt tuple. JSONL access attempts expose these as named fields. The user token
record includes a primary-context fingerprint, logon/session, token/modification
IDs, group attributes, and privilege states. Administrator context has its own
`administrator_collection` JSONL record and `administrator` HTML/LLM record.
Administrator observations never alter access profiles or the user access union.
User and administrator directory issues remain separately attributed.
