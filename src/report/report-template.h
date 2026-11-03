#pragma once

#include <string_view>

namespace win_obj {
    inline constexpr std::wstring_view report_html_start = LR"REPORT(<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Windows object report</title>
<style>
:root{color-scheme:light;--ink:#182b35;--muted:#58717d;--line:#d8e3e7;--accent:#006b68;--paper:#fff;--wash:#f2f6f7}
*{box-sizing:border-box}body{margin:0;background:var(--wash);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{background:#142f39;color:#fff;padding:32px max(24px,calc((100vw - 1500px)/2));border-bottom:5px solid #4ec5af}
.eyebrow{font-size:11px;font-weight:700;letter-spacing:.16em;color:#8dd8cb;text-transform:uppercase}h1{font-size:30px;letter-spacing:-.03em;margin:6px 0}h2{font-size:18px;margin:0 0 12px}p{margin:8px 0}.muted{color:var(--muted)}header .muted{color:#c1d6dc}
main{max-width:1548px;margin:auto;padding:24px}.topline{display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap}
.badge{border:1px solid #b9d9ce;background:#eaf7f1;color:#165e43;border-radius:20px;font-size:12px;padding:3px 10px;white-space:nowrap}.badge.warn{background:#fff3d7;border-color:#e6c784;color:#765000}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}.card,.panel{background:var(--paper);border:1px solid var(--line);border-radius:10px}.card{padding:16px 20px}.card span{display:block;color:var(--muted);font-size:12px}.card strong{font-size:27px;letter-spacing:-.03em}
.panel{padding:18px;margin-bottom:18px}.filters{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;align-items:end}label{display:block;color:var(--muted);font-size:12px;font-weight:600}input,select,button{font:inherit}input,select{display:block;width:100%;min-width:0;padding:9px 10px;border:1px solid #b9ccd3;border-radius:6px;background:white;color:var(--ink)}
button{cursor:pointer;border:1px solid #b9ccd3;border-radius:6px;background:#fff;color:var(--ink);padding:8px 12px}button:hover{border-color:var(--accent);background:#eff9f6}button:disabled{cursor:default;opacity:.4}:focus-visible{outline:3px solid #139c98;outline-offset:2px}
.table-panel{padding:0;overflow:hidden}.toolbar{padding:14px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.toolbar label{display:flex;align-items:center;gap:8px}.toolbar select{width:auto}.scroll{overflow:auto;max-height:65vh}table{border-collapse:collapse;width:100%;font-size:13px;text-align:left}th{background:#edf3f5;color:#39545f;position:sticky;top:0;z-index:1;font-size:12px;white-space:nowrap}th,td{padding:11px 14px;border-bottom:1px solid #e5ecef;vertical-align:top}th button{border:0;background:transparent;padding:0;color:inherit;font-weight:650}tbody tr:hover{background:#f4faf8}.name{min-width:280px;max-width:620px;overflow-wrap:anywhere;font-family:Consolas,monospace;font-size:12px}.code{font-family:Consolas,monospace;white-space:nowrap}.outcomes{min-width:170px}.outcomes span{display:inline-block;margin:0 7px 3px 0}.granted{color:#176744}.denied,.error{color:#a33232}.skipped,.unsupported{color:#687983}.timeout,.busy,.reduced{color:#96600a}.empty{padding:36px;text-align:center;color:var(--muted)}.pagination{padding:14px 18px;display:flex;gap:12px;justify-content:flex-end;align-items:center}
summary{cursor:pointer;font-weight:650}details .scroll{margin-top:14px;max-height:280px}.notice{font-size:12px;color:var(--muted);margin:12px 0}.metadata{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}.fatal{background:#ffe7e7;color:#8c2222;padding:16px}
dialog{border:1px solid var(--line);border-radius:12px;padding:0;width:min(1300px,95vw);max-height:90vh;color:var(--ink)}dialog::backdrop{background:#092531a8}dialog .dialog-head .metadata{max-height:28vh;overflow:auto}dialog .dialog-head{padding:20px;border-bottom:1px solid var(--line)}dialog h2{overflow-wrap:anywhere;max-width:90%;font-size:16px}dialog .scroll{max-height:58vh}.detail-note{min-width:250px;font-size:12px}.advisory{background:#fff8e8}noscript{display:block;padding:24px;background:#fff3d7}
@media(max-width:900px){.filters{grid-template-columns:1fr 1fr}.filters label:first-child{grid-column:1/-1}.cards{grid-template-columns:1fr 1fr}main{padding:14px}header{padding:24px}.name{min-width:220px}}
@media print{header{background:white;color:black}.filters,.pagination,button{display:none}.scroll{max-height:none;overflow:visible}.cards{grid-template-columns:repeat(4,1fr)}}
th[aria-sort="ascending"] button::after{content:" \2191"}th[aria-sort="descending"] button::after{content:" \2193"}
</style></head><body>
<header><div class="topline"><div><div class="eyebrow">win-obj-enum / local report</div><h1>Windows object report</h1><p class="muted" id="subtitle"></p></div><span id="completion" class="badge"></span></div></header>
<noscript>This report needs JavaScript for sorting and filtering. It works offline and makes no network requests.</noscript>
<main><div class="cards"><div class="card"><span>Objects in report</span><strong id="objectCount">0</strong></div><div class="card"><span>Objects discovered</span><strong id="discoveredCount">0</strong></div><div class="card"><span>Access observations</span><strong id="attemptCount">0</strong></div><div class="card"><span>Discovery issues</span><strong id="issueCount">0</strong></div></div>
<section class="panel"><div class="filters"><label>Search names, rights, errors<input id="search" type="search" placeholder="Path, interface UUID, or access right"></label><label>Process name or PID<input id="process" type="search" placeholder="svchost.exe or exact PID"></label><label>Object type<select id="type"><option value="">All types</option></select></label><label>Probe outcome<select id="status"><option value="">All outcomes</option><option value="untested">Untested</option></select></label><label>Access right or check<select id="right"><option value="">All checks</option></select></label><label>Discovery source<select id="discovery"><option value="">Any source</option><option value="1">User only</option><option value="2">Administrator only</option><option value="3">Both</option></select></label><label>Process evidence source<select id="processSource"><option value="">Any source</option><option value="1">User observations</option><option value="2">Administrator observations</option></select></label><label>User access verification<select id="context"><option value="">Any verification</option><option value="verified">Primary context verified</option><option value="failed">Context verification failed</option><option value="unverified">No verification recorded</option></select></label><button id="reset">Reset filters</button></div>
<p class="notice">Outcome and check filters match the same attempt. Explicit masks are observed unions, not jointly granted access. MAXIMUM_ALLOWED is advisory. Connection success does not prove server-object or application access.</p><p class="notice">Processes are observed handle holders, pipe servers, device users, TCP listeners, or session members. Creator attribution is unknown. Empty results do not prove that no process is associated.</p><p class="notice">Access results come only from the original user primary context. Administrator discovery and metadata never contribute to access grants.</p><p id="adminCoverage" class="notice"></p><p id="processCoverage" class="notice"></p></section>
<section class="panel table-panel"><div class="toolbar"><span id="showing" role="status" aria-live="polite"></span><label>Rows per page<select id="pageSize"><option>50</option><option selected>100</option><option>250</option></select></label></div><div class="scroll"><table id="objects"><thead><tr>
<th scope="col" aria-sort="none"><button data-sort="type">Type</button></th><th scope="col" aria-sort="ascending"><button data-sort="name">Object name</button></th><th scope="col" aria-sort="none"><button data-sort="outcome">Outcomes</button></th><th scope="col" aria-sort="none"><button data-sort="union">Explicit union</button></th><th scope="col" aria-sort="none"><button data-sort="count">Checks</button></th><th scope="col" aria-sort="none"><button data-sort="processText">Associated processes</button></th><th scope="col" aria-sort="none"><button data-sort="discoverySource">Discovery</button></th><th scope="col">Details</th>
</tr></thead><tbody id="rows"></tbody></table><div id="empty" class="empty" hidden>No objects match these filters.</div></div><div class="pagination"><button id="previous">Previous</button><span id="pageLabel"></span><button id="next">Next</button></div></section>
<details class="panel" id="coverage"><summary>Scan coverage and discovery issues</summary><div class="scroll"><table><thead><tr><th>Type</th><th>Discovered</th><th>Matched</th><th>User discovery</th><th>Administrator discovery</th><th>Probes</th></tr></thead><tbody id="coverageRows"></tbody></table></div><div class="scroll"><table><thead><tr><th>Type</th><th>Location</th><th>Error</th></tr></thead><tbody id="issueRows"></tbody></table></div></details>
<details class="panel"><summary>Scan settings and user primary token</summary><div id="metadata" class="metadata"></div></details>
<p class="notice">Offline report. Sorting and filtering change only the view; all exported rows remain in this file. “Completed” describes scan execution, not universal object accessibility. Skipped and unsupported checks remain unresolved.</p>
</main>
<dialog id="detail"><div class="dialog-head"><div class="topline"><h2 id="detailName"></h2><button id="closeDetail">Close</button></div><div id="detailMeta" class="metadata"></div></div><div class="scroll"><table><thead><tr><th>Check / evidence</th><th>Outcome</th><th>Requested</th><th>Granted</th><th>Error</th><th>ms</th><th>Notes / user context</th></tr></thead><tbody id="detailRows"></tbody></table><p class="empty" id="noChecks" hidden>Access was not tested for this object.</p></div></dialog>
<script id="report-data" type="application/json">)REPORT";

    inline constexpr std::wstring_view report_html_end = LR"REPORT(</script>
<script>
'use strict';
try {
const report = JSON.parse(document.getElementById('report-data').textContent);
const $ = id => document.getElementById(id);
const hex = value => value == null ? '\u2014' : '0x' + Number(value).toString(16);
const cell = (row, text, className = '') => { const td = document.createElement('td'); td.textContent = String(text); td.className = className; row.append(td); return td; };
const option = (select, value, label) => { const node = document.createElement('option'); node.value = value; node.textContent = label; select.append(node); };
const attempts = object => object.profile == null ? [] : report.profiles[object.profile];
const outcomes = object => {
  if (object.error) return 'error';
  if (object.profile == null) return 'untested';
  const counts = new Map(); for (const a of attempts(object)) counts.set(a[1], (counts.get(a[1]) || 0) + 1);
  return Array.from(counts, ([name, count]) => count + ' ' + name).join(' / ') || 'no checks';
};
const statusNames = ['granted','reduced','denied','privilege-required','unavailable','busy','timeout','unsupported','skipped','error'];
for (const name of statusNames) option($('status'), name, name.replaceAll('-', ' '));
for (const type of Array.from(new Set(report.groups.map(g => g.type))).sort()) option($('type'), type, type);
for (const name of Array.from(new Set(report.rights.map(r => r[0]))).sort()) option($('right'), name, name);
const sourceName = source => ({1:'user',2:'administrator',3:'both'})[source] || 'unknown';
const processEntries = object => (object.processes || []).map(([id, relation, sources]) => ({ ...report.processes[id], relation, sources }));
const processLabel = process => process.name + ' (PID ' + process.pid + ', ' + process.relation + '; ' + sourceName(process.sources) + ')';
const processText = object => processEntries(object).map(processLabel).join('; ') || ('Unknown: ' + object.processStatus);
const processPreview = object => { const entries = processEntries(object); return entries.length > 3 ? entries.slice(0,3).map(processLabel).join('; ') + '; +' + (entries.length - 3) + ' more (Inspect)' : object.processText; };
const rows = report.objects.map((object, id) => ({ ...object, id, outcome: outcomes(object), count: attempts(object).length, processText: processText(object),
  search: [object.type, object.name, object.native, object.error, ...(object.rpc || []), object.session == null ? '' : 'session ' + object.session,
    ...attempts(object).map(a => [report.rights[a[0]][0], a[1], a[4], a[5] ? hex(a[5]) : '', a[6] ? hex(a[6]) : ''].join(' '))].join(' ').toLowerCase() }));
let sortKey = 'name', direction = 1, page = 0, visible = rows;
$('subtitle').textContent = report.started + ' to ' + report.finished + ' | ' + (report.access ? 'Discovery + access' : 'Discovery only') + ' | ' + report.selection;
$('completion').textContent = report.completed ? 'Scan completed' : 'Partial or failed scan';
if (!report.completed) $('completion').classList.add('warn');
if (report.userContextError) $('completion').textContent = 'User context verification failed: ' + report.userContextError;
$('objectCount').textContent = rows.length.toLocaleString();
$('discoveredCount').textContent = report.groups.reduce((n,g) => n + g.total, 0).toLocaleString();
$('attemptCount').textContent = rows.reduce((n,r) => n + r.count, 0).toLocaleString();
$('issueCount').textContent = report.groups.reduce((n,g) => n + g.issues.length + g.adminIssues.length, 0).toLocaleString();
const admin = report.administrator;
const adminMessage = !admin.requested ? 'Administrator collection not requested.' : admin.error ? 'Administrator collection unavailable: ' + admin.errorOperation + ' (' + admin.error + '). User results are retained.' + (!admin.cleanupConfirmed ? ' Collector cleanup unconfirmed; user access probes skipped.' : '') :
  'Administrator collection received. Debug privilege: ' + (admin.debugRequested ? admin.debugEnabled ? 'enabled in collector only' : 'unavailable (' + admin.debugError + ')' : 'not requested') + '. ' +
  (admin.processScan.requested ? 'Administrator process coverage: ' + (admin.processScan.complete ? 'completed' : 'partial') + ', ' + admin.processScan.failed + ' failures, ' + admin.processScan.inaccessibleProcesses + ' inaccessible processes, ' + admin.processScan.timeouts + ' timeouts.' + (admin.processScan.budgetExhausted ? ' Budget exhausted.' : '') + (admin.processScan.error ? ' ' + admin.processScan.errorOperation + ': ' + hex(admin.processScan.error) : '') + (admin.processScan.tcpError ? ' TCP error: ' + hex(admin.processScan.tcpError) : '') : 'Administrator process collection disabled.');
$('adminCoverage').textContent = adminMessage;
if (admin.error || admin.debugError) $('adminCoverage').classList.add('warn');
const pc = report.processScan;
$('processCoverage').textContent = !pc.requested ? 'Process collection disabled.' :
  'User process snapshot: ' + (pc.complete ? 'traversal completed' : 'partial') + '; ' + pc.queried + ' handle queries, ' + pc.failed + ' failures, ' +
  pc.inaccessibleProcesses + ' inaccessible processes, ' + pc.timeouts + ' timeouts.' + (pc.budgetExhausted ? ' Time budget exhausted.' : '') +
  (pc.error ? ' ' + pc.errorOperation + ': ' + hex(pc.error) : '') + (pc.tcpError ? ' TCP snapshot error: ' + hex(pc.tcpError) : '');
if (pc.requested && !pc.complete) $('processCoverage').classList.add('warn');
const metadata = ['Selection: ' + report.selection, 'Name filter: ' + (report.match || '(none)'), 'Device opens: ' + Boolean(report.options.devices),
  'Connections: ' + Boolean(report.options.connections), 'MAXIMUM_ALLOWED: ' + Boolean(report.options.maximum), 'Attempt timeout: ' + report.options.timeoutMs + ' ms'];
if (report.token) {
  const t = report.token; metadata.push('SID: ' + t.sid, 'Integrity RID: ' + hex(t.integrity), 'Elevated: ' + Boolean(t.elevated), 'Restricted: ' + Boolean(t.restricted),
    'AppContainer: ' + Boolean(t.appContainer), 'Impersonating: ' + Boolean(t.impersonating), 'Enabled privileges: ' + (t.privileges.join(', ') || '(none)'));
  metadata.push('Execution: primary token; no thread impersonation', 'Primary fingerprint: ' + t.fingerprint, 'Logon ID: ' + t.authenticationId, 'Session: ' + t.session, 'Group states: ' + t.groups.join(', '), 'Privilege states: ' + t.privilegeStates.join(', '));
  if (t.error) metadata.push('Token error: ' + t.errorOperation + ' ' + hex(t.error));
}
if (admin.token) metadata.push('Administrator SID: ' + admin.token.sid, 'Administrator primary fingerprint: ' + admin.token.fingerprint, 'Administrator enabled privileges: ' + admin.token.privileges.join(', '));
$('metadata').textContent = metadata.join('\n');
for (const group of report.groups) {
  const row = document.createElement('tr'); cell(row, group.type); cell(row, group.total); cell(row, group.matched);
  cell(row, !group.userDiscovered ? 'failed' : (group.issues.length ? 'partial' : 'complete') + ' (' + group.userTotal + ')'); cell(row, !admin.requested ? 'not requested' : !group.adminDiscovered ? 'failed' : (group.adminIssues.length ? 'partial' : 'complete') + ' (' + group.adminTotal + ')'); cell(row, !report.access ? 'not requested' : group.probesCompleted ? 'completed' : 'incomplete'); $('coverageRows').append(row);
  for (const issue of group.adminIssues) { const item = document.createElement('tr'); cell(item, group.type + ' / administrator'); cell(item, issue[0], 'name'); cell(item, issue[1] + ' ' + hex(issue[2]), 'code'); $('issueRows').append(item); }
  for (const issue of group.issues) { const item = document.createElement('tr'); cell(item, group.type); cell(item, issue[0], 'name'); cell(item, issue[1] + ' ' + hex(issue[2]), 'code'); $('issueRows').append(item); }
}
function inspect(object) {
  $('detailName').textContent = object.name;
  const lines = ['Type: ' + object.type + (object.native ? ' | Native type: ' + object.native : ''), 'Explicit observed union: ' + hex(object.union) + ' (not a combined grant)'];
  lines.push('Discovery source: ' + sourceName(object.discoverySource), 'Access context: original user primary token', 'Creator: unknown', 'Associated processes: ' + object.processText);
  for (const p of processEntries(object)) if (p.imagePath) lines.push('Process image (administrator): PID ' + p.pid + ' ' + p.imagePath);
  if (object.session != null) lines.push('Session ID: ' + object.session);
  if (object.rpc) lines.push('RPC interface: ' + object.rpc[0] + ' v' + object.rpc[1] + '.' + object.rpc[2], 'RPC object UUID: ' + object.rpc[3]);
  if (object.time && object.time !== '0') { const date = new Date(Number((BigInt(object.time) - 116444736000000000n) / 10000n)); if (!Number.isNaN(date.getTime())) lines.push('Observed: ' + date.toISOString()); }
  if (object.error) lines.push('Error: ' + object.error);
  $('detailMeta').textContent = lines.join('\n'); $('detailRows').replaceChildren();
  attempts(object).forEach((a, i) => {
    const right = report.rights[a[0]], row = document.createElement('tr');
    if (right[0] === 'MAXIMUM_ALLOWED') row.className = 'advisory';
    cell(row, right[0] + '\n' + right[1]); cell(row, a[1], a[1]); cell(row, hex(right[2]), 'code');
    cell(row, a[3] == null ? (a[2] ? 'Opened; mask unknown' : 'Unknown') : hex(a[3]), 'code');
    cell(row, [a[5] ? a[4] + ' ' + hex(a[5]) : '', a[6] ? 'Query NTSTATUS ' + hex(a[6]) : ''].filter(Boolean).join('\n') || '\u2014', 'code');
    cell(row, object.ms[i] || 0); cell(row, (right[3] || '') + '\n' + (a[8] ? 'CONTEXT FAILED: ' + a[8] : a[7] ? 'User primary context verified before/after' : 'No context verification recorded'), 'detail-note'); $('detailRows').append(row);
  });
  $('noChecks').hidden = attempts(object).length !== 0; $('detail').showModal();
}
function render() {
  const query = $('search').value.trim().toLowerCase(), type = $('type').value, status = $('status').value, right = $('right').value, process = $('process').value.trim().toLowerCase(), discovery = $('discovery').value, processSource = Number($('processSource').value), context = $('context').value;
  visible = rows.filter(object => ((!process && !processSource) || processEntries(object).some(p => (!process || (/^\d+$/.test(process) ? String(p.pid) === String(Number(process)) : p.name.toLowerCase().includes(process))) && (!processSource || (p.sources & processSource)))) && (!discovery || object.discoverySource === Number(discovery)) && (!query || object.search.includes(query)) && (!type || object.type === type) &&
    (!status && !right && !context || status === 'untested' && !right && !context && object.profile == null && !object.error ||
      status === 'error' && !right && !context && Boolean(object.error) || attempts(object).some(a => (!status || a[1] === status) && (!right || report.rights[a[0]][0] === right) && (!context || context === 'verified' && a[7] || context === 'failed' && a[8] || context === 'unverified' && !a[7] && !a[8]))));
  visible.sort((a,b) => {
    const av = a[sortKey], bv = b[sortKey];
    const comparison = sortKey === 'union' || sortKey === 'count' ? (av == null ? -1 : av) - (bv == null ? -1 : bv) : String(av).localeCompare(String(bv), undefined, {numeric:true});
    return direction * comparison || a.id - b.id;
  });
  const size = Number($('pageSize').value), pages = Math.max(1, Math.ceil(visible.length / size)); page = Math.max(0, Math.min(page, pages - 1));
  const fragment = document.createDocumentFragment();
  for (const object of visible.slice(page * size, (page + 1) * size)) {
    const row = document.createElement('tr'); cell(row, object.type); cell(row, object.name, 'name');
    const summary = cell(row, '', 'outcomes');
    for (const label of object.outcome.split(' / ')) { const span = document.createElement('span'); span.textContent = label; span.className = label.split(' ').at(-1); summary.append(span); }
    cell(row, hex(object.union), 'code'); cell(row, object.count); cell(row, processPreview(object), 'detail-note'); cell(row, sourceName(object.discoverySource));
    const action = cell(row, ''), button = document.createElement('button'); button.textContent = 'Inspect'; button.setAttribute('aria-label', 'Inspect ' + object.name); button.addEventListener('click', () => inspect(object)); action.append(button); fragment.append(row);
  }
  $('rows').replaceChildren(fragment); $('empty').hidden = visible.length !== 0;
  $('showing').textContent = visible.length.toLocaleString() + ' of ' + rows.length.toLocaleString() + ' objects match';
  $('pageLabel').textContent = 'Page ' + (page + 1) + ' of ' + pages;
  $('previous').disabled = page === 0; $('next').disabled = page >= pages - 1;
  document.querySelectorAll('[data-sort]').forEach(button => button.parentElement.setAttribute('aria-sort', button.dataset.sort === sortKey ? direction === 1 ? 'ascending' : 'descending' : 'none'));
}
for (const id of ['search','process','type','status','right','discovery','processSource','context','pageSize']) $(id).addEventListener(id === 'search' || id === 'process' ? 'input' : 'change', () => { page = 0; render(); });
document.querySelectorAll('[data-sort]').forEach(button => button.addEventListener('click', () => { direction = sortKey === button.dataset.sort ? -direction : 1; sortKey = button.dataset.sort; page = 0; render(); }));
$('reset').addEventListener('click', () => { for (const id of ['search','process','type','status','right','discovery','processSource','context']) $(id).value = ''; page = 0; sortKey = 'name'; direction = 1; render(); });
$('previous').addEventListener('click', () => { --page; render(); }); $('next').addEventListener('click', () => { ++page; render(); });
$('closeDetail').addEventListener('click', () => $('detail').close());
render();
} catch (error) {
  const message = document.createElement('p'); message.className = 'fatal'; message.textContent = 'Could not display this report: ' + error.message; document.querySelector('main').prepend(message);
}
</script></body></html>)REPORT";
}
