// Dependency-free tests for the exact JavaScript embedded in the generated report.
// A small DOM double exercises events and rendering without requiring a browser.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

class Element {
    constructor(tag = 'div') {
        this.tag = tag; this.children = []; this.attributes = {}; this.dataset = {};
        this.listeners = {}; this.value = ''; this.hidden = false; this.disabled = false;
        this.className = ''; this.text = ''; this.open = false;
        this.classList = { add: name => { this.className += ' ' + name; } };
    }
    set textContent(text) { this.text = String(text); this.children = []; }
    get textContent() { return this.text + this.children.map(node => node.textContent).join(''); }
    append(...nodes) {
        for (const node of nodes) {
            if (node.tag === 'fragment') this.append(...node.children);
            else { node.parentElement = this; this.children.push(node); }
        }
    }
    prepend(node) { node.parentElement = this; this.children.unshift(node); }
    replaceChildren(...nodes) { this.children = []; this.text = ''; this.append(...nodes); }
    setAttribute(name, value) { this.attributes[name] = value; }
    addEventListener(name, callback) { (this.listeners[name] ||= []).push(callback); }
    trigger(name) { for (const callback of this.listeners[name] || []) callback(); }
    showModal() { this.open = true; }
    close() { this.open = false; }
}

function loadReport(path) {
    const html = fs.readFileSync(path, 'utf8');
    const dataText = html.match(/<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/)[1];
    const data = JSON.parse(dataText);
    const source = html.match(/<script>\s*([\s\S]*?)<\/script>/)[1];
    assert.equal((html.match(/<script(?:\s|>)/g) || []).length, 2, 'data escaped into executable markup');
    const ids = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(match => [match[1], new Element()]));
    ids.get('report-data').textContent = dataText;
    ids.get('pageSize').value = '100';
    const main = new Element('main');
    const buttons = ['type', 'name', 'outcome', 'union', 'count', 'processText', 'discoverySource'].map(key => {
        const button = new Element('button'); button.dataset.sort = key;
        new Element('th').append(button); return button;
    });
    const context = { document: {
        getElementById: id => { assert(ids.has(id), 'missing DOM ID: ' + id); return ids.get(id); },
        createElement: tag => new Element(tag), createDocumentFragment: () => new Element('fragment'),
        querySelectorAll: selector => { assert.equal(selector, '[data-sort]'); return buttons; },
        querySelector: selector => { assert.equal(selector, 'main'); return main; }
    } };
    vm.runInNewContext(source, context, { timeout: 5000 });
    assert(!main.children.some(node => node.className === 'fatal'), main.textContent);
    assert.equal(context.reportInjected, undefined);
    return { data, ids, buttons, context, main, html };
}

const report = loadReport('build/tests/reports/fixture.html');
const { ids, data, buttons } = report;
const set = (id, value) => { ids.get(id).value = value; ids.get(id).trigger(id === 'search' || id === 'process' ? 'input' : 'change'); };
const click = id => ids.get(id).trigger('click');
const rows = () => ids.get('rows').children;
const names = () => rows().map(row => row.children[1].textContent);
assert.equal(data.objects.length, 127);
assert.equal(data.profiles.length, 2, 'timings should not split otherwise identical profiles');
assert.equal(data.objects[124].ms[0], 124, 'HTML lost per-attempt timing');
assert.equal(data.objects[126].session, 0, 'session zero lost');
assert.equal(data.objects[126].profile, null, 'discovery-only row mislabeled');
assert.equal(rows().length, 100);
click('next'); assert.equal(rows().length, 27); assert(ids.get('next').disabled);
click('previous'); assert.equal(rows().length, 100);
set('type', 'event'); set('status', 'denied'); set('right', 'EVENT_QUERY_STATE');
assert.equal(rows().length, 0, 'outcome and check must match the same attempt');
set('right', 'EVENT_MODIFY_STATE'); assert.equal(rows().length, 100);
assert.equal(ids.get('showing').textContent, '125 of 127 objects match');
set('search', '<script>'); assert.equal(rows().length, 1);
assert(names()[0].includes('<script>alert(1)</script>'));
rows()[0].children[7].children[0].trigger('click');
assert(ids.get('detail').open); assert.equal(ids.get('detailRows').children.length, 3);
assert.equal(ids.get('detailRows').children[2].children[3].textContent, '0x0', 'zero grant displayed as unknown');
assert.equal(ids.get('detailRows').children[2].className, 'advisory');
assert(ids.get('detailRows').children[1].children[6].textContent.includes('</script>'));
click('closeDetail'); assert(!ids.get('detail').open);
click('reset'); set('type', 'namedpipe');
rows()[0].children[7].children[0].trigger('click');
assert.equal(ids.get('detailRows').children[0].children[3].textContent, 'Unknown');
click('closeDetail'); click('reset'); set('status', 'untested');
assert.deepEqual(names(), ['Session 0']);
click('reset'); set('pageSize', '250');
buttons.find(button => button.dataset.sort === 'union').trigger('click');
assert.equal(names()[0], 'Session 0', 'numeric sort must distinguish unknown from zero');
buttons.find(button => button.dataset.sort === 'union').trigger('click');
assert.equal(rows()[0].children[3].textContent, '0x1');
assert.equal(buttons.find(button => button.dataset.sort === 'union').parentElement.attributes['aria-sort'], 'descending');
set('search', '0xc0000022'); assert.equal(rows().length, 125);
click('reset'); set('process', 'sVcHoSt'); assert.equal(rows().length, 125);
set('process', '42'); assert.equal(rows().length, 126, 'exact PID must not match 142');
set('process', '142'); assert.equal(rows().length, 2, 'all holders and servers should be searchable');
set('type', 'event'); assert.equal(rows().length, 1, 'process and type filters must compose');
rows()[0].children[7].children[0].trigger('click');
assert(ids.get('detailMeta').textContent.includes('Creator: unknown'));
assert(ids.get('detailMeta').textContent.includes('helper-\u03a9</script>.exe'));
click('closeDetail'); click('reset'); set('process', 'no-such-process'); assert.equal(rows().length, 0);
click('reset'); assert.equal(rows().length, 127); assert.equal(ids.get('process').value, '');
assert.equal(data.processes.length, 5, 'identities must be deduplicated by PID and creation time');
assert.equal(data.objects[0].processes.length, 4);
set('process', '342'); assert.equal(rows().length, 1, 'holders omitted from the preview must remain searchable');
assert(rows()[0].children[5].textContent.includes('+1 more'));
assert(!rows()[0].children[5].textContent.includes('hidden-holder'));
rows()[0].children[7].children[0].trigger('click');
assert(ids.get('detailMeta').textContent.includes('hidden-holder.exe'));
click('closeDetail'); click('reset');
assert(ids.get('processCoverage').textContent.includes('partial'));
assert.equal(data.objects[0].creator, null);
set('discovery', '2'); assert.equal(rows().length, 1); assert(names()[0].endsWith('Event-1'));
set('discovery', '3'); assert.equal(rows().length, 1); assert(names()[0].includes('<script>'));
click('reset'); set('process', 'svchost'); set('processSource', '2'); assert.equal(rows().length, 1, 'process name and evidence source must match the same association');
set('context', 'verified'); assert.equal(rows().length, 1);
click('reset'); set('context', 'verified'); assert.equal(rows().length, 125);
set('context', 'failed'); assert.equal(rows().length, 0);
set('context', 'unverified'); assert.equal(rows().length, 1); assert.equal(names()[0], '\\\\.\\pipe\\busy');
click('reset'); assert.equal(ids.get('discovery').value, ''); assert.equal(ids.get('processSource').value, ''); assert.equal(ids.get('context').value, '');
assert(ids.get('adminCoverage').textContent.includes('enabled in collector only'));
assert.equal(data.token.elevated, 0); assert.equal(data.administrator.token.elevated, 1);
const empty = loadReport('build/tests/reports/empty.html');
assert.equal(empty.ids.get('rows').children.length, 0);
assert.equal(empty.ids.get('empty').hidden, false);

// Decode the compact profiles and compare their access evidence with the HTML.
const compact = fs.readFileSync('build/tests/reports/fixture-\u03a9.txt', 'utf8');
const codes = {G:'granted',R:'reduced',D:'denied',P:'privilege-required',U:'unavailable',B:'busy',T:'timeout',X:'unsupported',S:'skipped',E:'error'};
const profiles = compact.split('\n').filter(line => /^P \d+/.test(line));
assert.equal(profiles.length, data.profiles.length);
for (const line of profiles) {
    const [, id, ...entries] = line.split(' ');
    const decoded = entries.map(entry => {
        const [head, ...fields] = entry.split(',');
        const [, right, status] = head.match(/^r(\d+):([A-Z])$/);
        let opened = 0, granted = null, domain = 'none', error = 0, query = 0, verified = 0, contextError = 0;
        for (const field of fields) {
            if (field === 'o') opened = 1;
            else if (field === 'v') verified = 1;
            else if (field.startsWith('c=')) contextError = Number(field.slice(2));
            else if (field.startsWith('g=')) granted = Number(field.slice(2));
            else if (field.startsWith('q=')) query = Number(field.slice(2));
            else if (field.startsWith('e=')) { const pair = field.slice(2).split(':'); domain = pair[0]; error = Number(pair[1]); }
        }
        return [Number(right), codes[status], opened, granted, domain, error, query, verified, contextError];
    });
    assert.deepEqual(decoded, data.profiles[Number(id)], 'LLM profile lost access evidence');
}
const objectLines = compact.split('\n').filter(line => line.startsWith('O '));
assert.equal(objectLines.length, data.objects.length);
objectLines.forEach((line, i) => {
    const match = line.match(/^O ("(?:\\.|[^"\\])*")(.*)$/);
    assert(match); assert.equal(JSON.parse(match[1]), data.objects[i].name);
    const profile = match[2].match(/\bp=(\d+)/);
    assert.equal(profile ? Number(profile[1]) : null, data.objects[i].profile);
});
const processLines = compact.split('\n').filter(line => /^PROC \d+/.test(line));
assert.equal(processLines.length, data.processes.length);
for (const line of processLines) {
    const [, id, pid, name, created, session, imagePath] = line.match(/^PROC (\d+) (\d+) ("(?:\\.|[^"\\])*") (\d+) (\d+)(?: path=("(?:\\.|[^"\\])*"))?$/);
    assert.deepEqual({ pid: Number(pid), name: JSON.parse(name), created, session: Number(session), imagePath: imagePath ? JSON.parse(imagePath) : '' }, data.processes[Number(id)]);
}
objectLines.forEach((line, i) => {
    const match = line.match(/ proc=([^ ]+)/);
    const refs = match ? match[1].split(',').map(item => { const [id, role, source] = item.split(':'); return [Number(id), role, Number(source)]; }) : [];
    assert.deepEqual(refs, data.objects[i].processes);
});
console.log('Report UI logic and compact-profile round-trip tests passed');
