// Case correlations (fixlist/case_correlations.py): an FRST / Addition line
// whose file also appears in another log of the same infection case gets an
// info icon. Clicking it lists what those logs say about the file: scanner
// detections with their SHA-256 / MD5 and stored centralbox result, and what a
// fixlist did to it. Read-only; nothing here changes a line's status.
//
// Everything is optional: without correlations, on any error or for guests
// the analyzer looks exactly as before.

const CASE_CORRELATIONS_URL = analyzerConfig.caseCorrelationsUrl || '';
const CORRELATION_DOT = ' · ';

let caseCorrelations = new Map();
// Line text -> the worst related finding as a line-verdict status letter
// (computed by the server with the line-verdict precedence).
let caseCorrelationStatuses = new Map();
let caseCorrelationsUploadId = '';
// 'case': the helper's own cases with this log; 'user': no such case, so the
// other logs of the same forum user (caseCorrelationsName).
let caseCorrelationsScope = '';
let caseCorrelationsName = '';

let correlationMenuEl = null;
let correlationMenuTrigger = null;

function caseCorrelationsFor(entry) {
    if (!entry || typeof entry.line !== 'string') return [];
    return caseCorrelations.get(entry.line.trim()) || [];
}

// What a related log says, without log ids: the detection name or family
// and the centralbox verdict (or the fixlist result).
function correlationHash(item) {
    if (item.kind !== 'hash') return '';
    const sha = typeof item.sha256 === 'string' && /^[0-9a-f]{64}$/.test(item.sha256) ? item.sha256 : '';
    const md5 = typeof item.md5 === 'string' && /^[0-9a-f]{32}$/.test(item.md5) ? item.md5 : '';
    return sha ? 'SHA-256 ' + sha : md5 ? 'MD5 ' + md5 : '';
}

// How an entry was matched when not through the line's own file
// (case_correlations.MATCH_NOTES).
const CORRELATION_MATCH_NOTES = {
    argument: 'file in command line',
    registry: 'same registry value',
    service: 'same service',
    task: 'same task',
    extension: 'same extension',
    clsid: 'same CLSID',
    firewall: 'same firewall rule',
};

function correlationFinding(item) {
    if (item.kind === 'fixlog') return item.result || 'fixlist result';
    const result = item.centralbox && typeof item.centralbox === 'object' ? item.centralbox : null;
    // A bare hash (no detection, no centralbox result) shows the hash itself.
    const name = (result && (result.family || result.malware_type)) || item.detection || correlationHash(item);
    const verdict = result && result.verdict ? 'centralbox: ' + result.verdict
        : result && result.state === 'unknown' ? 'not in centralbox' : '';
    // A detection of a folder this line's file is in.
    const where = item.in_folder ? 'in detected folder' : '';
    // A Windows Defender event in a Fixlog, not a scanner's detection.
    const source = item.source === 'defender' ? 'Defender' : '';
    // Matched through something else than the line's own file.
    const how = CORRELATION_MATCH_NOTES[item.match] || '';
    // Which file the finding is about (the line's own, one in its command line, ...).
    const file = typeof item.file === 'string' ? item.file : '';
    return [file, name, verdict, source, how, where].filter(Boolean).join(CORRELATION_DOT) || (item.kind === 'hash' ? 'file hash' : 'detection');
}

// The log type a finding comes from, flagged when that log seems to come
// from another system.
function correlationSource(item) {
    if (isOwnCorrelation(item)) return 'this log';
    return String(item.log_type || 'log') + (item.system === 'different' ? CORRELATION_DOT + 'other system?' : '');
}

// One row per distinct finding (same log type and finding listed once).
function correlationRows(items) {
    const seen = new Set();
    return items.filter((item) => {
        const key = correlationSource(item) + '\n' + correlationFinding(item);
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

const CENTRALBOX_REPORT_URL_RE = /^https:\/\/centralbox\.dev\/analysis\/[0-9a-f]{64}$/;

// Distinct centralbox report URLs of the entries (stored verdicts of known hashes).
function correlationReportUrls(items) {
    const urls = [];
    items.forEach((item) => {
        const result = item && item.centralbox && typeof item.centralbox === 'object' ? item.centralbox : null;
        const url = result && typeof result.report_url === 'string' ? result.report_url : '';
        if (CENTRALBOX_REPORT_URL_RE.test(url) && !urls.includes(url)) urls.push(url);
    });
    return urls;
}

const CENTRALBOX_CHECK_URL = analyzerConfig.centralboxHashCheckUrl || '';
const CENTRALBOX_FRESH_URL = analyzerConfig.centralboxFreshStartUrl || '';
const CENTRALBOX_FRESH_STATUS_URL = analyzerConfig.centralboxFreshStatusUrl || '';
// Lookups only for a signed-in helper (the URLs are empty for guests) while
// centralbox is available (log_analyzer view).
const CENTRALBOX_LOOKUPS_ON = Boolean(analyzerConfig.centralboxAvailable)
    && Boolean(CENTRALBOX_CHECK_URL || (CENTRALBOX_FRESH_URL && CENTRALBOX_FRESH_STATUS_URL));
const CENTRALBOX_LOOKUP_URLS = {
    check: CENTRALBOX_CHECK_URL, fresh: CENTRALBOX_FRESH_URL, freshStatus: CENTRALBOX_FRESH_STATUS_URL,
};

// Correlated hashes without a centralbox verdict (shared: centralbox_lookup.js).
function correlationLookupTargets(items) {
    return typeof CentralboxLookup === 'object' ? CentralboxLookup.targets(items) : [];
}

// Lookup feedback sits right in front of the line's ⓘ icon, on its row. A
// redraw replaces the icon (e.g. when the answer changes the correlations),
// so the icon is found again by its line; without one the hint goes away.
// `spot` is {anchor, line}; `done` lets the hint fade after a moment.
let correlationLookupHint = null;
let correlationLookupHintTimer = null;
const CORRELATION_HINT_MS = 4000;

function removeCorrelationHint() {
    if (correlationLookupHintTimer) clearTimeout(correlationLookupHintTimer);
    correlationLookupHintTimer = null;
    if (correlationLookupHint) correlationLookupHint.remove();
    correlationLookupHint = null;
    correlationLookupHintSpot = null;
}

function correlationTriggerFor(spot) {
    if (spot.anchor && spot.anchor.isConnected) return spot.anchor;
    const found = Array.from(document.querySelectorAll('.line-correlation-trigger'))
        .find((button) => button.correlationLine === spot.line);
    if (found) spot.anchor = found;
    return found || null;
}

let correlationLookupHintSpot = null;

function placeCorrelationHint() {
    const hint = correlationLookupHint;
    const anchor = hint && correlationLookupHintSpot ? correlationTriggerFor(correlationLookupHintSpot) : null;
    if (!hint) return;
    if (!anchor) {
        removeCorrelationHint();
        return;
    }
    const rect = anchor.getBoundingClientRect();
    // Only while the icon is wholly inside the visible part of the log list:
    // a line scrolled (even partly) out of it would put the label over the
    // rest of the page.
    const area = anchor.closest('#logLines');
    if (area) {
        const box = area.getBoundingClientRect();
        if (rect.top < box.top || rect.bottom > box.bottom || rect.left < box.left || rect.right > box.right) {
            hint.hidden = true;
            return;
        }
    }
    hint.hidden = false;
    const width = hint.offsetWidth || 0;
    const height = hint.offsetHeight || 0;
    let left = rect.left - width - 4;
    if (left < 8) left = rect.right + 4;  // no room in front: just behind it
    const top = rect.top + (rect.height - height) / 2;
    hint.style.left = `${left + window.scrollX}px`;
    hint.style.top = `${top + window.scrollY}px`;
}

// The log list scrolls on its own: keep the hint next to its icon.
document.addEventListener('scroll', placeCorrelationHint, { capture: true, passive: true });
window.addEventListener('resize', placeCorrelationHint);

function correlationHint(spot, message, done = false) {
    if (correlationLookupHintTimer) clearTimeout(correlationLookupHintTimer);
    correlationLookupHintTimer = null;
    if (!correlationTriggerFor(spot)) {
        removeCorrelationHint();
        return;
    }
    if (!correlationLookupHint) {
        correlationLookupHint = document.createElement('div');
        correlationLookupHint.className = 'correlation-lookup-hint';
        correlationLookupHint.setAttribute('role', 'status');
        correlationLookupHint.setAttribute('aria-live', 'polite');
        document.body.appendChild(correlationLookupHint);
    }
    correlationLookupHintSpot = spot;
    correlationLookupHint.textContent = message;
    placeCorrelationHint();
    if (done) correlationLookupHintTimer = setTimeout(removeCorrelationHint, CORRELATION_HINT_MS);
}

// The final answer: shown in front of the icon, then the correlations are
// fetched again (a new answer changes colour and finding) and the hint
// follows the redrawn icon.
async function finishCorrelationLookup(spot, message, refresh = true) {
    correlationHint(spot, message, true);
    if (!refresh || !caseCorrelationsUploadId) return;
    await refreshCaseCorrelations(caseCorrelationsUploadId);
    if (correlationLookupHint && correlationLookupHint.textContent === message) correlationHint(spot, message, true);
}

async function checkCorrelatedHash(target, spot) {
    const result = await CentralboxLookup.check(target, CENTRALBOX_LOOKUP_URLS, (message) => correlationHint(spot, message));
    await finishCorrelationLookup(spot, result.message, result.refresh);
}

async function freshLookupCorrelatedHash(target, spot) {
    const result = await CentralboxLookup.fresh(target, CENTRALBOX_LOOKUP_URLS, (message) => correlationHint(spot, message));
    await finishCorrelationLookup(spot, result.message, result.refresh);
}

// Distinct file hashes of the entries (SHA-256, else the MD5 alone) with the
// file each belongs to, for the line's copy and search menus (analysis.js):
// [{hash, file}].
function correlationHashValues(items) {
    const hashes = [];
    (Array.isArray(items) ? items : []).forEach((item) => {
        if (!item || item.kind !== 'hash') return;
        const sha = typeof item.sha256 === 'string' && /^[0-9a-f]{64}$/.test(item.sha256) ? item.sha256 : '';
        const md5 = typeof item.md5 === 'string' && /^[0-9a-f]{32}$/.test(item.md5) ? item.md5 : '';
        const hash = sha || md5;
        if (hash && !hashes.some((known) => known.hash === hash)) {
            hashes.push({ hash, file: typeof item.file === 'string' ? item.file : '' });
        }
    });
    return hashes;
}

// How a correlated hash is shown in a menu: its file first, so a line that
// names several files says which one the hash is of. Only the hash is
// copied or looked up.
function correlationHashLabel({ hash, file }) {
    return file ? `${file} · ${hash}` : hash;
}

function correlationSummary(items) {
    return correlationRows(items).map((item) => `${correlationSource(item)}: ${correlationFinding(item)}`).join('\n');
}

// An entry of the loaded log itself (Defender events of its Addition part).
function isOwnCorrelation(item) {
    return Boolean(item) && Boolean(caseCorrelationsUploadId) && item.upload_id === caseCorrelationsUploadId;
}

// Where the line's findings come from: other logs, the log's own Addition
// part, or both.
function correlationHeader(items) {
    const list = Array.isArray(items) ? items : [];
    const own = list.some(isOwnCorrelation);
    const others = list.some((item) => !isOwnCorrelation(item));
    const scope = caseCorrelationsScope === 'user'
        ? `other logs of user ${caseCorrelationsName} (no case of yours)`
        : 'other logs of this case';
    if (own && !others) return "same file in this log's Addition part";
    if (own) return `same file in this log's Addition part and in ${scope}`;
    return `same file in ${scope}`;
}

const CORRELATION_STATUS_CLASS = {
    B: 'b', P: 'p', C: 'c', A: 'a', '!': 'w', G: 'g', S: 's', I: 'i', J: 'j',
};

function caseCorrelationStatusFor(entry) {
    if (!entry || typeof entry.line !== 'string') return '';
    return caseCorrelationStatuses.get(entry.line.trim()) || '';
}

// Lines whose correlations offer a centralbox lookup (correlationLookupTargets).
function correlationLookupLines() {
    if (!CENTRALBOX_LOOKUPS_ON) return [];
    return [...caseCorrelations.entries()]
        .filter(([, items]) => correlationLookupTargets(items).length > 0)
        .map(([line]) => line)
        .sort();
}

// The info icon for one analyzer row, or null.
function buildCaseCorrelationButton(entry) {
    try {
        const items = caseCorrelationsFor(entry);
        if (!items.length) return null;
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'line-correlation-trigger';
        // Lets a running lookup find this line's icon again after a redraw.
        button.correlationLine = entry.line.trim();
        const status = caseCorrelationStatusFor(entry);
        if (CORRELATION_STATUS_CLASS[status]) button.dataset.status = CORRELATION_STATUS_CLASS[status];
        const lookup = CENTRALBOX_LOOKUPS_ON && correlationLookupTargets(items).length > 0;
        // A circle with an up arrow instead of the circled i (centralbox_lookup.js).
        if (typeof CentralboxLookup === 'object') CentralboxLookup.setIcon(button, lookup);
        else button.textContent = 'ⓘ';
        button.setAttribute('aria-haspopup', 'menu');
        button.setAttribute('aria-expanded', 'false');
        button.setAttribute('aria-label', lookup
            ? 'what logs say about this file; a hash can be looked up on centralbox'
            : 'what logs say about this file');
        button.title = correlationHeader(items) + ':\n' + correlationSummary(items)
            + (lookup ? '\n(a hash without centralbox verdict: look it up from this menu)' : '');
        button.addEventListener('click', (event) => {
            event.stopPropagation();
            openCaseCorrelationMenu(button, items);
        });
        return button;
    } catch (error) {
        return null;
    }
}

function closeCaseCorrelationMenu() {
    if (correlationMenuTrigger) {
        correlationMenuTrigger.setAttribute('aria-expanded', 'false');
        correlationMenuTrigger = null;
    }
    if (correlationMenuEl) {
        correlationMenuEl.hidden = true;
        correlationMenuEl.innerHTML = '';
    }
}

function ensureCaseCorrelationMenu() {
    if (correlationMenuEl && document.body.contains(correlationMenuEl)) return correlationMenuEl;
    const menu = document.createElement('div');
    menu.className = 'line-copy-menu line-correlation-menu';
    menu.setAttribute('role', 'menu');
    menu.hidden = true;
    menu.addEventListener('click', (event) => event.stopPropagation());
    document.body.appendChild(menu);
    document.addEventListener('click', closeCaseCorrelationMenu);
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeCaseCorrelationMenu(); });
    window.addEventListener('resize', closeCaseCorrelationMenu);
    correlationMenuEl = menu;
    return menu;
}

// That log at the entry's line, which its page scrolls to and marks. For a
// hash: the file's entry (path line or detection header), not the hash line.
function correlationLogUrl(item) {
    const id = String(item.upload_id || '');
    const line = Number(item.anchor_line_no || item.line_no);
    if (!/^[A-Za-z0-9_-]+$/.test(id)) return '';
    return `/uploads/${encodeURIComponent(id)}/` + (Number.isInteger(line) && line > 0 ? `#L${line}` : '');
}

function addCorrelationMenuItem(menu, key, value, run, extraClass) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'line-copy-menu-item' + (extraClass ? ' ' + extraClass : '');
    item.setAttribute('role', 'menuitem');
    const label = document.createElement('span');
    label.className = 'line-copy-menu-key';
    label.textContent = key;
    const preview = document.createElement('span');
    preview.className = 'line-copy-menu-value';
    preview.textContent = value;
    item.append(label, preview);
    item.addEventListener('click', (event) => {
        event.stopPropagation();
        closeCaseCorrelationMenu();
        run();
    });
    menu.appendChild(item);
}

// The analyzer row (index into analyzedLines) of a line of the loaded log,
// numbered like the server and the log page (content.split('\n') from 1),
// or -1. The analyzer leaves out blank lines (see computeBlankLineGaps).
function analyzerIndexForLogLine(lineNo) {
    const input = document.getElementById('logInput');
    const lines = (input ? input.value : '').split('\n');
    if (!Number.isInteger(lineNo) || lineNo < 1 || lineNo > lines.length) return -1;
    const text = (lines[lineNo - 1].split(SPLITLINES_BOUNDARY)[0] || '').trim();
    if (!text) return -1;
    let index = 0;
    lines.slice(0, lineNo - 1).join('\n').split(SPLITLINES_BOUNDARY).forEach((piece) => {
        if (piece.trim()) index += 1;
    });
    if (analyzedLines[index] && analyzedLines[index].line === text) return index;
    // The textarea no longer matches the analysis exactly: the first row with the text.
    return analyzedLines.findIndex((entry) => entry && entry.line === text);
}

// Scroll the analyzer to a line of the loaded log and mark it for a moment
// (the mark fades out, as on the log page).
const CORRELATION_FLASH_MS = 2500;
let correlationFlashTimer = null;

function jumpToAnalyzerLine(lineNo, trigger, fromLine = '') {
    const index = analyzerIndexForLogLine(lineNo);
    const badge = index >= 0 ? document.querySelector(`#logLines .status-badge[data-line-index="${index}"]`) : null;
    const row = badge ? badge.closest('.log-line') : null;
    // Hints go next to the ⓘ icon of the line the jump started from.
    const spot = { anchor: trigger || null, line: trigger ? trigger.correlationLine || '' : fromLine };
    if (!row) {
        correlationHint(spot, 'line not found in the analyzer', true);
        return;
    }
    if (row.offsetParent === null) {
        correlationHint(spot, 'that line is hidden by the legend filter', true);
        return;
    }
    row.scrollIntoView({ block: 'center' });
    document.querySelectorAll('#logLines .correlation-flash, #logLines .correlation-flash-fade').forEach((el) => {
        el.classList.remove('correlation-flash', 'correlation-flash-fade');
    });
    void row.offsetWidth;
    row.classList.add('correlation-flash');
    if (correlationFlashTimer) clearTimeout(correlationFlashTimer);
    correlationFlashTimer = setTimeout(() => {
        // Fade out only now: the mark comes on at once.
        row.classList.add('correlation-flash-fade');
        row.classList.remove('correlation-flash');
        correlationFlashTimer = setTimeout(() => row.classList.remove('correlation-flash-fade'), 900);
    }, CORRELATION_FLASH_MS);
}

function openNewTab(url) {
    if (url) window.open(url, '_blank', 'noopener,noreferrer');
}

function openCaseCorrelationMenu(trigger, items) {
    if (correlationMenuTrigger === trigger && correlationMenuEl && !correlationMenuEl.hidden) {
        closeCaseCorrelationMenu();
        return;
    }
    if (typeof closeLineCopyMenu === 'function') closeLineCopyMenu();
    if (typeof closeLineSearchMenu === 'function') closeLineSearchMenu();
    const menu = ensureCaseCorrelationMenu();
    menu.innerHTML = '';
    const header = document.createElement('div');
    header.className = 'line-copy-menu-header';
    header.textContent = correlationHeader(items);
    menu.appendChild(header);

    // Clicking a row opens that log at the line (its id is never shown); a
    // row of the loaded log itself goes to the line here instead.
    correlationRows(items).forEach((item) => {
        const classes = ['line-correlation-source', `line-correlation-system-${item.system || 'unknown'}`];
        if (['b', 'p', 'g', 'w'].includes(item.severity)) classes.push(`line-correlation-sev-${item.severity}`);
        if (item.centralbox && item.centralbox.verdict === 'malicious') classes.push('line-correlation-bad');
        const run = isOwnCorrelation(item)
            ? () => jumpToAnalyzerLine(Number(item.anchor_line_no || item.line_no), trigger)
            : () => openNewTab(correlationLogUrl(item));
        addCorrelationMenuItem(menu, correlationSource(item), correlationFinding(item), run, classes.join(' '));
    });
    // The centralbox report of each correlated hash, shown as its URL like
    // the hash menus' VirusTotal entry.
    correlationReportUrls(items).forEach((url) => {
        addCorrelationMenuItem(menu, 'centralbox', url, () => openNewTab(url));
    });
    // Correlated hashes without a centralbox verdict: look them up from here,
    // like from the hash menu of the log they are in.
    const targets = CENTRALBOX_LOOKUPS_ON ? correlationLookupTargets(items) : [];
    const spot = () => ({ anchor: trigger, line: trigger.correlationLine || '' });
    targets.forEach((target) => {
        const which = targets.length > 1 ? ' ' + target.short : (target.file ? ' of ' + target.file : '');
        if (CENTRALBOX_CHECK_URL) {
            addCorrelationMenuItem(menu, 'centralbox', 'check this hash' + which,
                () => checkCorrelatedHash(target, spot()));
        }
        if (CENTRALBOX_FRESH_URL && CENTRALBOX_FRESH_STATUS_URL) {
            addCorrelationMenuItem(menu, 'centralbox', 'run fresh lookup' + which,
                () => freshLookupCorrelatedHash(target, spot()));
        }
    });

    menu.hidden = false;
    if (correlationMenuTrigger && correlationMenuTrigger !== trigger) {
        correlationMenuTrigger.setAttribute('aria-expanded', 'false');
    }
    correlationMenuTrigger = trigger;
    trigger.setAttribute('aria-expanded', 'true');

    const rect = trigger.getBoundingClientRect();
    const menuWidth = menu.offsetWidth || 320;
    const menuHeight = menu.offsetHeight || 0;
    let left = rect.right - menuWidth;
    if (left < 8) left = Math.max(8, rect.left);
    if (left + menuWidth > window.innerWidth - 8) left = window.innerWidth - menuWidth - 8;
    let top = rect.bottom + 4;
    if (top + menuHeight > window.innerHeight - 8) top = Math.max(8, rect.top - menuHeight - 4);
    menu.style.left = `${left + window.scrollX}px`;
    menu.style.top = `${top + window.scrollY}px`;
}

// The "correlations" section of the line inspector (the ? mode's box): the
// same findings as the line's ⓘ menu, each opening that log at the line (or,
// for the loaded log itself, jumping to the line here).
function renderLineInspectorCorrelations(entry) {
    const section = document.getElementById('lineInspectorCorrelationsSection');
    const summary = document.getElementById('lineInspectorCorrelationsSummary');
    const list = document.getElementById('lineInspectorCorrelations');
    if (!section || !summary || !list) return;
    const items = caseCorrelationsFor(entry);
    list.innerHTML = '';
    summary.innerHTML = '';
    section.hidden = items.length === 0;
    if (!items.length) return;

    const status = caseCorrelationStatusFor(entry);
    summary.appendChild(document.createTextNode(correlationHeader(items)));
    if (status && typeof buildStatusSymbolNode === 'function') {
        summary.appendChild(document.createTextNode(' - worst finding: '));
        summary.appendChild(buildStatusSymbolNode(status));
    }

    const fromLine = typeof entry.line === 'string' ? entry.line.trim() : '';
    correlationRows(items).forEach((item) => {
        const row = document.createElement('li');
        const classes = [`line-correlation-system-${item.system || 'unknown'}`];
        if (['b', 'p', 'g', 'w'].includes(item.severity)) classes.push(`line-correlation-sev-${item.severity}`);
        if (item.centralbox && item.centralbox.verdict === 'malicious') classes.push('line-correlation-bad');
        row.className = classes.join(' ');
        const link = document.createElement('a');
        link.className = 'line-inspector-correlation-source';
        link.textContent = correlationSource(item);
        if (isOwnCorrelation(item)) {
            link.href = '#';
            link.title = 'go to the line in this log';
            link.addEventListener('click', (event) => {
                event.preventDefault();
                closeLineInspectorModal({ restoreFocus: false });
                jumpToAnalyzerLine(Number(item.anchor_line_no || item.line_no), null, fromLine);
            });
        } else {
            const url = correlationLogUrl(item);
            if (url) {
                link.href = url;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                link.title = 'open that log at the line';
            }
        }
        const finding = document.createElement('span');
        finding.className = 'line-inspector-correlation-finding';
        finding.textContent = correlationFinding(item);
        row.append(link, document.createTextNode(': '), finding);
        list.appendChild(row);
    });
    correlationReportUrls(items).forEach((url) => {
        const row = document.createElement('li');
        row.appendChild(document.createTextNode('centralbox: '));
        const link = document.createElement('a');
        link.href = url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.textContent = url;
        row.appendChild(link);
        list.appendChild(row);
    });
}

function isValidCorrelation(item) {
    return item && typeof item === 'object'
        && ['hash', 'detection', 'fixlog'].includes(item.kind)
        && typeof item.upload_id === 'string' && typeof item.log_type === 'string';
}

// Fetch the correlations for the loaded upload, then redraw the rows.
async function refreshCaseCorrelations(uploadId) {
    const id = String(uploadId || '').trim();
    if (id !== caseCorrelationsUploadId) {
        caseCorrelations = new Map();
        caseCorrelationsUploadId = id;
    }
    if (!id || !CASE_CORRELATIONS_URL) return;
    let body = null;
    try {
        const url = `${CASE_CORRELATIONS_URL}?upload_id=${encodeURIComponent(id)}`;
        const response = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
        if (!response.ok) return;
        body = await response.json();
    } catch (error) {
        return;
    }
    if (!body || typeof body !== 'object' || id !== caseCorrelationsUploadId) return;
    caseCorrelationsScope = body.scope === 'user' || body.scope === 'case' ? body.scope : '';
    caseCorrelationsName = typeof body.name === 'string' ? body.name : '';
    const raw = body.correlations && typeof body.correlations === 'object' ? body.correlations : {};
    const rawStatuses = body.statuses && typeof body.statuses === 'object' ? body.statuses : {};
    const previousStatuses = JSON.stringify([...caseCorrelationStatuses]);
    // A lookup's answer can change the icon without changing the status.
    const previousLookups = JSON.stringify(correlationLookupLines());
    caseCorrelationStatuses = new Map(
        Object.keys(rawStatuses)
            .filter((line) => typeof rawStatuses[line] === 'string' && CORRELATION_STATUS_CLASS[rawStatuses[line]])
            .map((line) => [line.trim(), rawStatuses[line]]),
    );
    const next = new Map();
    Object.keys(raw).forEach((line) => {
        const items = Array.isArray(raw[line]) ? raw[line].filter(isValidCorrelation) : [];
        if (line.trim() && items.length) next.set(line.trim(), items);
    });
    const keysChanged = next.size !== caseCorrelations.size
        || [...next.keys()].some((line) => !caseCorrelations.has(line));
    caseCorrelations = next;
    const changed = keysChanged
        || previousStatuses !== JSON.stringify([...caseCorrelationStatuses])
        || previousLookups !== JSON.stringify(correlationLookupLines());
    if (changed && typeof renderLogLines === 'function' && analyzedLines.length) {
        try {
            renderLogLines();
            // The legend's "correlated (n)" filter (speech_suggestions.js).
            if (typeof renderRuleTagsLine === 'function') renderRuleTagsLine(lastAnalysisPayload);
        } catch (error) {
            // Never let correlations break the analyzer.
        }
    }
}
