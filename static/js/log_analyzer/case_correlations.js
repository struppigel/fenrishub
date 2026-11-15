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

function correlationFinding(item) {
    if (item.kind === 'fixlog') return item.result || 'fixlist result';
    const result = item.centralbox && typeof item.centralbox === 'object' ? item.centralbox : null;
    // A bare hash (no detection, no centralbox result) shows the hash itself.
    const name = (result && (result.family || result.malware_type)) || item.detection || correlationHash(item);
    const verdict = result && result.verdict ? 'centralbox: ' + result.verdict
        : result && result.state === 'unknown' ? 'not in centralbox' : '';
    // A detection of a folder this line's file is in.
    const where = item.in_folder ? 'in detected folder' : '';
    return [name, verdict, where].filter(Boolean).join(CORRELATION_DOT) || (item.kind === 'hash' ? 'file hash' : 'detection');
}

// The log type a finding comes from, flagged when that log seems to come
// from another system.
function correlationSource(item) {
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
const CENTRALBOX_FRESH_POLL_MS = 4000;
const CENTRALBOX_FRESH_POLL_TRIES = 30;

// Correlated hashes without a centralbox verdict (never checked, or not in
// centralbox): [{hash, uploadId, short}]. The endpoints accept a hash only
// together with a log that contains it: the related log of the entry.
function correlationLookupTargets(items) {
    const targets = [];
    const seen = new Set();
    items.forEach((item) => {
        if (!item || item.kind !== 'hash') return;
        const result = item.centralbox && typeof item.centralbox === 'object' ? item.centralbox : null;
        if (result && result.report_url) return;  // known: the report entry covers it
        const sha = typeof item.sha256 === 'string' && /^[0-9a-f]{64}$/.test(item.sha256) ? item.sha256 : '';
        const md5 = typeof item.md5 === 'string' && /^[0-9a-f]{32}$/.test(item.md5) ? item.md5 : '';
        const hash = sha || md5;
        const uploadId = String(item.upload_id || '');
        if (!hash || seen.has(hash) || !/^[A-Za-z0-9_-]+$/.test(uploadId)) return;
        seen.add(hash);
        targets.push({ hash, uploadId, short: (sha ? 'SHA-256 ' : 'MD5 ') + hash.slice(0, 12) + '…' });
    });
    return targets;
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
    // Only while the icon is inside the visible part of the log list: a line
    // scrolled out of it would put the label over the rest of the page.
    const area = anchor.closest('#logLines');
    if (area) {
        const box = area.getBoundingClientRect();
        if (rect.bottom <= box.top || rect.top >= box.bottom || rect.right <= box.left || rect.left >= box.right) {
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

function centralboxVerdictText(verdict) {
    if (!verdict || typeof verdict !== 'object') return '';
    if (verdict.state === 'unknown') return 'not in centralbox';
    if (verdict.verdict === 'malicious') return 'centralbox: ' + (verdict.family || verdict.malware_type || 'malicious');
    return verdict.verdict ? 'centralbox: ' + verdict.verdict : '';
}

async function postCentralbox(url, payload) {
    try {
        const response = await fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
                'X-CSRFToken': getCookie('csrftoken'),
            },
            body: JSON.stringify(payload),
        });
        let body = null;
        try {
            body = await response.json();
        } catch (error) {
            body = null;
        }
        return { status: response.status, body };
    } catch (error) {
        return { status: 0, body: null };
    }
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
    correlationHint(spot, 'centralbox: checking…');
    const { status, body } = await postCentralbox(CENTRALBOX_CHECK_URL, { sha256: target.hash, upload_id: target.uploadId });
    let message = 'centralbox: the check failed, try again later';
    if (status === 200 && body && typeof body === 'object') {
        message = centralboxVerdictText(body.verdict)
            || (body.unknown ? 'not in centralbox'
                : body.available ? 'centralbox: no answer yet, try again later' : 'centralbox is not available right now');
    }
    await finishCorrelationLookup(spot, message);
}

async function freshLookupCorrelatedHash(target, spot) {
    correlationHint(spot, 'centralbox: starting a fresh lookup…');
    const { status, body } = await postCentralbox(CENTRALBOX_FRESH_URL, { sha256: target.hash, upload_id: target.uploadId });
    if (status !== 200 || !body || body.ok !== true) {
        const message = body && typeof body.message === 'string' && body.message ? body.message : 'the lookup could not be started';
        await finishCorrelationLookup(spot, 'centralbox: ' + message, false);
        return;
    }
    if (body.state !== 'running') {
        await finishCorrelationLookup(spot, centralboxVerdictText(body.verdict) || 'centralbox: ' + body.state);
        return;
    }
    correlationHint(spot, 'centralbox: looking up…');
    const url = CENTRALBOX_FRESH_STATUS_URL.replace('0'.repeat(64), encodeURIComponent(target.hash));
    for (let attempt = 0; attempt < CENTRALBOX_FRESH_POLL_TRIES; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, CENTRALBOX_FRESH_POLL_MS));
        let state = null;
        try {
            const response = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
            state = response.ok ? await response.json() : null;
        } catch (error) {
            state = null;
        }
        if (state && typeof state === 'object' && state.state && state.state !== 'running') {
            const text = state.state === 'error'
                ? 'centralbox: the lookup failed, try again after the cooldown'
                : centralboxVerdictText(state.verdict) || (state.state === 'not_found' ? 'not in centralbox' : 'centralbox: done');
            await finishCorrelationLookup(spot, text);
            return;
        }
    }
    await finishCorrelationLookup(spot, 'centralbox: still running; reload the analysis later', false);
}

function correlationSummary(items) {
    return correlationRows(items).map((item) => `${correlationSource(item)}: ${correlationFinding(item)}`).join('\n');
}

function correlationHeader() {
    return caseCorrelationsScope === 'user'
        ? `same file in other logs of user ${caseCorrelationsName} (no case of yours)`
        : 'same file in other logs of this case';
}

const CORRELATION_STATUS_CLASS = {
    B: 'b', P: 'p', C: 'c', A: 'a', '!': 'w', G: 'g', S: 's', I: 'i', J: 'j',
};

function caseCorrelationStatusFor(entry) {
    if (!entry || typeof entry.line !== 'string') return '';
    return caseCorrelationStatuses.get(entry.line.trim()) || '';
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
        button.textContent = 'ⓘ';
        button.setAttribute('aria-haspopup', 'menu');
        button.setAttribute('aria-expanded', 'false');
        button.setAttribute('aria-label', 'what other logs of this case say about this file');
        button.title = correlationHeader() + ':\n' + correlationSummary(items);
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
    header.textContent = correlationHeader();
    menu.appendChild(header);

    // Clicking a row opens that log at the line (its id is never shown).
    correlationRows(items).forEach((item) => {
        const classes = ['line-correlation-source', `line-correlation-system-${item.system || 'unknown'}`];
        if (['b', 'p', 'g', 'w'].includes(item.severity)) classes.push(`line-correlation-sev-${item.severity}`);
        if (item.centralbox && item.centralbox.verdict === 'malicious') classes.push('line-correlation-bad');
        addCorrelationMenuItem(menu, correlationSource(item), correlationFinding(item),
            () => openNewTab(correlationLogUrl(item)), classes.join(' '));
    });
    // The centralbox report of each correlated hash, shown as its URL like
    // the hash menus' VirusTotal entry.
    correlationReportUrls(items).forEach((url) => {
        addCorrelationMenuItem(menu, 'centralbox', url, () => openNewTab(url));
    });
    // Correlated hashes without a centralbox verdict: look them up from here,
    // like from the hash menu of the log they are in.
    const targets = correlationLookupTargets(items);
    const spot = () => ({ anchor: trigger, line: trigger.correlationLine || '' });
    targets.forEach((target) => {
        const which = targets.length > 1 ? ' ' + target.short : '';
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
    caseCorrelationsScope = body.scope === 'user' ? 'user' : 'case';
    caseCorrelationsName = typeof body.name === 'string' ? body.name : '';
    const raw = body.correlations && typeof body.correlations === 'object' ? body.correlations : {};
    const rawStatuses = body.statuses && typeof body.statuses === 'object' ? body.statuses : {};
    const previousStatuses = JSON.stringify([...caseCorrelationStatuses]);
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
    const changed = next.size !== caseCorrelations.size
        || [...next.keys()].some((line) => !caseCorrelations.has(line))
        || previousStatuses !== JSON.stringify([...caseCorrelationStatuses]);
    caseCorrelations = next;
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
