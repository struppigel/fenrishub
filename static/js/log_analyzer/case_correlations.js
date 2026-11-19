// Case correlations (fixlist/case_correlations.py): an FRST / Addition line
// whose file also appears in another log of the same infection case gets an
// info icon. Clicking it opens the info box (static/js/correlation_info.js)
// with everything those logs say about the file: hashes and centralbox
// results (with check / fresh lookup), detections, fixlist results, file
// facts and activity from Spor, FRST Search and Shortcut logs. Read-only;
// nothing here changes a line's status.
//
// Everything is optional: without correlations, on any error or for guests
// the analyzer looks exactly as before.

const CASE_CORRELATIONS_URL = analyzerConfig.caseCorrelationsUrl || '';

let caseCorrelations = new Map();
// Line text -> the worst related finding as a line-verdict status letter
// (computed by the server with the line-verdict precedence).
let caseCorrelationStatuses = new Map();
let caseCorrelationsUploadId = '';
// 'case': the helper's own cases with this log; 'user': no such case, so the
// other logs of the same forum user (caseCorrelationsName).
let caseCorrelationsScope = '';
let caseCorrelationsName = '';

function caseCorrelationsFor(entry) {
    if (!entry || typeof entry.line !== 'string') return [];
    return caseCorrelations.get(entry.line.trim()) || [];
}

// The wording of findings, sources and links is shared with the uploaded log
// page (static/js/correlation_format.js).
function correlationFinding(item) {
    return CorrelationFormat.finding(item);
}

function correlationSource(item) {
    return CorrelationFormat.source(item, isOwnCorrelation);
}

function correlationRows(items) {
    return CorrelationFormat.rows(items, isOwnCorrelation);
}

function correlationReportUrls(items) {
    return CorrelationFormat.reportUrls(items);
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

// A short note right in front of the line's ⓘ icon, on its row: why a jump
// from the info box to a line of this log did not work (not found, hidden
// by the legend filter). A redraw replaces the icon, so the icon is found
// again by its line; without one the note goes away. `spot` is {anchor,
// line}; `done` lets the note fade after a moment. (Lookups report in the
// info box itself, correlation_info.js.)
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

// Distinct file hashes of the entries with the file each belongs to, for the
// line's copy and search menus (analysis.js): [{hash, file}].
function correlationHashValues(items) {
    return CorrelationFormat.hashValues(items);
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
    return CorrelationFormat.header(items, isOwnCorrelation, {
        scope: caseCorrelationsScope, name: caseCorrelationsName,
    });
}

const CORRELATION_STATUS_CLASS = CorrelationFormat.STATUS_CLASS;

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
        button.setAttribute('aria-haspopup', 'dialog');
        button.setAttribute('aria-label', lookup
            ? 'what other logs say about this file; a hash can be looked up on centralbox'
            : 'what other logs say about this file');
        button.title = correlationHeader(items) + ':\n' + correlationSummary(items)
            + (lookup ? '\n(a hash without centralbox verdict: look it up from the info box)' : '');
        button.addEventListener('click', (event) => {
            event.stopPropagation();
            openCorrelationInfo(entry, button);
        });
        return button;
    } catch (error) {
        return null;
    }
}

function correlationLogUrl(item) {
    return CorrelationFormat.logUrl(item);
}

// The analyzer row (index into analyzedLines) of a line of the loaded log,
// numbered like the server and the log page (content.split('\n') from 1),
// or -1. The analyzer leaves out blank lines (see computeBlankLineGaps).
function analyzerIndexForLogLine(lineNo, lineText = '') {
    const input = document.getElementById('logInput');
    const lines = (input ? input.value : '').split('\n');
    // The textarea turns a lone CR into a line break, so its numbering can
    // run ahead of the server's: the row is checked against the line's text
    // (from the server when known) and else searched near the estimate.
    let index = -1;
    let text = typeof lineText === 'string' ? lineText.trim() : '';
    if (Number.isInteger(lineNo) && lineNo >= 1 && lineNo <= lines.length) {
        if (!text) text = (lines[lineNo - 1].split(SPLITLINES_BOUNDARY)[0] || '').trim();
        index = 0;
        lines.slice(0, lineNo - 1).join('\n').split(SPLITLINES_BOUNDARY).forEach((piece) => {
            if (piece.trim()) index += 1;
        });
    }
    if (!text) return -1;
    if (index >= 0 && analyzedLines[index] && analyzedLines[index].line === text) return index;
    let best = -1;
    analyzedLines.forEach((entry, candidate) => {
        if (!entry || entry.line !== text) return;
        if (best < 0 || Math.abs(candidate - index) < Math.abs(best - index)) best = candidate;
    });
    return best;
}

// Scroll the analyzer to a line of the loaded log and mark it for a moment
// (the mark fades out, as on the log page).
const CORRELATION_FLASH_MS = 2500;
let correlationFlashTimer = null;

function jumpToAnalyzerLine(lineNo, trigger, fromLine = '', lineText = '') {
    const index = analyzerIndexForLogLine(lineNo, lineText);
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

// The info box for one analyzer row (correlation_info.js): everything the
// other logs say about the line's files, with links and centralbox lookups.
// It reads the line's entries again after a lookup refreshed them.
function openCorrelationInfo(entry, trigger) {
    if (typeof CorrelationInfo !== 'object' || !entry || typeof entry.line !== 'string') return;
    const lineText = entry.line.trim();
    CorrelationInfo.open({
        lineText,
        getEntries: () => caseCorrelations.get(lineText) || [],
        isOwn: isOwnCorrelation,
        scope: caseCorrelationsScope,
        name: caseCorrelationsName,
        status: caseCorrelationStatusFor(entry),
        onJump: (lineNo, item) => jumpToAnalyzerLine(Number(lineNo), trigger, lineText, item && item.line_text),
        lookup: { canLookup: CENTRALBOX_LOOKUPS_ON, urls: CENTRALBOX_LOOKUP_URLS },
        refresh: () => refreshCaseCorrelations(caseCorrelationsUploadId),
        trigger,
    });
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
    // The full picture (file facts, activity, lookups) is in the info box.
    if (typeof CorrelationInfo === 'object') {
        const more = document.createElement('button');
        more.type = 'button';
        more.className = 'line-inspector-correlation-more';
        more.textContent = 'show everything other logs say';
        more.addEventListener('click', () => openCorrelationInfo(entry, more));
        summary.appendChild(document.createTextNode(' '));
        summary.appendChild(more);
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
                jumpToAnalyzerLine(Number(item.anchor_line_no || item.line_no), null, fromLine, item.line_text);
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
        && ['hash', 'detection', 'fixlog', 'evidence', 'file_info', 'mention'].includes(item.kind)
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
