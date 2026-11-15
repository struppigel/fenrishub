// centralbox case suggestions (fixlist/views/centralbox.py): an FRST line whose
// file has a malicious SHA-256 in another log of the same infection case gets a
// "suggested B" chip. Clicking it only queues an ordinary pending status change
// (with a prefilled rule description); the analyst still confirms it through
// the usual rule preview. Nothing is applied by itself.
//
// Everything here is optional. Without suggestions, on any error, for guests
// or with centralbox down, the analyzer looks exactly as before.

const CENTRALBOX_SUGGESTIONS_URL = analyzerConfig.centralboxSuggestionsUrl || '';
const CENTRALBOX_DOT = ' · ';

let centralboxSuggestions = new Map();
let centralboxSuggestionsUploadId = '';
let centralboxSuggestionsRetry = null;

function centralboxSuggestionFor(entry) {
    if (!entry || typeof entry.line !== 'string') return null;
    return centralboxSuggestions.get(entry.line.trim()) || null;
}

// What the related log says, without log ids, hashes or paths: verdict,
// family (or malware type), the detection name and the log type.
function centralboxSuggestionFinding(suggestion) {
    const source = suggestion.source || {};
    const parts = [`centralbox: ${suggestion.family || suggestion.malware_type || 'malicious'} (malicious)`];
    if (source.detection) parts.push(source.detection);
    if (source.log_type) parts.push(`found in ${source.log_type}`);
    return parts;
}

function centralboxSuggestionDescription(suggestion) {
    return centralboxSuggestionFinding(suggestion).join(', ');
}

function centralboxSuggestionTooltip(suggestion, currentStatus) {
    const lines = centralboxSuggestionFinding(suggestion);
    if (currentStatus && currentStatus !== '?') {
        lines.push(`the rules say ${currentStatus}; click to queue B instead`);
    } else {
        lines.push('click to queue B for this line');
    }
    return lines.join('\n');
}

// The chip for one analyzer row, or null. B lines get none.
function buildCentralboxSuggestionChip(entry, index) {
    try {
        const suggestion = centralboxSuggestionFor(entry);
        if (!suggestion) return null;
        const status = entry.dominant_status || '?';
        if (status === 'B') return null;
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.className = 'centralbox-suggestion-chip';
        const conflict = status !== '?';
        if (conflict) chip.classList.add('centralbox-suggestion-conflict');
        chip.textContent = conflict
            ? `rule: ${status}${CENTRALBOX_DOT}centralbox: malicious`
            : `suggested B${suggestion.family ? CENTRALBOX_DOT + suggestion.family : ''}`;
        chip.title = centralboxSuggestionTooltip(suggestion, status);
        chip.addEventListener('click', (event) => {
            event.stopPropagation();
            acceptCentralboxSuggestion(index, suggestion);
        });
        return chip;
    } catch (error) {
        return null;
    }
}

async function acceptCentralboxSuggestion(index, suggestion) {
    if (typeof saveStatusSelection !== 'function') return;
    await saveStatusSelection(index, 'B');
    try {
        const entry = analyzedLines[index];
        const key = entry ? pendingOverrideKeyForEntry(entry, index) : null;
        const change = key ? pendingStatusChanges.get(key) : null;
        if (change && change.new_status === 'B' && !ruleDescriptionOverrides.has(String(change.id))) {
            ruleDescriptionOverrides.set(String(change.id), centralboxSuggestionDescription(suggestion));
            if (typeof scheduleDraftSave === 'function') scheduleDraftSave();
        }
    } catch (error) {
        // The status change itself is queued; only the description is missing.
    }
}

function isValidCentralboxSuggestion(item) {
    return item && typeof item === 'object'
        && typeof item.line === 'string' && item.line.trim()
        && typeof item.sha256 === 'string' && /^[0-9a-f]{64}$/.test(item.sha256)
        && item.verdict === 'malicious';
}

// Fetch the suggestions for the loaded upload, then redraw the rows. A second
// request follows once if some of the case's hashes were still being looked up.
async function refreshCentralboxSuggestions(uploadId, attempt = 0) {
    if (centralboxSuggestionsRetry) {
        clearTimeout(centralboxSuggestionsRetry);
        centralboxSuggestionsRetry = null;
    }
    const id = String(uploadId || '').trim();
    if (id !== centralboxSuggestionsUploadId) {
        centralboxSuggestions = new Map();
        centralboxSuggestionsUploadId = id;
    }
    if (!id || !CENTRALBOX_SUGGESTIONS_URL) return;
    let body = null;
    try {
        const url = `${CENTRALBOX_SUGGESTIONS_URL}?upload_id=${encodeURIComponent(id)}`;
        const response = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
        if (!response.ok) return;
        body = await response.json();
    } catch (error) {
        return;
    }
    if (!body || typeof body !== 'object' || id !== centralboxSuggestionsUploadId) return;
    const next = new Map();
    (Array.isArray(body.suggestions) ? body.suggestions : []).forEach((item) => {
        if (isValidCentralboxSuggestion(item)) next.set(item.line.trim(), item);
    });
    const changed = next.size !== centralboxSuggestions.size
        || [...next.keys()].some((line) => !centralboxSuggestions.has(line));
    centralboxSuggestions = next;
    if (changed && typeof renderLogLines === 'function' && analyzedLines.length) {
        try {
            renderLogLines();
        } catch (error) {
            // Never let suggestions break the analyzer.
        }
    }
    if (body.available === true && Number(body.pending) > 0 && attempt < 1) {
        centralboxSuggestionsRetry = setTimeout(() => refreshCentralboxSuggestions(id, attempt + 1), 20000);
    }
}
