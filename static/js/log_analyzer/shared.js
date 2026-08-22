let analyzedLines = [];
let copiedLineIndexes = new Set();
const EDITABLE_STATUSES = ['B', 'P', 'C', '!', 'G', 'S', 'J', '?'];
const STATUS_CLASS_MAP = {
    B: 'status-b',
    P: 'status-p',
    C: 'status-c',
    '!': 'status-w',
    A: 'status-a',
    G: 'status-g',
    S: 'status-s',
    I: 'status-i',
    J: 'status-j',
    '?': 'status-unknown',
};
const HIDE_CLASS_PREFIX = 'hide-';
const hiddenStatuses = new Set();
const ALL_LEGEND_STATUS_CLASSES = Object.values(STATUS_CLASS_MAP);
const STATUS_LABEL_MAP = {
    B: 'malware',
    P: 'potentially unwanted',
    C: 'clean',
    '!': 'warning',
    A: 'alert',
    G: 'grayware',
    S: 'security',
    I: 'informational',
    J: 'junk',
    '?': 'unknown',
};
const STATUS_PRECEDENCE_ORDER = ['B', 'P', 'C', 'A', '!', 'G', 'S', 'I', 'J', '?'];
const MATCH_TYPE_LABEL_MAP = {
    exact: 'Exact line',
    parsed: 'Parsed',
    filepath: 'File path',
    substring: 'Substring',
    regex: 'Regex',
};
const PENDING_STATUS_STORAGE_KEY = 'fenrishub_pending_status_changes';
const CONFLICT_RESOLUTION_STORAGE_KEY = 'fenrishub_conflict_resolutions';
const CONFLICT_ACTION_UPDATE_EXISTING = 'update_existing_status';
const CONFLICT_ACTION_KEEP_BOTH = 'keep_both';
const CONFLICT_ACTION_KEEP_NEW_DISABLE_OTHER = 'keep_new_disable_other';
const CONFLICT_ACTION_DISCARD_NEW = 'discard_new';
const analyzerConfig = window.logAnalyzerConfig || {};
const GUEST_TOKEN = analyzerConfig.guestToken || '';

function withGuestToken(url) {
    if (!GUEST_TOKEN || !url) {
        return url;
    }
    const separator = url.indexOf('?') === -1 ? '?' : '&';
    return `${url}${separator}guest=${encodeURIComponent(GUEST_TOKEN)}`;
}

const ANALYZE_LOG_URL = withGuestToken(analyzerConfig.analyzeLogUrl || '');
const LINE_DETAILS_URL = withGuestToken(analyzerConfig.lineDetailsUrl || '');
const PREVIEW_RULE_CHANGES_URL = analyzerConfig.previewRuleChangesUrl || '';
const PERSIST_RULE_CHANGES_URL = analyzerConfig.persistRuleChangesUrl || '';
const CREATE_FIXLIST_URL = analyzerConfig.createFixlistUrl || '';
const EDIT_FIXLIST_ID = analyzerConfig.initialFixlistId || '';
const CURRENT_USERNAME = analyzerConfig.currentUsername || '';
const UPLOAD_LINK_HELPER_BASE = analyzerConfig.uploadLinkHelperBase || '';
const UPLOAD_LINK_GENERAL = analyzerConfig.uploadLinkGeneral || '';

// The forum username of the upload currently loaded in the analyzer. Set from
// the upload content payload; cleared when the selection is cleared, so one
// case's user never bleeds into the next case's reply.
let currentForumUsername = '';

function setCurrentForumUsername(name) {
    currentForumUsername = String(name === null || name === undefined ? '' : name).trim();
}

// {COUNTER} numbers steps across the whole reply, not per speech, so several
// speeches inserted one after another compose into a single numbered list.
// Reset when the response is emptied (see the speech menu's transform) and
// carried in the analyzer draft so a restored half-written reply keeps counting
// from where it left off instead of repeating numbers.
const COUNTER_TOKEN = '{COUNTER}';
let speechCounter = 0;

function resetSpeechCounter() {
    speechCounter = 0;
}

function getSpeechCounter() {
    return speechCounter;
}

function setSpeechCounter(value) {
    const parsed = Number(value);
    speechCounter = Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 0;
}

// Speeches carry placeholders that are resolved the moment one is inserted into
// the response panel — {USERNAME} depends on which upload is loaded right now,
// so this cannot be done server-side. Mirrors copyFrstFixMessage() in
// view_fixlist.html: a split/join global replace, no regex escaping needed.
//
// A token with no value is deliberately left in the text. A visible {USERNAME}
// is a prompt to fill it in; a silent "Hi ," or a link missing its ?u= is a
// message you send without noticing.
function applySpeechPlaceholders(text) {
    // ?u= prefills the forum-username field on the upload form. It works on both
    // the per-helper and the general route (see upload_log_view).
    const prefilled = (base) =>
        `${base}?u=${encodeURIComponent(currentForumUsername)}`;

    const replacements = {};
    if (CURRENT_USERNAME) {
        replacements['{HELPERNAME}'] = CURRENT_USERNAME;
    }
    if (currentForumUsername) {
        replacements['{USERNAME}'] = currentForumUsername;
    }
    if (UPLOAD_LINK_HELPER_BASE) {
        replacements['{UPLOADLINK_HELPER}'] = UPLOAD_LINK_HELPER_BASE;
        if (currentForumUsername) {
            replacements['{UPLOADLINK_HELPER_PREFILLED}'] = prefilled(UPLOAD_LINK_HELPER_BASE);
        }
    }
    if (UPLOAD_LINK_GENERAL) {
        replacements['{UPLOADLINK_GENERAL}'] = UPLOAD_LINK_GENERAL;
        if (currentForumUsername) {
            replacements['{UPLOADLINK_GENERAL_PREFILLED}'] = prefilled(UPLOAD_LINK_GENERAL);
        }
    }

    // Note the closing brace is part of each token, so {UPLOADLINK_HELPER} is
    // not a substring of {UPLOADLINK_HELPER_PREFILLED} and replacement order
    // cannot corrupt the longer name. test_speech_placeholders.html locks this in.
    let result = String(text === null || text === undefined ? '' : text);

    // Counted first, so it numbers only what the speech's author wrote — a
    // {COUNTER} arriving via some other placeholder's value stays literal, the
    // same way substituted values are never rescanned for further tokens.
    const segments = result.split(COUNTER_TOKEN);
    if (segments.length > 1) {
        result = segments.reduce((acc, segment) => `${acc}${++speechCounter}${segment}`);
    }

    Object.keys(replacements).forEach((token) => {
        result = result.split(token).join(replacements[token]);
    });
    return result;
}

const RULE_SUBMIT_TARGET_CREATE_FIXLIST = 'create_fixlist';
const RULE_SUBMIT_TARGET_RESCAN = 'rescan';
let statusPickerBusy = false;
let pendingStatusChanges = new Map();
let pendingChangeSequence = 0;
let ruleDescriptionOverrides = new Map();
let removedRuleCandidateIds = new Set();
let expandedRuleCandidateId = null;
let ruleSubmitTarget = RULE_SUBMIT_TARGET_CREATE_FIXLIST;
let conflictWizardState = {
    queue: [],
    index: 0,
    resolutions: {},
    discardedRuleIds: new Set(),
};

const DATE_CLUSTER_TOLERANCE_MS = 10 * 60 * 1000;
const DATE_CLUSTER_STATUS_TO_BUCKET = { B: 'b', P: 'p', '!': 'w' };
let dateClusters = {
    b: { days: new Set(), stamps: [] },
    p: { days: new Set(), stamps: [] },
    w: { days: new Set(), stamps: [] },
};

function parseFrstDate(str) {
    if (typeof str !== 'string') {
        return null;
    }
    const trimmed = str.trim();
    const match = /^(\d{4})-(\d{2})-(\d{2})(?:\s+(\d{2}):(\d{2})(?::(\d{2}))?)?$/.exec(trimmed);
    if (!match) {
        return null;
    }
    const [, y, mo, d, h, mi, s] = match;
    const ymd = `${y}-${mo}-${d}`;
    if (h === undefined) {
        return { ymd, epochMs: null };
    }
    const epochMs = Date.UTC(
        Number(y),
        Number(mo) - 1,
        Number(d),
        Number(h),
        Number(mi),
        s !== undefined ? Number(s) : 0,
    );
    return { ymd, epochMs };
}

function recomputeDateClusters() {
    const next = {
        b: { days: new Set(), stamps: [] },
        p: { days: new Set(), stamps: [] },
        w: { days: new Set(), stamps: [] },
    };
    for (const entry of analyzedLines) {
        const bucketKey = DATE_CLUSTER_STATUS_TO_BUCKET[entry.dominant_status];
        if (!bucketKey) continue;
        const dates = Array.isArray(entry.dates) ? entry.dates : [];
        for (const raw of dates) {
            const parsed = parseFrstDate(raw);
            if (!parsed) continue;
            if (parsed.epochMs === null) continue;
            next[bucketKey].days.add(parsed.ymd);
            next[bucketKey].stamps.push({ ymd: parsed.ymd, epochMs: parsed.epochMs });
        }
    }
    dateClusters = next;
}

function classifyDateAgainstClusters(parsed) {
    if (!parsed) return null;
    for (const bucketKey of ['b', 'p', 'w']) {
        const bucket = dateClusters[bucketKey];
        if (parsed.epochMs !== null) {
            for (const seed of bucket.stamps) {
                if (seed.ymd === parsed.ymd
                    && Math.abs(seed.epochMs - parsed.epochMs) <= DATE_CLUSTER_TOLERANCE_MS) {
                    return bucketKey;
                }
            }
        } else if (bucket.days.has(parsed.ymd)) {
            return bucketKey;
        }
    }
    return null;
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return parts.pop().split(';').shift();
    }
    return '';
}

function safeParseJson(input, fallback) {
    try {
        return JSON.parse(input);
    } catch (error) {
        return fallback;
    }
}

function recomputePendingChangeSequence() {
    let maxSequence = 0;
    pendingStatusChanges.forEach((change) => {
        const orderValue = Number(change && change.order);
        const idValue = Number(change && change.id);
        if (Number.isFinite(orderValue)) {
            maxSequence = Math.max(maxSequence, orderValue);
        }
        if (Number.isFinite(idValue)) {
            maxSequence = Math.max(maxSequence, idValue);
        }
    });
    pendingChangeSequence = maxSequence;
}

function normalizePendingChangesForCurrentLines() {
    if (!pendingStatusChanges.size || !analyzedLines.length) {
        return;
    }

    const availableLineKeys = new Set(analyzedLines.map((entry) => pendingOverrideKeyForEntry(entry)));
    const normalizedPending = new Map();
    pendingStatusChanges.forEach((change, key) => {
        const changeLine = change && typeof change.line === 'string' ? change.line : key;
        if (!availableLineKeys.has(changeLine)) {
            return;
        }
        normalizedPending.set(changeLine, {
            ...change,
            line: changeLine,
        });
    });

    pendingStatusChanges = normalizedPending;
    recomputePendingChangeSequence();

    const validChangeIds = new Set(
        [...pendingStatusChanges.values()].map((change) => String(change && change.id))
    );
    [...ruleDescriptionOverrides.keys()].forEach((changeId) => {
        if (!validChangeIds.has(String(changeId))) {
            ruleDescriptionOverrides.delete(changeId);
        }
    });
}

// Replace [start, end) in a textarea while keeping the browser's own undo
// history intact.
//
// Writing to .value directly is invisible to that history, which is why a bulk
// insert used to be un-undoable: Ctrl+Z had nothing to take back and the analyst
// had to delete the lines by hand. Going through execCommand makes the edit look
// like typing, so one call becomes exactly one undo step (and one redo step),
// and the 'input' event that fires keeps the copied-line highlighting and the
// draft autosave in sync for free.
function applyTextareaEdit(textarea, start, end, replacement) {
    if (!textarea) {
        return false;
    }
    const before = textarea.value;
    const expected = before.substring(0, start) + replacement + before.substring(end);
    if (expected === before) {
        return true;
    }

    textarea.focus();
    textarea.setSelectionRange(start, end);

    let accepted = false;
    try {
        accepted = replacement
            ? document.execCommand('insertText', false, replacement)
            : document.execCommand('delete');
    } catch (e) {
        accepted = false;
    }
    if (accepted && textarea.value === expected) {
        return true;
    }

    // The engine refused the command (or applied it differently than asked).
    // Falling back to a plain write costs the undo step but never loses the edit.
    textarea.value = expected;
    const caret = start + replacement.length;
    textarea.setSelectionRange(caret, caret);
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
    return false;
}

function initializeCursorPosition() {
    const textarea = document.getElementById('selectedLines');
    const text = textarea.value;
    const marker = 'CloseProcesses:';
    const markerIndex = text.indexOf(marker);

    if (markerIndex !== -1) {
        const lineEndIndex = text.indexOf('\n', markerIndex);
        const cursorPos = lineEndIndex !== -1 ? lineEndIndex + 1 : markerIndex + marker.length;
        textarea.selectionStart = textarea.selectionEnd = cursorPos;
    }
}

function updateSaveChangesButtonState() {
    const saveChangesButton = document.getElementById('saveRulesRescanButton');
    const hasPendingChanges = pendingStatusChanges.size > 0;
    if (saveChangesButton) {
        saveChangesButton.classList.toggle('has-pending-changes', hasPendingChanges);
    }

    const bannerStatisticsEl = document.getElementById('bannerStatistics');
    if (bannerStatisticsEl && bannerStatisticsEl.textContent) {
        bannerStatisticsEl.textContent = bannerStatisticsEl.textContent.replace(
            /pending status changes: \d+/,
            `pending status changes: ${pendingStatusChanges.size}`
        );
    }
}

function updateSummary(summary, fallbackTotal = 0) {
    const totalLines = Number(summary.total_lines || fallbackTotal);
    const matchedLines = Number(summary.matched_lines || 0);
    const unknownLines = Number(summary.unknown_lines || 0);
    const pendingChanges = pendingStatusChanges.size;
    const summaryEl = document.getElementById('analysisSummary');
    const bannerStatisticsEl = document.getElementById('bannerStatistics');
    const legendEl = document.getElementById('statusLegend');
    const summaryText = `lines: ${totalLines}, matched: ${matchedLines}, unknown: ${unknownLines}, pending status changes: ${pendingChanges}`;
    
    if (summaryEl) {
        summaryEl.textContent = summaryText;
    }
    if (bannerStatisticsEl) {
        bannerStatisticsEl.textContent = summaryText;
        bannerStatisticsEl.style.display = totalLines > 0 ? 'block' : 'none';
    }
    if (legendEl) {
        legendEl.hidden = false;
    }
    updateLegendCounts();
    updateSaveChangesButtonState();
}

function updateLegendCounts() {
    const counts = Object.create(null);
    analyzedLines.forEach((line) => {
        // css_class is presentational (a fallback-only match stays 'status-unknown'
        // so the whole line isn't coloured). The verdict is dominant_status — count
        // by that so the legend agrees with the uploads count, the matched summary,
        // and the bulk buttons.
        const cls = STATUS_CLASS_MAP[line.dominant_status] || 'status-unknown';
        counts[cls] = (counts[cls] || 0) + 1;
    });
    document.querySelectorAll('.legend-item[data-status-class]').forEach((item) => {
        const countEl = item.querySelector('.legend-count');
        if (!countEl) {
            return;
        }
        const cls = item.dataset.statusClass;
        const count = counts[cls] || 0;
        countEl.textContent = `(${count})`;
    });
}

function summarizeEffectiveStatuses(lines) {
    let matchedLines = 0;
    let unknownLines = 0;

    lines.forEach((line) => {
        const status = line.dominant_status || '?';
        if (status === '?') {
            unknownLines += 1;
        } else {
            matchedLines += 1;
        }
    });

    return {
        total_lines: lines.length,
        matched_lines: matchedLines,
        unknown_lines: unknownLines,
    };
}

function attachLineKeys(lines) {
    const seenByLine = new Map();
    return lines.map((entry) => {
        const lineText = entry.line || '';
        const nextCount = (seenByLine.get(lineText) || 0) + 1;
        seenByLine.set(lineText, nextCount);

        const baseStatus = entry.dominant_status || '?';
        const baseReasons = Array.isArray(entry.reasons) ? [...entry.reasons] : [];

        return {
            ...entry,
            _lineKey: `${lineText}::${nextCount}`,
            _lineTextKey: lineText,
            _baseDominantStatus: baseStatus,
            _baseStatusCodes: entry.status_codes || baseStatus,
            _baseCssClass: entry.css_class || STATUS_CLASS_MAP[baseStatus] || 'status-unknown',
            _baseStatusLabel: entry.status_label || STATUS_LABEL_MAP[baseStatus] || 'unknown',
            _baseReasons: baseReasons,
            _baseFilepathHighlight: entry.filepath_highlight || null,
        };
    });
}

function pendingOverrideKeyForEntry(entry, fallbackIndex = 0) {
    if (entry && typeof entry._lineTextKey === 'string') {
        return entry._lineTextKey;
    }
    if (entry && typeof entry.line === 'string') {
        return entry.line;
    }
    return entry && entry._lineKey ? entry._lineKey : `line::${fallbackIndex}`;
}

function applyPendingOverrides() {
    analyzedLines = analyzedLines.map((entry) => {
        const baseStatus = entry._baseDominantStatus || entry.dominant_status || '?';
        const baseReasons = Array.isArray(entry._baseReasons) ? [...entry._baseReasons] : [];
        const pending = pendingStatusChanges.get(pendingOverrideKeyForEntry(entry));

        if (!pending) {
            return {
                ...entry,
                dominant_status: baseStatus,
                status_codes: entry._baseStatusCodes || baseStatus,
                css_class: entry._baseCssClass || STATUS_CLASS_MAP[baseStatus] || 'status-unknown',
                status_label: entry._baseStatusLabel || STATUS_LABEL_MAP[baseStatus] || 'unknown',
                reasons: baseReasons,
                matched: baseStatus !== '?',
                filepath_highlight: entry._baseFilepathHighlight || null,
            };
        }

        const overrideStatus = pending.new_status;
        return {
            ...entry,
            dominant_status: overrideStatus,
            status_codes: overrideStatus,
            css_class: STATUS_CLASS_MAP[overrideStatus] || 'status-unknown',
            status_label: STATUS_LABEL_MAP[overrideStatus] || 'unknown',
            reasons: [...baseReasons, `manual override: ${pending.original_status} -> ${pending.new_status}`],
            matched: overrideStatus !== '?',
            filepath_highlight: null,
        };
    });
    recomputeDateClusters();
}

function getPendingStatusChangesPayload() {
    return [...pendingStatusChanges.values()]
        .sort((left, right) => left.order - right.order)
        .map((change) => {
            const payload = {
                id: change.id,
                line: change.line,
                original_status: change.original_status,
                new_status: change.new_status,
                order: change.order,
            };

            const changeId = String(change.id);
            if (ruleDescriptionOverrides.has(changeId)) {
                payload.description = ruleDescriptionOverrides.get(changeId);
            }

            return payload;
        });
}

function applyAnalysisPayload(payload, options = {}) {
    const nextLines = Array.isArray(payload.lines) ? payload.lines : [];
    const shouldResetCopied = Boolean(options.resetCopied);
    const preservePendingChanges = Boolean(options.preservePendingChanges);
    const keyedLines = attachLineKeys(nextLines);

    if (shouldResetCopied) {
        copiedLineIndexes = new Set();
        if (!preservePendingChanges) {
            pendingStatusChanges.clear();
            pendingChangeSequence = 0;
            ruleDescriptionOverrides.clear();
            removedRuleCandidateIds.clear();
            expandedRuleCandidateId = null;
        }
    } else if (nextLines.length !== analyzedLines.length) {
        copiedLineIndexes = new Set();
        if (!preservePendingChanges) {
            pendingStatusChanges.clear();
            pendingChangeSequence = 0;
            ruleDescriptionOverrides.clear();
            removedRuleCandidateIds.clear();
            expandedRuleCandidateId = null;
        }
    } else {
        copiedLineIndexes = new Set(
            [...copiedLineIndexes].filter((index) => index >= 0 && index < nextLines.length)
        );
    }

    analyzedLines = keyedLines;
    if (preservePendingChanges) {
        normalizePendingChangesForCurrentLines();
    }
    applyPendingOverrides();
    renderWarnings(payload.warnings || []);
    updateSummary(summarizeEffectiveStatuses(analyzedLines), analyzedLines.length);
    closeStatusPicker();
    renderLogLines();
}

function setRuleSubmitTarget(nextTarget) {
    if (nextTarget !== RULE_SUBMIT_TARGET_RESCAN) {
        ruleSubmitTarget = RULE_SUBMIT_TARGET_CREATE_FIXLIST;
        return;
    }
    ruleSubmitTarget = RULE_SUBMIT_TARGET_RESCAN;
}

function clearPendingAnalyzerChanges() {
    pendingStatusChanges.clear();
    pendingChangeSequence = 0;
    ruleDescriptionOverrides.clear();
    removedRuleCandidateIds.clear();
    expandedRuleCandidateId = null;
    updateSaveChangesButtonState();
    // These changes are now real rules, so the draft must stop offering them back.
    if (typeof flushDraftSave === 'function') {
        flushDraftSave();
    }
}