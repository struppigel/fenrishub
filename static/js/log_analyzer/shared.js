let analyzedLines = [];
let copiedLineIndexes = new Set();
const EDITABLE_STATUSES = ['B', 'P', 'C', '!', 'G', 'S', 'J', '?'];
const STATUS_CLASS_MAP = {
    B: 'status-b',
    P: 'status-p',
    C: 'status-c',
    '!': 'status-w',
    G: 'status-g',
    S: 'status-s',
    I: 'status-i',
    J: 'status-j',
    '?': 'status-unknown',
};
const STATUS_LABEL_MAP = {
    B: 'malware',
    P: 'potentially unwanted',
    C: 'clean',
    '!': 'warning',
    G: 'grayware',
    S: 'security',
    I: 'informational',
    J: 'junk',
    '?': 'unknown',
};
const STATUS_PRECEDENCE_ORDER = ['B', 'P', 'C', '!', 'G', 'S', 'I', 'J', '?'];
const PENDING_STATUS_STORAGE_KEY = 'fenrishub_pending_status_changes';
const CONFLICT_RESOLUTION_STORAGE_KEY = 'fenrishub_conflict_resolutions';
const CONFLICT_ACTION_UPDATE_EXISTING = 'update_existing_status';
const CONFLICT_ACTION_KEEP_BOTH = 'keep_both';
const CONFLICT_ACTION_KEEP_NEW_DISABLE_OTHER = 'keep_new_disable_other';
const CONFLICT_ACTION_DISCARD_NEW = 'discard_new';
const analyzerConfig = window.logAnalyzerConfig || {};
const ANALYZE_LOG_URL = analyzerConfig.analyzeLogUrl || '';
const LINE_DETAILS_URL = analyzerConfig.lineDetailsUrl || '';
const PREVIEW_RULE_CHANGES_URL = analyzerConfig.previewRuleChangesUrl || '';
const PERSIST_RULE_CHANGES_URL = analyzerConfig.persistRuleChangesUrl || '';
const CREATE_FIXLIST_URL = analyzerConfig.createFixlistUrl || '';
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
    updateSaveChangesButtonState();
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
        };
    });
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
}