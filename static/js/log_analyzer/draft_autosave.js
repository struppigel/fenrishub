// Autosave / restore for in-progress analyzer work.
//
// Nothing the analyst does between "load log" and "save fix" reaches the server:
// the fixlist lives in the #selectedLines textarea, the reply to the user lives in
// #responseText (which has no server-side home at all), and every manual
// reclassification lives in the pendingStatusChanges Map. Closing the tab used to
// destroy all of it. This module mirrors that state into localStorage on a debounce
// and offers it back on the next visit.
//
// localStorage only, by design: it covers the accidental-tab-close case, and it is
// the only option that also works for anonymous and guest sessions, which have no
// server-side identity at all.

const DRAFT_KEY_PREFIX = 'fenrishub_analyzer_draft:';
const DRAFT_INDEX_KEY = 'fenrishub_analyzer_drafts_index';
const DRAFT_SCHEMA_VERSION = 1;
const DRAFT_DEBOUNCE_MS = 1200;
const DRAFT_INTERVAL_MS = 10000;
const DRAFT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const DRAFT_MAX_ENTRIES = 5;
// FRST logs are large and localStorage is ~5 MB. Above this we drop the raw log
// text from the draft and restore statuses onto a re-pasted log instead.
const DRAFT_MAX_LOG_INPUT_CHARS = 1500000;

let draftSaveTimer = null;
let draftIntervalTimer = null;
let draftLastFingerprint = '';
let draftInitialSelectedLines = '';
let draftInitialResponseText = '';
let draftRestorePending = false;
let draftUnloadGuardBound = false;
let suppressUnloadGuard = false;

// Windows textareas report CRLF while server-seeded content uses LF; comparing
// them raw makes every freshly loaded page look dirty.
function normalizeDraftNewlines(text) {
    return String(text === null || text === undefined ? '' : text).replace(/\r\n/g, '\n');
}

function hashDraftText(text) {
    const value = normalizeDraftNewlines(text);
    let hash = 0x811c9dc5;
    for (let index = 0; index < value.length; index++) {
        hash ^= value.charCodeAt(index);
        hash = Math.imul(hash, 0x01000193);
    }
    return `${(hash >>> 0).toString(16)}-${value.length}`;
}

function readDraftStorage(key) {
    try {
        return localStorage.getItem(key);
    } catch (e) {
        return null;
    }
}

function writeDraftStorage(key, value) {
    try {
        localStorage.setItem(key, value);
        return true;
    } catch (e) {
        return false;
    }
}

function removeDraftStorage(key) {
    try {
        localStorage.removeItem(key);
    } catch (e) {
        // Storage disabled or full; nothing useful to do.
    }
}

function readDraftIndex() {
    const raw = readDraftStorage(DRAFT_INDEX_KEY);
    if (!raw) {
        return {};
    }
    try {
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (e) {
        return {};
    }
}

function writeDraftIndex(index) {
    writeDraftStorage(DRAFT_INDEX_KEY, JSON.stringify(index));
}

function draftIndexEntries(index) {
    return Object.keys(index)
        .map((key) => ({ key, meta: index[key] || {} }))
        .sort((left, right) => Number(right.meta.savedAt || 0) - Number(left.meta.savedAt || 0));
}

// Drop expired drafts and anything past the retention count. Runs on init and
// again whenever a write hits the quota.
function pruneDraftIndex(now) {
    const index = readDraftIndex();
    const cutoff = now - DRAFT_MAX_AGE_MS;
    const survivors = {};

    draftIndexEntries(index).forEach((entry, position) => {
        const savedAt = Number(entry.meta.savedAt || 0);
        if (savedAt < cutoff || position >= DRAFT_MAX_ENTRIES) {
            removeDraftStorage(entry.key);
            return;
        }
        survivors[entry.key] = entry.meta;
    });

    writeDraftIndex(survivors);
    return survivors;
}

function getCurrentUploadId() {
    const uploadSelect = document.getElementById('uploadSourceSelect');
    const selected = uploadSelect ? String(uploadSelect.value || '').trim() : '';
    if (selected) {
        return selected;
    }
    return String(analyzerConfig.initialUploadId || '').trim();
}

function buildDraftKey(uploadId, fixlistId, logInput) {
    if (uploadId) {
        const fixlistSuffix = fixlistId ? `:f:${fixlistId}` : '';
        return `${DRAFT_KEY_PREFIX}u:${uploadId}${fixlistSuffix}`;
    }
    return `${DRAFT_KEY_PREFIX}h:${hashDraftText(logInput)}`;
}

function getCurrentDraftKey() {
    const logInput = document.getElementById('logInput');
    return buildDraftKey(
        getCurrentUploadId(),
        EDIT_FIXLIST_ID,
        logInput ? logInput.value : '',
    );
}

function serializeRuleDescriptionOverrides() {
    return [...ruleDescriptionOverrides.entries()].map(([id, description]) => [String(id), String(description)]);
}

function buildDraftPayload(now) {
    const logInputEl = document.getElementById('logInput');
    const selectedLinesEl = document.getElementById('selectedLines');
    const responseTextEl = document.getElementById('responseText');
    const logLinesEl = document.getElementById('logLines');
    const logInputValue = logInputEl ? logInputEl.value : '';
    const uploadId = getCurrentUploadId();

    const payload = {
        v: DRAFT_SCHEMA_VERSION,
        savedAt: now,
        uploadId,
        fixlistId: EDIT_FIXLIST_ID || '',
        logInputHash: hashDraftText(logInputValue),
        selectedLines: selectedLinesEl ? selectedLinesEl.value : '',
        responseText: responseTextEl ? responseTextEl.value : '',
        speechCounter: getSpeechCounter(),
        pendingStatusChanges: [...pendingStatusChanges.entries()],
        pendingChangeSequence,
        ruleDescriptionOverrides: serializeRuleDescriptionOverrides(),
        hiddenStatuses: [...hiddenStatuses],
        scrollTop: logLinesEl ? logLinesEl.scrollTop : 0,
    };

    // With an upload selected the log text is refetchable from the content API,
    // so storing it would burn quota for nothing.
    if (!uploadId && logInputValue.length <= DRAFT_MAX_LOG_INPUT_CHARS) {
        payload.logInput = logInputValue;
    }

    return payload;
}

function draftFingerprint() {
    const logInputEl = document.getElementById('logInput');
    const selectedLinesEl = document.getElementById('selectedLines');
    const responseTextEl = document.getElementById('responseText');
    return [
        pendingStatusChanges.size,
        pendingChangeSequence,
        ruleDescriptionOverrides.size,
        hiddenStatuses.size,
        logInputEl ? logInputEl.value.length : 0,
        selectedLinesEl ? selectedLinesEl.value.length : 0,
        responseTextEl ? responseTextEl.value.length : 0,
    ].join('|');
}

// True when there is analyst work that only exists in the browser.
function hasUnsavedAnalyzerWork() {
    if (pendingStatusChanges.size > 0) {
        return true;
    }
    // The response is never written to the server, so any text in it at all is
    // work that only the draft can preserve.
    const responseTextEl = document.getElementById('responseText');
    if (responseTextEl && normalizeDraftNewlines(responseTextEl.value) !== draftInitialResponseText) {
        return true;
    }
    const selectedLinesEl = document.getElementById('selectedLines');
    if (!selectedLinesEl) {
        return false;
    }
    return normalizeDraftNewlines(selectedLinesEl.value) !== draftInitialSelectedLines;
}

function persistDraftPayload(key, payload) {
    const now = Number(payload.savedAt);
    if (writeDraftStorage(key, JSON.stringify(payload))) {
        return true;
    }

    // Quota hit: shed old drafts and retry once.
    pruneDraftIndex(now);
    if (writeDraftStorage(key, JSON.stringify(payload))) {
        return true;
    }

    // Last resort — keep only the irreplaceable parts.
    const minimal = {
        v: DRAFT_SCHEMA_VERSION,
        savedAt: now,
        uploadId: payload.uploadId,
        fixlistId: payload.fixlistId,
        logInputHash: payload.logInputHash,
        selectedLines: payload.selectedLines,
        responseText: payload.responseText,
        speechCounter: payload.speechCounter,
        pendingStatusChanges: payload.pendingStatusChanges,
        pendingChangeSequence: payload.pendingChangeSequence,
        ruleDescriptionOverrides: payload.ruleDescriptionOverrides,
        hiddenStatuses: [],
        scrollTop: 0,
        partial: true,
    };
    return writeDraftStorage(key, JSON.stringify(minimal));
}

function saveDraftNow() {
    // The draft mirrors current state, so work being undone (or rules being
    // persisted) must drop it rather than leave it stale. The exception is an
    // unanswered restore prompt: clearing there would delete the very draft
    // being offered.
    if (!hasUnsavedAnalyzerWork()) {
        if (!draftRestorePending) {
            clearDraft();
        }
        return;
    }

    const now = new Date().getTime();
    const key = getCurrentDraftKey();
    const payload = buildDraftPayload(now);

    if (!persistDraftPayload(key, payload)) {
        return;
    }

    const index = readDraftIndex();
    index[key] = {
        savedAt: now,
        uploadId: payload.uploadId,
        fixlistId: payload.fixlistId,
    };
    writeDraftIndex(index);
    draftLastFingerprint = draftFingerprint();
}

function scheduleDraftSave() {
    if (draftSaveTimer !== null) {
        clearTimeout(draftSaveTimer);
    }
    draftSaveTimer = setTimeout(() => {
        draftSaveTimer = null;
        saveDraftNow();
    }, DRAFT_DEBOUNCE_MS);
}

function flushDraftSave() {
    if (draftSaveTimer !== null) {
        clearTimeout(draftSaveTimer);
        draftSaveTimer = null;
    }
    saveDraftNow();
}

// Safety net for mutations that forgot to call scheduleDraftSave().
function startDraftInterval() {
    if (draftIntervalTimer !== null) {
        return;
    }
    draftIntervalTimer = setInterval(() => {
        if (draftFingerprint() !== draftLastFingerprint) {
            saveDraftNow();
        }
    }, DRAFT_INTERVAL_MS);
}

function clearDraft() {
    const key = getCurrentDraftKey();
    removeDraftStorage(key);
    const index = readDraftIndex();
    if (Object.prototype.hasOwnProperty.call(index, key)) {
        delete index[key];
        writeDraftIndex(index);
    }
}

// Called just before the fixlist form POSTs. The draft is kept rather than
// deleted so a failed submit is still recoverable, but flagged so it stops
// being offered.
function markDraftSubmitted() {
    const key = getCurrentDraftKey();
    const raw = readDraftStorage(key);
    if (!raw) {
        return;
    }
    try {
        const payload = JSON.parse(raw);
        payload.submittedAt = new Date().getTime();
        writeDraftStorage(key, JSON.stringify(payload));
    } catch (e) {
        removeDraftStorage(key);
    }
}

function readDraftAt(key) {
    const raw = readDraftStorage(key);
    if (!raw) {
        return null;
    }
    try {
        const payload = JSON.parse(raw);
        if (!payload || payload.v !== DRAFT_SCHEMA_VERSION || payload.submittedAt) {
            return null;
        }
        return payload;
    } catch (e) {
        return null;
    }
}

function draftIsWorthOffering(payload) {
    if (!payload) {
        return false;
    }
    const changeCount = Array.isArray(payload.pendingStatusChanges) ? payload.pendingStatusChanges.length : 0;
    if (changeCount > 0) {
        return true;
    }
    if (normalizeDraftNewlines(payload.responseText).trim().length > 0) {
        return true;
    }
    return normalizeDraftNewlines(payload.selectedLines) !== draftInitialSelectedLines;
}

// With an upload loaded the key is exact. A pasted-log session has an empty
// #logInput on load, so its own key is unreachable — fall back to the most
// recent upload-less draft.
function findRestorableDraft() {
    const uploadId = getCurrentUploadId();
    if (uploadId) {
        const key = getCurrentDraftKey();
        const payload = readDraftAt(key);
        return draftIsWorthOffering(payload) ? { key, payload } : null;
    }

    const index = readDraftIndex();
    const candidates = draftIndexEntries(index).filter((entry) => !entry.meta.uploadId);
    for (const entry of candidates) {
        const payload = readDraftAt(entry.key);
        if (draftIsWorthOffering(payload)) {
            return { key: entry.key, payload };
        }
    }
    return null;
}

function formatDraftTimestamp(savedAt) {
    const saved = new Date(Number(savedAt) || 0);
    const time = saved.toTimeString().slice(0, 5);
    const isToday = saved.toDateString() === new Date().toDateString();
    return isToday ? `today ${time}` : `${saved.toDateString()} ${time}`;
}

function describeDraft(payload) {
    const changeCount = Array.isArray(payload.pendingStatusChanges) ? payload.pendingStatusChanges.length : 0;
    const fixlistLineCount = normalizeDraftNewlines(payload.selectedLines)
        .split('\n')
        .filter((segment) => segment.trim().length > 0).length;

    const details = [
        `${changeCount} status change${changeCount === 1 ? '' : 's'}`,
        `${fixlistLineCount} fixlist line${fixlistLineCount === 1 ? '' : 's'}`,
    ];

    // Only worth mentioning when there is one; most drafts have no response.
    const responseChars = normalizeDraftNewlines(payload.responseText).trim().length;
    if (responseChars > 0) {
        details.push(`a response of ${responseChars} character${responseChars === 1 ? '' : 's'}`);
    }

    return `Draft from ${formatDraftTimestamp(payload.savedAt)} - ${details.join(', ')}.`;
}

function dismissDraftPrompt() {
    const container = document.getElementById('analyzerDraftPrompt');
    if (container) {
        container.innerHTML = '';
        container.hidden = true;
    }
}

// Rendered into its own container rather than #analysisWarnings, which
// renderWarnings() clears on every analysis.
function renderDraftPrompt(payload, onRestore, onDiscard) {
    const container = document.getElementById('analyzerDraftPrompt');
    if (!container) {
        return;
    }
    container.innerHTML = '';

    const promptElement = document.createElement('div');
    promptElement.className = 'analysis-warning';

    const headerElement = document.createElement('div');
    headerElement.className = 'analysis-warning-header';

    const titleElement = document.createElement('div');
    titleElement.className = 'analysis-warning-title';
    titleElement.textContent = 'Unsaved analyzer draft';

    const closeButton = document.createElement('button');
    closeButton.type = 'button';
    closeButton.className = 'analysis-warning-close';
    closeButton.setAttribute('aria-label', 'Close draft prompt');
    closeButton.textContent = 'x';
    closeButton.addEventListener('click', () => dismissDraftPrompt());

    headerElement.appendChild(titleElement);
    headerElement.appendChild(closeButton);
    promptElement.appendChild(headerElement);

    const messageElement = document.createElement('div');
    messageElement.className = 'analysis-warning-message';
    messageElement.textContent = describeDraft(payload);
    promptElement.appendChild(messageElement);

    const logInputEl = document.getElementById('logInput');
    const currentLog = logInputEl ? logInputEl.value : '';
    if (currentLog.trim() && payload.logInputHash && payload.logInputHash !== hashDraftText(currentLog)) {
        const mismatchElement = document.createElement('div');
        mismatchElement.className = 'analysis-warning-message';
        mismatchElement.textContent = 'The loaded log differs from the one this draft was made against; status changes that no longer match a line will be dropped.';
        promptElement.appendChild(mismatchElement);
    }

    const actionsElement = document.createElement('div');
    actionsElement.className = 'analysis-warning-actions';

    const restoreButton = document.createElement('button');
    restoreButton.type = 'button';
    restoreButton.textContent = 'restore';
    restoreButton.addEventListener('click', () => onRestore());

    const discardButton = document.createElement('button');
    discardButton.type = 'button';
    discardButton.textContent = 'discard';
    discardButton.addEventListener('click', () => onDiscard());

    actionsElement.appendChild(restoreButton);
    actionsElement.appendChild(discardButton);
    promptElement.appendChild(actionsElement);

    container.appendChild(promptElement);
    container.hidden = false;
}

function hydratePendingStateFromDraft(payload) {
    const entries = Array.isArray(payload.pendingStatusChanges) ? payload.pendingStatusChanges : [];
    pendingStatusChanges = new Map(
        entries.filter((entry) => Array.isArray(entry) && entry.length === 2),
    );
    pendingChangeSequence = Number(payload.pendingChangeSequence) || 0;

    const overrides = Array.isArray(payload.ruleDescriptionOverrides) ? payload.ruleDescriptionOverrides : [];
    ruleDescriptionOverrides = new Map(
        overrides.filter((entry) => Array.isArray(entry) && entry.length === 2),
    );

    recomputePendingChangeSequence();
    if (pendingChangeSequence < Number(payload.pendingChangeSequence || 0)) {
        pendingChangeSequence = Number(payload.pendingChangeSequence);
    }
}

// syncCopiedIndexesWithTextarea() only prunes; after a reload copiedLineIndexes is
// empty, so the "copied" highlighting has to be rebuilt from the restored text.
function restoreCopiedIndexesFromTextarea() {
    const textarea = document.getElementById('selectedLines');
    if (!textarea || !analyzedLines.length) {
        return;
    }
    const presentLines = new Set(
        normalizeDraftNewlines(textarea.value).split('\n').filter((segment) => segment.length > 0),
    );
    analyzedLines.forEach((entry, index) => {
        const line = fixlistTextForEntry(entry);
        if (line && presentLines.has(line)) {
            copiedLineIndexes.add(index);
            setCopiedState(index, true);
        }
    });
}

function restoreHiddenStatuses(payload) {
    const stored = Array.isArray(payload.hiddenStatuses) ? payload.hiddenStatuses : [];
    stored.forEach((statusClass) => {
        if (statusClass && !hiddenStatuses.has(statusClass)) {
            toggleStatusVisibility(statusClass);
        }
    });
}

async function restoreDraft(key, payload) {
    const logInputEl = document.getElementById('logInput');
    const currentLog = logInputEl ? logInputEl.value : '';
    const hasLoadedLog = Boolean(currentLog.trim());
    const matchesLoadedLog = !payload.logInputHash || payload.logInputHash === hashDraftText(currentLog);
    const canSupplyOwnLog = typeof payload.logInput === 'string' && payload.logInput.length > 0;

    // A draft carries the fixlist for the log it was made against. Grafting one
    // machine's remediation onto another's is the worst thing this feature could
    // do, so a mismatch is never resolved silently.
    if (hasLoadedLog && !matchesLoadedLog) {
        const message = canSupplyOwnLog
            ? 'This draft was made against a different log. Restore it and replace the currently loaded log?'
            : 'This draft was made against a different log, and that log was too large to store. Restore its fixlist and status changes onto the currently loaded log anyway?';
        if (!confirm(message)) {
            return;
        }
    }

    dismissDraftPrompt();

    if (canSupplyOwnLog && logInputEl && (!hasLoadedLog || !matchesLoadedLog)) {
        logInputEl.value = payload.logInput;
        await parseLogs();
    }

    hydratePendingStateFromDraft(payload);
    normalizePendingChangesForCurrentLines();
    applyPendingOverrides();
    updateSummary(summarizeEffectiveStatuses(analyzedLines), analyzedLines.length);
    renderLogLines();

    const selectedLinesEl = document.getElementById('selectedLines');
    if (selectedLinesEl && typeof payload.selectedLines === 'string') {
        selectedLinesEl.value = payload.selectedLines;
        restoreCopiedIndexesFromTextarea();
    }

    const responseTextEl = document.getElementById('responseText');
    if (responseTextEl && typeof payload.responseText === 'string') {
        responseTextEl.value = payload.responseText;
    }
    // Keep numbering going where the restored reply left off.
    setSpeechCounter(payload.speechCounter);

    restoreHiddenStatuses(payload);

    const logLinesEl = document.getElementById('logLines');
    if (logLinesEl && Number(payload.scrollTop) > 0) {
        logLinesEl.scrollTop = Number(payload.scrollTop);
    }

    updateSaveChangesButtonState();
    draftRestorePending = false;
    draftLastFingerprint = draftFingerprint();
}

function discardDraft(key) {
    dismissDraftPrompt();
    removeDraftStorage(key);
    const index = readDraftIndex();
    if (Object.prototype.hasOwnProperty.call(index, key)) {
        delete index[key];
        writeDraftIndex(index);
    }
    draftRestorePending = false;
}

function bindDraftUnloadGuard() {
    if (draftUnloadGuardBound) {
        return;
    }
    draftUnloadGuardBound = true;
    const flush = () => flushDraftSave();

    window.addEventListener('pagehide', flush);
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
            flush();
        }
    });

    window.addEventListener('beforeunload', (event) => {
        if (suppressUnloadGuard || !hasUnsavedAnalyzerWork()) {
            return;
        }
        flushDraftSave();
        event.preventDefault();
        event.returnValue = '';
    });
}

function setSuppressUnloadGuard(value) {
    suppressUnloadGuard = Boolean(value);
}

// Called from bootstrap's DOMContentLoaded, after initializePendingStatusChanges()
// so the restored Map cannot be wiped, and after the initial upload has loaded.
function initDraftAutosave() {
    const selectedLinesEl = document.getElementById('selectedLines');
    draftInitialSelectedLines = normalizeDraftNewlines(selectedLinesEl ? selectedLinesEl.value : '');
    const responseTextEl = document.getElementById('responseText');
    draftInitialResponseText = normalizeDraftNewlines(responseTextEl ? responseTextEl.value : '');
    draftLastFingerprint = draftFingerprint();

    pruneDraftIndex(new Date().getTime());
    bindDraftUnloadGuard();
    startDraftInterval();
}

function offerDraftRestore() {
    const found = findRestorableDraft();
    if (!found) {
        return;
    }
    draftRestorePending = true;
    renderDraftPrompt(
        found.payload,
        () => restoreDraft(found.key, found.payload),
        () => discardDraft(found.key),
    );
}
