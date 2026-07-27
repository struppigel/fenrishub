function bindAnalyzerButton(elementId, handler) {
    const element = document.getElementById(elementId);
    if (!element) {
        return;
    }

    element.addEventListener('click', (event) => {
        event.preventDefault();
        handler(event);
    });
}

const _uploadContentCache = new Map();

// Console-style loading indicator, defined in js/status_spinner.js (loaded from
// base.html) so the log search page can use the same one.
const startStatusSpinner = window.startStatusSpinner;

function buildUploadedLogContentUrl(uploadId) {
    const template = (window.logAnalyzerConfig && window.logAnalyzerConfig.uploadedLogContentUrlTemplate) || '';
    if (!template || !uploadId) {
        return '';
    }
    return template.replace('__UPLOAD_ID__', encodeURIComponent(uploadId));
}

function buildCachedAnalysisUrl(uploadId) {
    const template = (window.logAnalyzerConfig && window.logAnalyzerConfig.cachedAnalysisUrlTemplate) || '';
    if (!template || !uploadId) {
        return '';
    }
    return template.replace('__UPLOAD_ID__', encodeURIComponent(uploadId));
}

async function fetchCachedAnalysisPayload(uploadId) {
    const url = buildCachedAnalysisUrl(uploadId);
    if (!url) {
        return null;
    }
    try {
        const response = await fetch(url, {
            method: 'GET',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
        });
        if (!response.ok) {
            return null;
        }
        const data = await response.json();
        return data && data.has_cache ? data.payload : null;
    } catch (error) {
        return null;
    }
}

function showCachedAnalysisLayout() {
    const logInputElement = document.getElementById('logInput');
    const logLinesElement = document.getElementById('logLines');
    const parseButton = document.getElementById('parseButton');
    const resetButton = document.getElementById('resetButton');
    if (logInputElement) logInputElement.style.display = 'none';
    if (logLinesElement) logLinesElement.style.display = 'block';
    if (parseButton) parseButton.style.display = 'none';
    if (resetButton) resetButton.style.display = 'inline-flex';
}

async function loadSelectedUploadForAnalyzer() {
    const selectElement = document.getElementById('uploadSourceSelect');
    const statusElement = document.getElementById('uploadLoadStatus');
    const logInputElement = document.getElementById('logInput');
    if (!selectElement || !statusElement || !logInputElement) {
        return;
    }

    const uploadId = (selectElement.value || '').trim();
    if (!uploadId) {
        statusElement.textContent = '';
        const url = new URL(window.location);
        url.searchParams.delete('upload_id');
        window.history.replaceState(null, '', url);
        return;
    }

    const requestUrl = buildUploadedLogContentUrl(uploadId);
    if (!requestUrl) {
        statusElement.textContent = 'unable to resolve upload endpoint';
        return;
    }

    let stopSpinner = startStatusSpinner(statusElement, 'loading');

    let contentPayload = _uploadContentCache.get(uploadId);
    if (!contentPayload) {
        try {
            const response = await fetch(requestUrl, {
                method: 'GET',
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
            });
            if (!response.ok) {
                throw new Error(`Request failed: ${response.status}`);
            }
            contentPayload = await response.json();
            _uploadContentCache.set(uploadId, contentPayload);
        } catch (error) {
            stopSpinner();
            statusElement.textContent = 'failed to load upload';
            return;
        }
    }

    // For uploads the user doesn't normally have in their dropdown (e.g.
    // another helper's log loaded by direct URL), loadInitialUploadForAnalyzer
    // injects a placeholder option with " | loading...". Update it now that
    // we know the upload's metadata, so it doesn't say "loading" forever.
    const placeholderOption = [...selectElement.options].find(
        (option) => option.value === uploadId,
    );
    if (placeholderOption) {
        const parts = [
            contentPayload.upload_id || uploadId,
            contentPayload.original_filename,
            contentPayload.forum_username,
        ].filter((part) => part && String(part).trim().length > 0);
        placeholderOption.textContent = parts.join(' | ');
    }

    if (typeof resetToInput === 'function') {
        resetToInput();
    }
    logInputElement.value = contentPayload.content || '';
    const url = new URL(window.location);
    url.searchParams.set('upload_id', uploadId);
    window.history.replaceState(null, '', url);
    logInputElement.focus();

    const hasContent = Boolean(logInputElement.value.trim());
    let cachedAnalysisApplied = false;
    if (hasContent && typeof applyAnalysisPayload === 'function') {
        const cachedAnalysis = await fetchCachedAnalysisPayload(uploadId);
        if (cachedAnalysis) {
            applyAnalysisPayload(cachedAnalysis, { resetCopied: true });
            showCachedAnalysisLayout();
            stopSpinner();
            stopSpinner = startStatusSpinner(
                statusElement,
                `loaded ${contentPayload.upload_id} — refreshing analysis`,
            );
            cachedAnalysisApplied = true;
        }
    }

    if (!cachedAnalysisApplied) {
        stopSpinner();
        stopSpinner = () => {};
        statusElement.textContent = `loaded ${contentPayload.upload_id}`;
    }

    if (hasContent && typeof parseLogs === 'function') {
        try {
            await parseLogs();
        } finally {
            stopSpinner();
            statusElement.textContent = `loaded ${contentPayload.upload_id}`;
        }
    } else {
        stopSpinner();
    }
}

async function loadInitialUploadForAnalyzer() {
    const config = window.logAnalyzerConfig || {};
    const initialUploadId = (config.initialUploadId || '').trim();
    if (!initialUploadId) {
        return;
    }

    const selectElement = document.getElementById('uploadSourceSelect');
    if (!selectElement) {
        return;
    }

    if (![...selectElement.options].some((option) => option.value === initialUploadId)) {
        const option = document.createElement('option');
        option.value = initialUploadId;
        option.textContent = `${initialUploadId} | loading...`;
        selectElement.appendChild(option);
    }

    selectElement.value = initialUploadId;

    // Reveal the row up-front so the cached-analysis paint doesn't get
    // pushed down by a late layout shift when the background re-scan finishes.
    const uploadSourceRow = document.getElementById('uploadSourceRow');
    if (uploadSourceRow) {
        uploadSourceRow.hidden = false;
    }

    await loadSelectedUploadForAnalyzer();
}

function initializePendingStatusChanges() {
    sessionStorage.removeItem(PENDING_STATUS_STORAGE_KEY);
    pendingStatusChanges = new Map();
    pendingChangeSequence = 0;
    recomputePendingChangeSequence();
    updateSaveChangesButtonState();
}

const modalTriggerElements = {
    lineInspectorModal: null,
    ruleReviewModal: null,
    conflictWizardModal: null,
};

function isVisibleElement(element) {
    return Boolean(element) && !element.hidden && element.getClientRects().length > 0;
}

function getModalDialogElement(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) {
        return null;
    }
    return modal.querySelector('[role="dialog"]');
}

function getFocusableElements(container) {
    if (!container) {
        return [];
    }

    return [...container.querySelectorAll(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )].filter((element) => !element.hidden && element.getClientRects().length > 0);
}

function getActiveModalId() {
    const lineInspectorModal = document.getElementById('lineInspectorModal');
    if (lineInspectorModal && !lineInspectorModal.hidden) {
        return 'lineInspectorModal';
    }

    const conflictWizardModal = document.getElementById('conflictWizardModal');
    if (conflictWizardModal && !conflictWizardModal.hidden) {
        return 'conflictWizardModal';
    }

    const ruleReviewModal = document.getElementById('ruleReviewModal');
    if (ruleReviewModal && !ruleReviewModal.hidden) {
        return 'ruleReviewModal';
    }

    return null;
}

function handleAnalyzerModalOpen(modalId, options = {}) {
    const modal = document.getElementById(modalId);
    if (!modal) {
        return;
    }

    const triggerElement = options.triggerElement || document.activeElement;
    if (triggerElement && !modal.contains(triggerElement) && isVisibleElement(triggerElement)) {
        modalTriggerElements[modalId] = triggerElement;
    }

    const dialog = getModalDialogElement(modalId);
    if (dialog) {
        setTimeout(() => dialog.focus(), 0);
    }
}

function handleAnalyzerModalClose(modalId, options = {}) {
    const { restoreFocus = true } = options;
    const triggerElement = modalTriggerElements[modalId];
    modalTriggerElements[modalId] = null;

    if (!restoreFocus || !isVisibleElement(triggerElement)) {
        return;
    }

    setTimeout(() => triggerElement.focus(), 0);
}

function trapFocusInModal(event, modalId) {
    const dialog = getModalDialogElement(modalId);
    const focusableElements = getFocusableElements(dialog);

    if (!dialog) {
        return;
    }

    if (!focusableElements.length) {
        event.preventDefault();
        dialog.focus();
        return;
    }

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    const activeElement = document.activeElement;
    const focusInsideDialog = dialog.contains(activeElement);

    if (event.shiftKey) {
        if (!focusInsideDialog || activeElement === firstElement || activeElement === dialog) {
            event.preventDefault();
            lastElement.focus();
        }
        return;
    }

    if (!focusInsideDialog || activeElement === lastElement) {
        event.preventDefault();
        firstElement.focus();
    }
}

function toggleUploadSourceRow() {
    const uploadSourceRow = document.getElementById('uploadSourceRow');
    if (!uploadSourceRow) {
        return;
    }
    uploadSourceRow.hidden = !uploadSourceRow.hidden;
}

function extractFrstRunPath(logText) {
    if (!logText) {
        return '';
    }

    const match = logText.match(/^\s*Running from\s+(.+?)\s*$/im);
    if (!match) {
        return '';
    }

    const rawPath = match[1].trim();
    // If FRST reports the executable path, copy only its directory.
    if (/\\frst(?:64)?\.exe$/i.test(rawPath)) {
        return rawPath.replace(/\\[^\\]+$/, '');
    }

    return rawPath;
}

async function copyFrstPathFromLog() {
    const logInputElement = document.getElementById('logInput');
    const copyButton = document.getElementById('copyFrstPathButton');
    if (!logInputElement || !copyButton) {
        return;
    }

    const frstPath = extractFrstRunPath(logInputElement.value || '');
    if (!frstPath) {
        alert('No "Running from" path found in the log.');
        return;
    }

    try {
        await navigator.clipboard.writeText(frstPath);
        const originalText = copyButton.textContent;
        copyButton.textContent = 'copied';
        setTimeout(() => {
            copyButton.textContent = originalText;
        }, 1200);
    } catch (error) {
        alert('Unable to copy FRST path to clipboard.');
    }
}

function toggleStatusVisibility(statusClass) {
    if (!statusClass) {
        return;
    }

    const container = document.getElementById('logLines');
    if (!container) {
        return;
    }

    const hideClass = HIDE_CLASS_PREFIX + statusClass;
    const isCurrentlyHidden = hiddenStatuses.has(statusClass);

    if (isCurrentlyHidden) {
        hiddenStatuses.delete(statusClass);
        container.classList.remove(hideClass);
    } else {
        hiddenStatuses.add(statusClass);
        container.classList.add(hideClass);
    }

    const legendItem = document.querySelector(
        `.legend-item[data-status-class="${statusClass}"]`
    );
    if (legendItem) {
        legendItem.classList.toggle('legend-hidden', !isCurrentlyHidden);
    }
}

function toggleAllStatusVisibility() {
    const container = document.getElementById('logLines');
    if (!container) {
        return;
    }

    const allHidden = ALL_LEGEND_STATUS_CLASSES.every((sc) => hiddenStatuses.has(sc));

    ALL_LEGEND_STATUS_CLASSES.forEach((statusClass) => {
        const hideClass = HIDE_CLASS_PREFIX + statusClass;
        if (allHidden) {
            hiddenStatuses.delete(statusClass);
            container.classList.remove(hideClass);
        } else {
            hiddenStatuses.add(statusClass);
            container.classList.add(hideClass);
        }
    });

    document.querySelectorAll('.legend-item[data-status-class]').forEach((item) => {
        item.classList.toggle('legend-hidden', !allHidden);
    });
}

function bindLegendToggle() {
    const legend = document.getElementById('statusLegend');
    if (!legend) {
        return;
    }

    const toggleAllButton = document.getElementById('legendToggleAllButton');
    if (toggleAllButton) {
        toggleAllButton.addEventListener('click', (event) => {
            event.stopPropagation();
            toggleAllStatusVisibility();
        });
    }

    legend.addEventListener('click', (event) => {
        const item = event.target.closest('.legend-item[data-status-class]');
        if (!item) {
            return;
        }
        toggleStatusVisibility(item.dataset.statusClass);
    });

    legend.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter' && event.key !== ' ') {
            return;
        }
        const item = event.target.closest('.legend-item[data-status-class]');
        if (!item) {
            return;
        }
        event.preventDefault();
        toggleStatusVisibility(item.dataset.statusClass);
    });
}

function bindAnalyzerControls() {
    bindAnalyzerButton('parseButton', () => parseLogs());
    bindAnalyzerButton('resetButton', () => resetToInput());
    bindAnalyzerButton('questionCursorModeButton', () => toggleQuestionCursorMode());
    bindAnalyzerButton('cleanCursorModeButton', () => toggleCleanCursorMode());
    bindAnalyzerButton('saveRulesRescanButton', () => saveRulesAndRescan());
    bindAnalyzerButton('saveFixlistButton', () => goToCreateFixlist());
    bindAnalyzerButton('lineInspectorCloseButton', () => closeLineInspectorModal());
    bindAnalyzerButton('ruleReviewBackButton', () => cancelRuleWorkflow());
    bindAnalyzerButton('ruleReviewContinueButton', () => submitWithRulePersist(false));
    bindAnalyzerButton('ruleReviewSavePersistButton', () => submitWithRulePersist(true));
    bindAnalyzerButton('conflictWizardBackButton', () => cancelRuleWorkflow());
    bindAnalyzerButton('wizardNextButton', () => advanceConflictWizard());
    bindAnalyzerButton('toggleLoadUploadButton', () => toggleUploadSourceRow());
    bindAnalyzerButton('copyFrstPathButton', () => copyFrstPathFromLog());
    bindAnalyzerButton('addRemainingCleanButton', () => addRemainingAsClean());
    bindAnalyzerButton('toggleFixlistPanelButton', () => toggleFixlistPanel());
    
    const uploadSourceSelect = document.getElementById('uploadSourceSelect');
    if (uploadSourceSelect) {
        uploadSourceSelect.addEventListener('change', () => loadSelectedUploadForAnalyzer());
    }

    document.querySelectorAll('[data-insert-status]').forEach((button) => {
        button.addEventListener('click', (event) => {
            event.preventDefault();
            insertAllStatus(button.dataset.insertStatus);
        });
    });

    const selectedLinesTextarea = document.getElementById('selectedLines');
    if (selectedLinesTextarea) {
        selectedLinesTextarea.addEventListener('input', () => {
            syncCopiedIndexesWithTextarea();
            scheduleDraftSave();
        });
    }

    const logInputTextarea = document.getElementById('logInput');
    if (logInputTextarea) {
        logInputTextarea.addEventListener('input', () => scheduleDraftSave());
    }

    bindLegendToggle();
}

function bindAnalyzerModalDismissals() {
    const lineInspectorBackdrop = document.getElementById('lineInspectorBackdrop');
    const ruleReviewBackdrop = document.getElementById('ruleReviewBackdrop');
    const conflictWizardBackdrop = document.getElementById('conflictWizardBackdrop');

    if (lineInspectorBackdrop) {
        lineInspectorBackdrop.addEventListener('click', () => closeLineInspectorModal());
    }
    if (ruleReviewBackdrop) {
        ruleReviewBackdrop.addEventListener('click', () => cancelRuleWorkflow());
    }
    if (conflictWizardBackdrop) {
        conflictWizardBackdrop.addEventListener('click', () => cancelRuleWorkflow());
    }

    document.addEventListener('keydown', (event) => {
        const activeModalId = getActiveModalId();
        if (activeModalId && event.key === 'Tab') {
            trapFocusInModal(event, activeModalId);
            return;
        }

        if (event.key !== 'Escape') {
            return;
        }

        if (activeModalId === 'lineInspectorModal') {
            closeLineInspectorModal();
            return;
        }

        if (activeModalId === 'conflictWizardModal') {
            cancelRuleWorkflow();
            return;
        }
        if (activeModalId === 'ruleReviewModal') {
            cancelRuleWorkflow();
        }
    });
}

function exposeLegacyAnalyzerGlobals() {
    window.handleAnalyzerModalOpen = handleAnalyzerModalOpen;
    window.handleAnalyzerModalClose = handleAnalyzerModalClose;

    Object.assign(window, {
        advanceConflictWizard,
        closeConflictWizardModal,
        closeRuleReviewModal,
        cancelRuleWorkflow,
        closeStatusPicker,
        closeLineInspectorModal,
        fetchRulePreview,
        goToCreateFixlist,
        addRemainingAsClean,
        insertAllStatus,
        insertLine,
        openConflictWizardModal,
        openLineInspectorModal,
        openRuleReviewModal,
        openStatusPicker,
        parseLogs,
        removeLine,
        renderContradictionListsForRule,
        renderRulePreview,
        resetToInput,
        saveRulesAndRescan,
        saveStatusSelection,
        submitWithRulePersist,
        syncCopiedIndexesWithTextarea,
        toggleQuestionCursorMode,
        toggleCleanCursorMode,
        toggleFixlistPanel,
    });
}

exposeLegacyAnalyzerGlobals();

document.addEventListener('DOMContentLoaded', async () => {
    initializeCursorPosition();
    setupStatusPicker();
    if (typeof setupLineCopyMenu === 'function') {
        setupLineCopyMenu();
    }
    if (typeof setupLineSearchMenu === 'function') {
        setupLineSearchMenu();
    }
    if (typeof setupLookupMenu === 'function') {
        setupLookupMenu();
    }
    initializePendingStatusChanges();
    // Must follow initializePendingStatusChanges(), which wipes pending state on
    // every load; a restore before this point would be erased.
    initDraftAutosave();
    if (typeof applyQuestionCursorModeState === 'function') {
        applyQuestionCursorModeState();
    }
    if (typeof applyCleanCursorModeState === 'function') {
        applyCleanCursorModeState();
    }
    if (typeof initFixlistPanelState === 'function') {
        initFixlistPanelState();
    }
    if (typeof initIgnoreFirewallRulesState === 'function') {
        initIgnoreFirewallRulesState();
    }
    bindAnalyzerControls();
    bindAnalyzerModalDismissals();
    // Wait for the initial analysis to settle so the restored overrides land on
    // real lines and the prompt isn't cleared by the analysis render. A failed
    // load must still surface the draft — that is when recovery matters most.
    try {
        await loadInitialUploadForAnalyzer();
    } finally {
        offerDraftRestore();
    }
});