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

function buildUploadedLogContentUrl(uploadId) {
    const template = (window.logAnalyzerConfig && window.logAnalyzerConfig.uploadedLogContentUrlTemplate) || '';
    if (!template || !uploadId) {
        return '';
    }
    return template.replace('__UPLOAD_ID__', encodeURIComponent(uploadId));
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

    statusElement.textContent = 'loading...';

    try {
        const response = await fetch(requestUrl, {
            method: 'GET',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
            },
        });

        if (!response.ok) {
            throw new Error(`Request failed: ${response.status}`);
        }

        const payload = await response.json();
        if (typeof resetToInput === 'function') {
            resetToInput();
        }
        logInputElement.value = payload.content || '';
        statusElement.textContent = `loaded ${payload.upload_id}`;
        const url = new URL(window.location);
        url.searchParams.set('upload_id', uploadId);
        window.history.replaceState(null, '', url);
        logInputElement.focus();
    } catch (error) {
        statusElement.textContent = 'failed to load upload';
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
    await loadSelectedUploadForAnalyzer();
    
    // Show the upload source row if an initial upload was loaded
    const uploadSourceRow = document.getElementById('uploadSourceRow');
    if (uploadSourceRow) {
        uploadSourceRow.hidden = false;
    }
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
        toggleQuestionCursorMode,
        toggleCleanCursorMode,
    });
}

exposeLegacyAnalyzerGlobals();

document.addEventListener('DOMContentLoaded', () => {
    initializeCursorPosition();
    setupStatusPicker();
    initializePendingStatusChanges();
    if (typeof applyQuestionCursorModeState === 'function') {
        applyQuestionCursorModeState();
    }
    if (typeof applyCleanCursorModeState === 'function') {
        applyCleanCursorModeState();
    }
    bindAnalyzerControls();
    bindAnalyzerModalDismissals();
    loadInitialUploadForAnalyzer();
});