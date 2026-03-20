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

function initializePendingStatusChanges() {
    const pendingRaw = sessionStorage.getItem(PENDING_STATUS_STORAGE_KEY);
    const parsedPending = safeParseJson(pendingRaw || '[]', []);

    if (Array.isArray(parsedPending) && parsedPending.length > 0) {
        const tempMap = new Map();
        parsedPending.forEach((change) => {
            const key = change.line;
            tempMap.set(key, change);
        });
        pendingStatusChanges = tempMap;
    } else {
        pendingStatusChanges = new Map();
    }

    updateSaveChangesButtonState();
}

const modalTriggerElements = {
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

function bindAnalyzerControls() {
    bindAnalyzerButton('parseButton', () => parseLogs());
    bindAnalyzerButton('resetButton', () => resetToInput());
    bindAnalyzerButton('saveRulesRescanButton', () => saveRulesAndRescan());
    bindAnalyzerButton('saveFixlistButton', () => goToCreateFixlist());
    bindAnalyzerButton('ruleReviewBackButton', () => cancelRuleWorkflow());
    bindAnalyzerButton('ruleReviewContinueButton', () => submitWithRulePersist(false));
    bindAnalyzerButton('ruleReviewSavePersistButton', () => submitWithRulePersist(true));
    bindAnalyzerButton('conflictWizardBackButton', () => cancelRuleWorkflow());
    bindAnalyzerButton('wizardNextButton', () => advanceConflictWizard());

    document.querySelectorAll('[data-insert-status]').forEach((button) => {
        button.addEventListener('click', (event) => {
            event.preventDefault();
            insertAllStatus(button.dataset.insertStatus);
        });
    });
}

function bindAnalyzerModalDismissals() {
    const ruleReviewBackdrop = document.getElementById('ruleReviewBackdrop');
    const conflictWizardBackdrop = document.getElementById('conflictWizardBackdrop');

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
        fetchRulePreview,
        goToCreateFixlist,
        insertAllStatus,
        insertLine,
        openConflictWizardModal,
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
    });
}

exposeLegacyAnalyzerGlobals();

document.addEventListener('DOMContentLoaded', () => {
    initializeCursorPosition();
    setupStatusPicker();
    initializePendingStatusChanges();
    bindAnalyzerControls();
    bindAnalyzerModalDismissals();
});