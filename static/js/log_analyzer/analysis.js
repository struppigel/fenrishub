async function requestLogAnalysis(logText) {
    const response = await fetch(ANALYZE_LOG_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken'),
        },
        body: JSON.stringify({ log: logText }),
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || 'Failed to analyze log.');
    }

    return response.json();
}

function renderWarnings(warnings) {
    const container = document.getElementById('analysisWarnings');
    const warningList = Array.isArray(warnings) ? warnings : [];
    container.innerHTML = '';

    if (warningList.length === 0) {
        container.hidden = true;
        return;
    }

    warningList.forEach((warning) => {
        const warningElement = document.createElement('div');
        warningElement.className = 'analysis-warning';

        const titleText = String(warning.title || 'Warning').trim();
        const messageText = String(warning.message || '').trim();
        const showMessage = messageText && messageText.toLowerCase() !== titleText.toLowerCase();

        const headerElement = document.createElement('div');
        headerElement.className = 'analysis-warning-header';

        const titleElement = document.createElement('div');
        titleElement.className = 'analysis-warning-title';
        titleElement.textContent = titleText;

        const closeButton = document.createElement('button');
        closeButton.type = 'button';
        closeButton.className = 'analysis-warning-close';
        closeButton.setAttribute('aria-label', 'Close warning');
        closeButton.textContent = 'x';
        closeButton.addEventListener('click', () => {
            warningElement.remove();
            if (container.children.length === 0) {
                container.hidden = true;
            }
        });

        headerElement.appendChild(titleElement);
        headerElement.appendChild(closeButton);
        warningElement.appendChild(headerElement);

        if (showMessage) {
            const messageElement = document.createElement('div');
            messageElement.className = 'analysis-warning-message';
            messageElement.textContent = messageText;
            warningElement.appendChild(messageElement);
        }

        if (Array.isArray(warning.details) && warning.details.length > 0) {
            const detailsList = document.createElement('ul');
            detailsList.className = 'analysis-warning-details';
            warning.details.forEach((detail) => {
                const detailItem = document.createElement('li');
                detailItem.textContent = detail;
                detailsList.appendChild(detailItem);
            });
            warningElement.appendChild(detailsList);
        }

        container.appendChild(warningElement);
    });

    container.hidden = false;
}

async function parseLogs() {
    const logInput = document.getElementById('logInput').value;
    if (!logInput.trim()) {
        alert('No lines to parse');
        return;
    }

    const parseButton = document.getElementById('parseButton');
    if (parseButton) {
        parseButton.disabled = true;
        parseButton.textContent = 'analyzing...';
    }

    try {
        const payload = await requestLogAnalysis(logInput);
        applyAnalysisPayload(payload, { resetCopied: true, preservePendingChanges: true });

        if (analyzedLines.length === 0) {
            alert('No non-empty lines were found.');
            return;
        }
    } catch (error) {
        alert(error.message);
        return;
    } finally {
        if (parseButton) {
            parseButton.disabled = false;
            parseButton.textContent = 'parse lines';
        }
    }

    renderLogLines();

    document.getElementById('logInput').style.display = 'none';
    document.getElementById('logLines').style.display = 'block';
    document.getElementById('parseButton').style.display = 'none';
    document.getElementById('resetButton').style.display = 'inline-flex';
}

function resetToInput() {
    closeStatusPicker();
    document.getElementById('logLines').style.display = 'none';
    document.getElementById('logInput').style.display = 'block';
    document.getElementById('resetButton').style.display = 'none';
    document.getElementById('parseButton').style.display = 'inline-flex';
    const legendEl = document.getElementById('statusLegend');
    if (legendEl) {
        legendEl.hidden = true;
    }
}

let statusPickerTrigger = null;

function getStatusPickerButtons() {
    const picker = document.getElementById('statusPicker');
    if (!picker) {
        return [];
    }
    return [...picker.querySelectorAll('button')];
}

function focusStatusPickerButton(targetIndex) {
    const buttons = getStatusPickerButtons();
    if (!buttons.length) {
        return;
    }

    const safeIndex = Math.max(0, Math.min(targetIndex, buttons.length - 1));
    buttons[safeIndex].focus();
}

function focusStatusBadge(index) {
    const badge = document.querySelector(`.status-badge[data-line-index="${index}"]`);
    if (badge) {
        badge.focus();
    }
}

function setupStatusPicker() {
    document.addEventListener('click', (event) => {
        const picker = document.getElementById('statusPicker');
        if (!picker || picker.hidden) {
            return;
        }
        if (picker.contains(event.target)) {
            return;
        }
        closeStatusPicker({ restoreFocus: false });
    });

    const picker = document.getElementById('statusPicker');
    if (picker) {
        picker.addEventListener('keydown', (event) => {
            const buttons = getStatusPickerButtons();
            if (!buttons.length) {
                return;
            }

            const currentIndex = Math.max(0, buttons.indexOf(document.activeElement));
            if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
                event.preventDefault();
                focusStatusPickerButton((currentIndex + 1) % buttons.length);
                return;
            }
            if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
                event.preventDefault();
                focusStatusPickerButton((currentIndex - 1 + buttons.length) % buttons.length);
                return;
            }
            if (event.key === 'Home') {
                event.preventDefault();
                focusStatusPickerButton(0);
                return;
            }
            if (event.key === 'End') {
                event.preventDefault();
                focusStatusPickerButton(buttons.length - 1);
                return;
            }
            if (event.key === 'Escape') {
                event.preventDefault();
                closeStatusPicker();
            }
        });
    }

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeStatusPicker();
        }
    });
}

function closeStatusPicker(options = {}) {
    const { restoreFocus = true } = options;
    const picker = document.getElementById('statusPicker');
    if (!picker) {
        return;
    }
    if (statusPickerTrigger) {
        statusPickerTrigger.setAttribute('aria-expanded', 'false');
    }
    picker.hidden = true;
    picker.innerHTML = '';
    if (restoreFocus && statusPickerTrigger && document.contains(statusPickerTrigger)) {
        statusPickerTrigger.focus();
    }
    statusPickerTrigger = null;
}

function setStatusPickerDisabled(disabled) {
    const buttons = document.querySelectorAll('#statusPicker button');
    buttons.forEach((button) => {
        button.disabled = disabled;
    });
}

function openStatusPicker(anchor, index) {
    if (statusPickerBusy) {
        return;
    }

    const entry = analyzedLines[index];
    if (!entry) {
        return;
    }
    if ((entry._baseDominantStatus || entry.dominant_status) === 'I') {
        alert('Informational lines cannot be edited.');
        return;
    }

    const picker = document.getElementById('statusPicker');
    if (!picker) {
        return;
    }

    if (statusPickerTrigger && statusPickerTrigger !== anchor) {
        statusPickerTrigger.setAttribute('aria-expanded', 'false');
    }
    statusPickerTrigger = anchor;
    anchor.setAttribute('aria-expanded', 'true');
    picker.innerHTML = '';
    EDITABLE_STATUSES.forEach((status) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = `status-picker-option ${STATUS_CLASS_MAP[status] || 'status-unknown'}`;
        button.setAttribute('role', 'radio');
        button.setAttribute('aria-checked', entry.dominant_status === status ? 'true' : 'false');
        button.setAttribute('aria-label', `Set status to ${STATUS_LABEL_MAP[status] || 'unknown'}`);
        button.textContent = status;
        if (entry.dominant_status === status) {
            button.classList.add('active');
        }
        button.addEventListener('click', async (event) => {
            event.stopPropagation();
            await saveStatusSelection(index, status);
        });
        picker.appendChild(button);
    });

    const rect = anchor.getBoundingClientRect();
    const top = rect.bottom + 4;
    const left = Math.max(8, Math.min(rect.left, window.innerWidth - 190));
    picker.style.top = `${top}px`;
    picker.style.left = `${left}px`;
    picker.hidden = false;

    const buttons = getStatusPickerButtons();
    const activeIndex = buttons.findIndex((button) => button.classList.contains('active'));
    focusStatusPickerButton(activeIndex === -1 ? 0 : activeIndex);
}

async function saveStatusSelection(index, newStatus) {
    const entry = analyzedLines[index];
    if (!entry) {
        closeStatusPicker();
        return;
    }
    const currentStatus = entry.dominant_status || '?';
    const baseStatus = entry._baseDominantStatus || currentStatus;

    if (currentStatus === newStatus) {
        closeStatusPicker();
        return;
    }
    if (baseStatus === 'I') {
        alert('Informational lines cannot be edited.');
        closeStatusPicker();
        return;
    }

    statusPickerBusy = true;
    setStatusPickerDisabled(true);

    try {
        const lineKey = pendingOverrideKeyForEntry(entry, index);
        const existing = pendingStatusChanges.get(lineKey);

        if (newStatus === baseStatus) {
            pendingStatusChanges.delete(lineKey);
        } else {
            let id = existing ? existing.id : null;
            let order = existing ? existing.order : null;

            if (!id) {
                pendingChangeSequence += 1;
                id = String(pendingChangeSequence);
                order = pendingChangeSequence;
            }

            pendingStatusChanges.set(lineKey, {
                id,
                order,
                line: entry.line,
                original_status: baseStatus,
                new_status: newStatus,
            });
        }

        applyPendingOverrides();
        updateSummary(summarizeEffectiveStatuses(analyzedLines), analyzedLines.length);
        renderLogLines();
        closeStatusPicker({ restoreFocus: false });
        focusStatusBadge(index);
    } catch (error) {
        alert(error.message || 'Failed to update line status.');
    } finally {
        statusPickerBusy = false;
        setStatusPickerDisabled(false);
    }
}

function renderLogLines() {
    const container = document.getElementById('logLines');
    const savedScrollTop = container.scrollTop;
    container.innerHTML = '';

    analyzedLines.forEach((entry, index) => {
        const line = entry.line;
        const cssClass = entry.css_class || 'status-unknown';
        const status = entry.dominant_status || '?';

        const lineDiv = document.createElement('div');
        lineDiv.className = copiedLineIndexes.has(index)
            ? `log-line ${cssClass} copied`
            : `log-line ${cssClass}`;

        const badge = document.createElement('button');
        badge.type = 'button';
        badge.className = `status-badge ${cssClass}`;
        badge.dataset.lineIndex = String(index);
        badge.setAttribute('aria-haspopup', 'radiogroup');
        badge.setAttribute('aria-expanded', 'false');
        badge.textContent = status;
        badge.setAttribute('aria-label', `Change line status: ${STATUS_LABEL_MAP[status] || 'unknown'}`);
        if ((entry._baseDominantStatus || entry.dominant_status) === 'I') {
            badge.disabled = true;
            badge.setAttribute('aria-label', 'Informational line status is not editable');
        }
        badge.addEventListener('click', (event) => {
            event.stopPropagation();
            openStatusPicker(badge, index);
        });

        const text = document.createElement('span');
        text.className = 'line-text';
        text.textContent = line;

        lineDiv.appendChild(badge);
        lineDiv.appendChild(text);

        const reasons = Array.isArray(entry.reasons) ? entry.reasons : [];
        lineDiv.title = reasons.length > 0 ? `${line}\n\n${reasons.join('\n')}` : line;
        lineDiv.addEventListener('click', () => {
            if (copiedLineIndexes.has(index)) {
                removeLine(line, index);
            } else {
                insertLine(line, index);
            }
        });
        container.appendChild(lineDiv);
    });
    container.scrollTop = savedScrollTop;
}

function removeLine(line, index) {
    const textarea = document.getElementById('selectedLines');
    const cursorPos = textarea.selectionStart;
    const escaped = line.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp('(?:^|\\n)' + escaped + '(?:\\n|$)');
    const match = textarea.value.match(pattern);
    if (match) {
        const matchStart = textarea.value.indexOf(match[0]);
        let removal = match[0];
        let replaceWith = '';
        if (match[0].startsWith('\n') && match[0].endsWith('\n')) {
            replaceWith = '\n';
        }
        textarea.value = textarea.value.substring(0, matchStart) + replaceWith + textarea.value.substring(matchStart + removal.length);

        const removedLength = removal.length - replaceWith.length;
        let restoredPos = cursorPos;
        if (cursorPos > matchStart) {
            restoredPos = Math.max(matchStart, cursorPos - removedLength);
        }
        textarea.selectionStart = textarea.selectionEnd = restoredPos;
        textarea.focus();
    }
    copiedLineIndexes.delete(index);
    renderLogLines();
}

function insertLine(line, index) {
    if (analyzedLines[index] && analyzedLines[index].dominant_status === 'I') {
        return;
    }

    const textarea = document.getElementById('selectedLines');
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const text = textarea.value;

    const newText = text.substring(0, start) + line + '\n' + text.substring(end);
    textarea.value = newText;

    textarea.selectionStart = textarea.selectionEnd = start + line.length + 1;
    textarea.focus();

    copiedLineIndexes.add(index);
    renderLogLines();
}

function insertAllStatus(status) {
    const textarea = document.getElementById('selectedLines');
    let insertPosition = textarea.selectionStart;
    let linesAdded = 0;

    for (let index = 0; index < analyzedLines.length; index++) {
        if (copiedLineIndexes.has(index)) {
            continue;
        }

        const entry = analyzedLines[index];
        if (entry.dominant_status === status) {
            const line = entry.line;
            const text = textarea.value;

            const newText = text.substring(0, insertPosition) + line + '\n' + text.substring(insertPosition);
            textarea.value = newText;

            insertPosition += line.length + 1;

            copiedLineIndexes.add(index);
            linesAdded++;
        }
    }

    if (linesAdded > 0) {
        textarea.selectionStart = textarea.selectionEnd = insertPosition;
        textarea.focus();
        renderLogLines();
    }
}

function beginRuleWorkflow(target) {
    setRuleSubmitTarget(target);

    const pendingPayload = getPendingStatusChangesPayload();
    if (pendingPayload.length > 0) {
        sessionStorage.setItem(PENDING_STATUS_STORAGE_KEY, JSON.stringify(pendingPayload));
        fetchRulePreview(pendingPayload);
        return;
    }

    sessionStorage.removeItem(PENDING_STATUS_STORAGE_KEY);

    if (target === RULE_SUBMIT_TARGET_RESCAN) {
        parseLogs();
        return;
    }

    sessionStorage.removeItem(CONFLICT_RESOLUTION_STORAGE_KEY);
    window.location.href = CREATE_FIXLIST_URL;
}

function goToCreateFixlist() {
    const selected = document.getElementById('selectedLines').value;
    if (!selected.trim()) {
        alert('Add at least one line before saving.');
        return;
    }

    sessionStorage.setItem('fenrishub_prefill_content', selected);
    beginRuleWorkflow(RULE_SUBMIT_TARGET_CREATE_FIXLIST);
}

function saveRulesAndRescan() {
    const logInput = document.getElementById('logInput').value;
    if (!logInput.trim()) {
        alert('No lines to parse');
        return;
    }

    beginRuleWorkflow(RULE_SUBMIT_TARGET_RESCAN);
}

function openRuleReviewModal(options = {}) {
    const modal = document.getElementById('ruleReviewModal');
    if (modal) {
        modal.hidden = false;
    }
    if (typeof window.handleAnalyzerModalOpen === 'function') {
        window.handleAnalyzerModalOpen('ruleReviewModal', options);
    }
}

function closeRuleReviewModal(options = {}) {
    const modal = document.getElementById('ruleReviewModal');
    if (modal) {
        modal.hidden = true;
    }
    if (typeof window.handleAnalyzerModalClose === 'function') {
        window.handleAnalyzerModalClose('ruleReviewModal', options);
    }
}

function openConflictWizardModal(options = {}) {
    const modal = document.getElementById('conflictWizardModal');
    if (!modal) {
        return;
    }
    modal.hidden = false;
    if (typeof window.handleAnalyzerModalOpen === 'function') {
        window.handleAnalyzerModalOpen('conflictWizardModal', options);
    }
    renderConflictWizardStep();
}

function closeConflictWizardModal(options = {}) {
    const modal = document.getElementById('conflictWizardModal');
    if (modal) {
        modal.hidden = true;
    }
    if (typeof window.handleAnalyzerModalClose === 'function') {
        window.handleAnalyzerModalClose('conflictWizardModal', options);
    }
}