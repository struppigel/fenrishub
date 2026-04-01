async function requestLogAnalysis(logText, uploadId = '') {
    const payload = { log: logText };
    if (uploadId) {
        payload.upload_id = uploadId;
    }

    const response = await fetch(ANALYZE_LOG_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken'),
        },
        body: JSON.stringify(payload),
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || 'Failed to analyze log.');
    }

    return response.json();
}

async function requestLineDetails(line, status) {
    const response = await fetch(LINE_DETAILS_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken'),
        },
        body: JSON.stringify({ line, status }),
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || 'Failed to inspect line details.');
    }

    return response.json();
}

let questionCursorModeActive = false;
let cleanCursorModeActive = false;
let lineInspectorInFlight = false;

function closeLineInspectorModal(options = {}) {
    const modal = document.getElementById('lineInspectorModal');
    if (modal) {
        modal.hidden = true;
    }
    if (typeof window.handleAnalyzerModalClose === 'function') {
        window.handleAnalyzerModalClose('lineInspectorModal', options);
    }
}

function openLineInspectorModal(options = {}) {
    const modal = document.getElementById('lineInspectorModal');
    if (modal) {
        modal.hidden = false;
    }
    if (typeof window.handleAnalyzerModalOpen === 'function') {
        window.handleAnalyzerModalOpen('lineInspectorModal', options);
    }
}

function applyQuestionCursorModeState() {
    document.body.classList.toggle('question-cursor-mode', questionCursorModeActive);

    const button = document.getElementById('questionCursorModeButton');
    if (!button) {
        return;
    }

    button.setAttribute('aria-pressed', questionCursorModeActive ? 'true' : 'false');
    button.classList.toggle('is-active', questionCursorModeActive);
}

function toggleQuestionCursorMode() {
    questionCursorModeActive = !questionCursorModeActive;
    if (questionCursorModeActive) {
        cleanCursorModeActive = false;
        applyCleanCursorModeState();
    }
    applyQuestionCursorModeState();
}

function applyCleanCursorModeState() {
    document.body.classList.toggle('clean-cursor-mode', cleanCursorModeActive);

    const button = document.getElementById('cleanCursorModeButton');
    if (!button) {
        return;
    }

    button.setAttribute('aria-pressed', cleanCursorModeActive ? 'true' : 'false');
    button.classList.toggle('is-active', cleanCursorModeActive);
}

function toggleCleanCursorMode() {
    cleanCursorModeActive = !cleanCursorModeActive;
    if (cleanCursorModeActive) {
        questionCursorModeActive = false;
        applyQuestionCursorModeState();
    }
    applyCleanCursorModeState();
}

function buildLineInspectorRows(parsedRule) {
    if (!parsedRule || typeof parsedRule !== 'object') {
        return [];
    }

    const rows = [
        { key: 'status', value: `${parsedRule.status || '?'} (${STATUS_LABEL_MAP[parsedRule.status] || 'unknown'})` },
        { key: 'match type', value: parsedRule.match_type },
        { key: 'entry type', value: parsedRule.entry_type },
        { key: 'description', value: parsedRule.description },
        { key: 'clsid', value: parsedRule.clsid },
        { key: 'name', value: parsedRule.name },
        { key: 'filepath', value: parsedRule.filepath },
        { key: 'normalized filepath', value: parsedRule.normalized_filepath },
        { key: 'filename', value: parsedRule.filename },
        { key: 'company', value: parsedRule.company },
        { key: 'arguments', value: parsedRule.arguments },
        { key: 'file not signed', value: parsedRule.file_not_signed },
    ];

    return rows.filter((row) => {
        if (typeof row.value === 'boolean') {
            return true;
        }
        if (row.value === null || row.value === undefined) {
            return false;
        }
        return String(row.value).length > 0;
    });
}

function lineInspectorComponentClassForKey(key) {
    const lookup = {
        'entry type': 'parsed-entry-type',
        clsid: 'parsed-clsid',
        name: 'parsed-name',
        filepath: 'parsed-filepath',
        filename: 'parsed-filename',
        company: 'parsed-company',
        arguments: 'parsed-arguments',
    };
    return lookup[key] || '';
}

function renderLineInspector(detailsPayload, entry) {
    const parsedRule = detailsPayload && typeof detailsPayload.parsed_rule === 'object'
        ? detailsPayload.parsed_rule
        : null;
    const inspection = detailsPayload && typeof detailsPayload.inspection === 'object'
        ? detailsPayload.inspection
        : {};
    const effectiveMatches = Array.isArray(inspection.matches) ? inspection.matches : [];
    const shadowedMatches = Array.isArray(inspection.shadowed_matches) ? inspection.shadowed_matches : [];

    const summaryEl = document.getElementById('lineInspectorSummary');
    const sourceEl = document.getElementById('lineInspectorSource');
    const detailsEl = document.getElementById('lineInspectorDetails');
    const matchesListEl = document.getElementById('lineInspectorMatchesList');

    if (summaryEl) {
        const effectiveMatcher = inspection.effective_matcher || entry.matcher || 'unknown';
        const dominantStatus = inspection.dominant_status || entry.dominant_status || '?';
        summaryEl.textContent =
            `status: ${dominantStatus} (${STATUS_LABEL_MAP[dominantStatus] || 'unknown'}), ` +
            `matcher: ${effectiveMatcher}, ` +
            `matches: ${effectiveMatches.length + shadowedMatches.length}`;
    }

    if (sourceEl) {
        sourceEl.innerHTML = '';
        const text = document.createElement('div');
        text.className = 'rule-details-line';

        if (typeof appendHighlightedRuleLine === 'function') {
            appendHighlightedRuleLine(text, entry.line || '', parsedRule || {});
        } else {
            text.textContent = entry.line || '';
        }
        sourceEl.appendChild(text);
    }

    if (detailsEl) {
        detailsEl.innerHTML = '';
        const rows = buildLineInspectorRows(parsedRule);

        if (!rows.length) {
            const empty = document.createElement('div');
            empty.className = 'rule-details-empty';
            empty.textContent = 'No parsed components were detected for this line.';
            detailsEl.appendChild(empty);
        } else {
            const grid = document.createElement('div');
            grid.className = 'rule-details-grid';

            rows.forEach((row) => {
                const key = document.createElement('div');
                key.className = 'rule-detail-key';
                key.textContent = row.key;

                const value = document.createElement('div');
                value.className = 'rule-detail-value';
                const componentClass = lineInspectorComponentClassForKey(row.key);
                if (componentClass) {
                    value.classList.add(componentClass);
                }
                if (row.key === 'status' && parsedRule && parsedRule.status) {
                    const statusClass = STATUS_CLASS_MAP[parsedRule.status] || '';
                    if (statusClass) {
                        value.classList.add(statusClass);
                    }
                }
                value.textContent = formatRuleDetailValue(row.value);

                grid.appendChild(key);
                grid.appendChild(value);
            });

            detailsEl.appendChild(grid);
        }
    }

    if (matchesListEl) {
        matchesListEl.innerHTML = '';
        const allMatches = [
            ...effectiveMatches.map((match) => ({ ...match, _scope: 'effective' })),
            ...shadowedMatches.map((match) => ({ ...match, _scope: 'shadowed' })),
        ];

        if (!allMatches.length) {
            const empty = document.createElement('li');
            empty.textContent = 'No enabled rules currently match this line.';
            matchesListEl.appendChild(empty);
        } else {
            allMatches.forEach((match) => {
                const item = document.createElement('li');
                const scopeLabel = match._scope === 'shadowed' ? 'shadowed' : 'effective';
                const matcherText = match.matcher ? ` | matcher: ${match.matcher}` : '';
                const reasonText = match.reason ? ` | reason: ${match.reason}` : '';
                item.textContent =
                    `${scopeLabel} | #${match.id} | ${match.status} (${STATUS_LABEL_MAP[match.status] || 'unknown'}) | ` +
                    `${match.match_type}${matcherText} | ${match.source_text}${reasonText}`;
                matchesListEl.appendChild(item);
            });
        }
    }
}

async function openLineInspectorForIndex(index, options = {}) {
    const entry = analyzedLines[index];
    if (!entry || lineInspectorInFlight) {
        return;
    }

    lineInspectorInFlight = true;
    try {
        const detailsPayload = await requestLineDetails(entry.line || '', entry.dominant_status || '?');
        renderLineInspector(detailsPayload, entry);
        openLineInspectorModal(options);
    } catch (error) {
        alert(error.message || 'Failed to inspect line details.');
    } finally {
        lineInspectorInFlight = false;
    }
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
        const uploadSelect = document.getElementById('uploadSourceSelect');
        const selectedUploadId = uploadSelect ? (uploadSelect.value || '').trim() : '';
        if (selectedUploadId) {
            console.log('Parsing with upload_id:', selectedUploadId);
        }
        const payload = await requestLogAnalysis(logInput, selectedUploadId);
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
    if (['I', 'A'].includes(entry._baseDominantStatus || entry.dominant_status)) {
        alert('Informational and alert lines cannot be edited.');
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
    if (['I', 'A'].includes(baseStatus)) {
        alert('Informational and alert lines cannot be edited.');
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
            if (questionCursorModeActive) {
                openLineInspectorForIndex(index, { triggerElement: badge });
                return;
            }
            if (cleanCursorModeActive) {
                saveStatusSelection(index, 'C');
                return;
            }
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
            if (questionCursorModeActive) {
                openLineInspectorForIndex(index, { triggerElement: lineDiv });
                return;
            }
            if (cleanCursorModeActive) {
                saveStatusSelection(index, 'C');
                return;
            }
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

function setCopiedState(index, isCopied) {
    const badge = document.querySelector(`#logLines .status-badge[data-line-index="${index}"]`);
    if (!badge) {
        renderLogLines();
        return;
    }
    const lineDiv = badge.parentElement;
    if (isCopied) {
        lineDiv.classList.add('copied');
    } else {
        lineDiv.classList.remove('copied');
    }
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
    setCopiedState(index, false);
}

function shouldSkipFirewallRulesLine(line) {
    const ignoreFirewallRulesToggle = document.getElementById('bulkIgnoreFirewallRules');
    if (!ignoreFirewallRulesToggle || !ignoreFirewallRulesToggle.checked) {
        return false;
    }

    const normalizedLine = String(line || '').trimStart();
    return /^(?:[A-Z!?]\s+)?firewallrules:/i.test(normalizedLine);
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
    setCopiedState(index, true);
}

function insertAllStatus(status) {
    const textarea = document.getElementById('selectedLines');
    let insertPosition = textarea.selectionStart;
    let linesAdded = 0;
    const addedIndexes = [];

    for (let index = 0; index < analyzedLines.length; index++) {
        if (copiedLineIndexes.has(index)) {
            continue;
        }

        const entry = analyzedLines[index];
        if (entry.dominant_status === status) {
            const line = entry.line;
            if (shouldSkipFirewallRulesLine(line)) {
                continue;
            }
            const text = textarea.value;

            const newText = text.substring(0, insertPosition) + line + '\n' + text.substring(insertPosition);
            textarea.value = newText;

            insertPosition += line.length + 1;

            copiedLineIndexes.add(index);
            addedIndexes.push(index);
            linesAdded++;
        }
    }

    if (linesAdded > 0) {
        textarea.selectionStart = textarea.selectionEnd = insertPosition;
        textarea.focus();
        addedIndexes.forEach((idx) => setCopiedState(idx, true));
    }
}

function addRemainingAsClean() {
    if (!analyzedLines.length) {
        alert('No analyzed lines.');
        return;
    }

    const exclusions = ['ATTENTION', 'No File', '[X]', 'Access Denied', 'not found'];
    let count = 0;

    for (let index = 0; index < analyzedLines.length; index++) {
        const entry = analyzedLines[index];
        const effectiveStatus = entry.dominant_status || '?';
        if (effectiveStatus !== '?') continue;
        if (!entry.entry_type) continue;
        if (exclusions.some((ex) => entry.line.includes(ex))) continue;

        const lineKey = pendingOverrideKeyForEntry(entry, index);
        if (pendingStatusChanges.has(lineKey)) continue;

        pendingChangeSequence += 1;
        pendingStatusChanges.set(lineKey, {
            id: String(pendingChangeSequence),
            order: pendingChangeSequence,
            line: entry.line,
            original_status: '?',
            new_status: 'C',
        });
        count++;
    }

    if (count === 0) {
        alert('No remaining parsed unknown entries to mark as clean.');
        return;
    }

    applyPendingOverrides();
    updateSummary(summarizeEffectiveStatuses(analyzedLines), analyzedLines.length);
    renderLogLines();
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