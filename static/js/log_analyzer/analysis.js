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

const _lineDetailsCache = new Map();

async function requestLineDetails(line, status) {
    const cacheKey = line + '\0' + status;
    const cached = _lineDetailsCache.get(cacheKey);
    if (cached) {
        return cached;
    }

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

    const result = await response.json();
    _lineDetailsCache.set(cacheKey, result);
    return result;
}

let questionCursorModeActive = false;
let cleanCursorModeActive = false;
let lineInspectorInFlight = false;

const FIXLIST_PANEL_HIDDEN_KEY = 'fenrishub_fixlist_panel_hidden';
const IGNORE_FIREWALL_RULES_KEY = 'fenrishub_ignore_firewall_rules';
let fixlistPanelHidden = false;

// The right column hosts two editors — the fixlist and the (not yet persisted)
// response to the user — and shows one at a time. Both stay in the DOM while
// the other is showing, so the browser keeps their text, caret and scroll
// position across a switch. Which one is up, and whether the column is
// collapsed at all, is picked from a single dropdown ("fixlist" / "response" /
// "hidden").
//
// The collapsed flag is kept separate from the fix/response choice on purpose:
// inserting a line must not re-open a column the analyst deliberately
// collapsed to get a full-width log view.
const ACTIVE_RIGHT_PANEL_KEY = 'fenrishub_right_panel_active';
let activeRightPanel = 'fix';

function getActiveRightTextarea() {
    return document.getElementById(activeRightPanel === 'response' ? 'responseText' : 'selectedLines');
}

function currentRightPanelView() {
    return fixlistPanelHidden ? 'hidden' : activeRightPanel;
}

const RIGHT_PANEL_VIEW_LABELS = { fix: 'fixlist', response: 'response', hidden: 'hidden' };

function applyRightPanelMenuState() {
    const view = currentRightPanelView();
    const trigger = document.getElementById('panelMenuTrigger');
    if (trigger) {
        trigger.textContent = RIGHT_PANEL_VIEW_LABELS[view] + ' ▾';
    }
    document.querySelectorAll('[data-panel-view]').forEach((item) => {
        const isSelected = item.dataset.panelView === view;
        item.classList.toggle('is-selected', isSelected);
        item.setAttribute('aria-checked', isSelected ? 'true' : 'false');
    });
}

function applyFixlistPanelState() {
    const box = document.querySelector('.textareas-box');
    if (box) {
        box.classList.toggle('fixlist-hidden', fixlistPanelHidden);
    }
    applyRightPanelMenuState();
}

function initFixlistPanelState() {
    try {
        fixlistPanelHidden = localStorage.getItem(FIXLIST_PANEL_HIDDEN_KEY) === '1';
    } catch (e) {
        fixlistPanelHidden = false;
    }
    applyFixlistPanelState();
}

function setFixlistPanelHidden(hidden) {
    if (hidden === fixlistPanelHidden) return;
    fixlistPanelHidden = hidden;
    try {
        localStorage.setItem(FIXLIST_PANEL_HIDDEN_KEY, fixlistPanelHidden ? '1' : '0');
    } catch (e) {}
    applyFixlistPanelState();
}

function applyRightPanelState() {
    const fixlist = document.getElementById('selectedLines');
    const response = document.getElementById('responseText');
    if (fixlist) fixlist.hidden = activeRightPanel !== 'fix';
    if (response) response.hidden = activeRightPanel !== 'response';

    // The bulk "add B P J ! / ignore FW" group only makes sense for the
    // fixlist; while the response is up the speeches picker takes its place.
    const writingResponse = activeRightPanel === 'response';
    const bulkControls = document.querySelector('.bulk-insert-controls');
    if (bulkControls) bulkControls.hidden = writingResponse;
    const speechMenu = document.getElementById('speechMenu');
    if (speechMenu) speechMenu.hidden = !writingResponse;
    // Capturing a speech only makes sense out of prose, so the button follows
    // the picker in and out of view.
    const addSpeechButton = document.getElementById('addSpeechButton');
    if (addSpeechButton) {
        addSpeechButton.hidden = !writingResponse;
        if (typeof refreshAddSpeechButtonState === 'function') {
            refreshAddSpeechButtonState();
        }
    }

    applyRightPanelMenuState();
}

function setActiveRightPanel(panel, { focus = true } = {}) {
    const target = panel === 'response' ? 'response' : 'fix';
    if (target === activeRightPanel) return;
    activeRightPanel = target;
    try {
        localStorage.setItem(ACTIVE_RIGHT_PANEL_KEY, activeRightPanel);
    } catch (e) {}
    applyRightPanelState();
    if (focus) {
        const textarea = getActiveRightTextarea();
        if (textarea) textarea.focus();
    }
}

function initRightPanelState() {
    try {
        // 'speech' is the pre-rename value; treat it as 'response'.
        const stored = localStorage.getItem(ACTIVE_RIGHT_PANEL_KEY);
        activeRightPanel = (stored === 'response' || stored === 'speech') ? 'response' : 'fix';
    } catch (e) {
        activeRightPanel = 'fix';
    }
    applyRightPanelState();
}

// The single entry point behind the picker.
function selectRightPanelView(view) {
    if (view === 'hidden') {
        setFixlistPanelHidden(true);
        return;
    }
    setFixlistPanelHidden(false);
    setActiveRightPanel(view);
    const textarea = getActiveRightTextarea();
    if (textarea) textarea.focus();
}

// Inserting or removing a line always targets the fixlist, so flip back to it
// to keep the edit visible. A collapsed column stays collapsed.
function ensureFixlistPanelActive() {
    setActiveRightPanel('fix');
}

function initIgnoreFirewallRulesState() {
    const checkbox = document.getElementById('bulkIgnoreFirewallRules');
    if (!checkbox) return;
    try {
        const stored = localStorage.getItem(IGNORE_FIREWALL_RULES_KEY);
        if (stored !== null) {
            checkbox.checked = stored === '1';
        }
    } catch (e) {}
    checkbox.addEventListener('change', () => {
        try {
            localStorage.setItem(IGNORE_FIREWALL_RULES_KEY, checkbox.checked ? '1' : '0');
        } catch (e) {}
    });
}

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

function buildStatusSymbolNode(status) {
    const span = document.createElement('span');
    span.className = `status-symbol ${STATUS_CLASS_MAP[status] || 'status-unknown'}`;
    span.textContent = status || '?';
    return span;
}

function buildLineInspectorRows(parsedRule) {
    if (!parsedRule || typeof parsedRule !== 'object') {
        return [];
    }

    const rows = [
        { key: 'status', value: parsedRule.status || '?', _isStatusSymbol: true },
        { key: 'match type', value: parsedRule.match_type },
        { key: 'source text', value: parsedRule.source_text },
        { key: 'entry type', value: parsedRule.entry_type },
        { key: 'description', value: parsedRule.description },
        { key: 'clsid', value: parsedRule.clsid },
        { key: 'name', value: parsedRule.name },
        { key: 'filepath', value: parsedRule.filepath },
        { key: 'normalized filepath', value: parsedRule.normalized_filepath },
        { key: 'filename', value: parsedRule.filename },
        { key: 'company', value: parsedRule.company },
        { key: 'arguments', value: parsedRule.arguments },
        { key: 'attributes', value: parsedRule.attributes },
        { key: 'file not signed', value: parsedRule.file_not_signed },
        { key: 'is hidden', value: parsedRule.is_hidden },
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
        summaryEl.innerHTML = '';
        summaryEl.appendChild(document.createTextNode('status: '));
        summaryEl.appendChild(buildStatusSymbolNode(dominantStatus));
        summaryEl.appendChild(document.createTextNode(
            ` (${STATUS_LABEL_MAP[dominantStatus] || 'unknown'}), ` +
            `matcher: ${effectiveMatcher}, ` +
            `matches: ${effectiveMatches.length + shadowedMatches.length}`,
        ));
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
                if (row._isStatusSymbol) {
                    value.appendChild(buildStatusSymbolNode(row.value));
                    value.appendChild(document.createTextNode(
                        ` (${STATUS_LABEL_MAP[row.value] || 'unknown'})`,
                    ));
                } else {
                    value.textContent = formatRuleDetailValue(row.value);
                }

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
                const priorityText = (match.priority !== undefined && match.priority !== null)
                    ? ` | priority: ${match.priority}`
                    : '';
                const reasonText = match.reason ? ` | reason: ${match.reason}` : '';
                const ownerText = ` | owner: ${match.owner_username || '—'}`;
                item.appendChild(document.createTextNode(`${scopeLabel} | `));
                item.appendChild(buildStatusSymbolNode(match.status));
                item.appendChild(document.createTextNode(
                    ` (${STATUS_LABEL_MAP[match.status] || 'unknown'}) | ` +
                    `${match.match_type}${priorityText}${matcherText} | ${match.source_text}${reasonText}${ownerText}`,
                ));
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
        _lineDetailsCache.clear();
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
    // Lines whose only base match was a parsed-entry filepath fallback show the
    // rule's verdict on the badge but no full match exists yet. Clicking even
    // the same status must register an override so the workflow can persist a
    // full parsed_entry rule for this line.
    const hasFilepathFallback = Boolean(entry._baseFilepathHighlight);

    if (currentStatus === newStatus && !hasFilepathFallback) {
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

        if (newStatus === baseStatus && !hasFilepathFallback) {
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
        scheduleDraftSave();
    } catch (error) {
        alert(error.message || 'Failed to update line status.');
    } finally {
        statusPickerBusy = false;
        setStatusPickerDisabled(false);
    }
}

const LINE_COPY_COMPONENT_LABELS = [
    ['filepath', 'filepath'],
    ['filename', 'filename'],
    ['arguments', 'arguments'],
    ['clsid', 'clsid'],
    ['name', 'name'],
    ['company', 'company'],
];

let lineCopyMenuEl = null;
let lineCopyMenuTrigger = null;
let lineSearchMenuEl = null;
let lineSearchMenuTrigger = null;

// Shared by the copy and search menus so both offer the exact same item set:
// the whole line, parsed components, and any detected URLs/domains.
function buildLineLookupItems(entry) {
    const items = [{ key: 'whole line', value: entry.line || '' }];
    const components = (entry && typeof entry.components === 'object') ? entry.components : {};
    LINE_COPY_COMPONENT_LABELS.forEach(([key, label]) => {
        const value = components ? components[key] : '';
        if (value) {
            items.push({ key: label, value });
        }
    });

    // Refanged URLs and bare domains detected in the line, so the user can act on
    // the resolvable form directly without retyping (defanged "hxxp://..." → "http://...").
    const seenLookups = new Set();
    for (const span of findHighlightSpans(entry.line || '')) {
        if (span.type !== 'url' && span.type !== 'domain') continue;
        const value = span.type === 'url' ? refangUrl(span.text) : span.text;
        if (seenLookups.has(value)) continue;
        seenLookups.add(value);
        items.push({ key: span.type, value });
    }
    return items;
}

function ensureLineCopyMenu() {
    if (lineCopyMenuEl && document.body.contains(lineCopyMenuEl)) {
        return lineCopyMenuEl;
    }
    const menu = document.createElement('div');
    menu.className = 'line-copy-menu';
    menu.setAttribute('role', 'menu');
    menu.hidden = true;
    menu.addEventListener('click', (event) => event.stopPropagation());
    document.body.appendChild(menu);
    lineCopyMenuEl = menu;
    return menu;
}

function closeLineCopyMenu() {
    if (lineCopyMenuTrigger) {
        lineCopyMenuTrigger.setAttribute('aria-expanded', 'false');
        lineCopyMenuTrigger = null;
    }
    if (lineCopyMenuEl) {
        lineCopyMenuEl.hidden = true;
        lineCopyMenuEl.innerHTML = '';
    }
}

async function copyToClipboard(value) {
    if (typeof value !== 'string') return false;
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(value);
            return true;
        }
    } catch (err) {
        // fall through to fallback
    }
    try {
        const ta = document.createElement('textarea');
        ta.value = value;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        return ok;
    } catch (err) {
        return false;
    }
}

function openLineCopyMenu(trigger, index) {
    const entry = analyzedLines[index];
    if (!entry) return;

    closeLineSearchMenu();

    if (lineCopyMenuTrigger === trigger && lineCopyMenuEl && !lineCopyMenuEl.hidden) {
        closeLineCopyMenu();
        return;
    }

    const menu = ensureLineCopyMenu();
    menu.innerHTML = '';

    const header = document.createElement('div');
    header.className = 'line-copy-menu-header';
    header.textContent = 'copy to clipboard';
    menu.appendChild(header);

    const items = buildLineLookupItems(entry);

    items.forEach(({ key, value }) => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'line-copy-menu-item';
        item.setAttribute('role', 'menuitem');

        const label = document.createElement('span');
        label.className = 'line-copy-menu-key';
        label.textContent = key;

        const preview = document.createElement('span');
        preview.className = 'line-copy-menu-value';
        preview.textContent = value;

        item.appendChild(label);
        item.appendChild(preview);
        item.addEventListener('click', async (event) => {
            event.stopPropagation();
            const ok = await copyToClipboard(value);
            if (!ok) {
                alert('Failed to copy to clipboard.');
            }
            closeLineCopyMenu();
        });
        menu.appendChild(item);
    });

    menu.hidden = false;
    if (lineCopyMenuTrigger && lineCopyMenuTrigger !== trigger) {
        lineCopyMenuTrigger.setAttribute('aria-expanded', 'false');
    }
    lineCopyMenuTrigger = trigger;
    trigger.setAttribute('aria-expanded', 'true');

    const rect = trigger.getBoundingClientRect();
    const menuWidth = menu.offsetWidth || 240;
    const menuHeight = menu.offsetHeight || 0;
    let left = rect.right - menuWidth;
    if (left < 8) left = Math.max(8, rect.left);
    if (left + menuWidth > window.innerWidth - 8) {
        left = window.innerWidth - menuWidth - 8;
    }
    let top = rect.bottom + 4;
    if (top + menuHeight > window.innerHeight - 8) {
        top = Math.max(8, rect.top - menuHeight - 4);
    }
    menu.style.left = `${left + window.scrollX}px`;
    menu.style.top = `${top + window.scrollY}px`;
}

function setupLineCopyMenu() {
    document.addEventListener('click', () => closeLineCopyMenu());
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeLineCopyMenu();
    });
    window.addEventListener('resize', () => closeLineCopyMenu());
    document.addEventListener('scroll', () => closeLineCopyMenu(), true);
}

// Search menu — mirrors the copy menu (same items, positioning and dismissal),
// but each item opens a Google search for its value in a new tab instead of
// copying it. Reuses the .line-copy-menu* CSS classes for styling.
function ensureLineSearchMenu() {
    if (lineSearchMenuEl && document.body.contains(lineSearchMenuEl)) {
        return lineSearchMenuEl;
    }
    const menu = document.createElement('div');
    menu.className = 'line-copy-menu line-search-menu';
    menu.setAttribute('role', 'menu');
    menu.hidden = true;
    menu.addEventListener('click', (event) => event.stopPropagation());
    document.body.appendChild(menu);
    lineSearchMenuEl = menu;
    return menu;
}

function closeLineSearchMenu() {
    if (lineSearchMenuTrigger) {
        lineSearchMenuTrigger.setAttribute('aria-expanded', 'false');
        lineSearchMenuTrigger = null;
    }
    if (lineSearchMenuEl) {
        lineSearchMenuEl.hidden = true;
        lineSearchMenuEl.innerHTML = '';
    }
}

function openLineSearchMenu(trigger, index) {
    const entry = analyzedLines[index];
    if (!entry) return;

    closeLineCopyMenu();

    if (lineSearchMenuTrigger === trigger && lineSearchMenuEl && !lineSearchMenuEl.hidden) {
        closeLineSearchMenu();
        return;
    }

    const menu = ensureLineSearchMenu();
    menu.innerHTML = '';

    const header = document.createElement('div');
    header.className = 'line-copy-menu-header';
    header.textContent = 'search on google';
    menu.appendChild(header);

    const items = buildLineLookupItems(entry);

    items.forEach(({ key, value }) => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'line-copy-menu-item';
        item.setAttribute('role', 'menuitem');

        const label = document.createElement('span');
        label.className = 'line-copy-menu-key';
        label.textContent = key;

        const preview = document.createElement('span');
        preview.className = 'line-copy-menu-value';
        preview.textContent = value;

        item.appendChild(label);
        item.appendChild(preview);
        item.addEventListener('click', (event) => {
            event.stopPropagation();
            window.open('https://www.google.com/search?q=' + encodeURIComponent(value), '_blank', 'noopener');
            closeLineSearchMenu();
        });
        menu.appendChild(item);
    });

    menu.hidden = false;
    if (lineSearchMenuTrigger && lineSearchMenuTrigger !== trigger) {
        lineSearchMenuTrigger.setAttribute('aria-expanded', 'false');
    }
    lineSearchMenuTrigger = trigger;
    trigger.setAttribute('aria-expanded', 'true');

    const rect = trigger.getBoundingClientRect();
    const menuWidth = menu.offsetWidth || 240;
    const menuHeight = menu.offsetHeight || 0;
    let left = rect.right - menuWidth;
    if (left < 8) left = Math.max(8, rect.left);
    if (left + menuWidth > window.innerWidth - 8) {
        left = window.innerWidth - menuWidth - 8;
    }
    let top = rect.bottom + 4;
    if (top + menuHeight > window.innerHeight - 8) {
        top = Math.max(8, rect.top - menuHeight - 4);
    }
    menu.style.left = `${left + window.scrollX}px`;
    menu.style.top = `${top + window.scrollY}px`;
}

function setupLineSearchMenu() {
    document.addEventListener('click', () => closeLineSearchMenu());
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeLineSearchMenu();
    });
    window.addEventListener('resize', () => closeLineSearchMenu());
    document.addEventListener('scroll', () => closeLineSearchMenu(), true);
}

const DATE_HIGHLIGHT_RE = /\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}(?::\d{2})?)?/g;
const CHROME_EXT_ID_RE = /(?<=\\Extensions\\|\\Extension: \[|\\User Data\\|_crx_|--app-id=)[a-p]{32}\b/g;
// Matches any FRST line whose platform prefix is "Edge " — covers
// `Edge Extension:` (file-based), `Edge HKU\…`, `Edge HKLM\…` (registry-based)
// and other Edge settings lines. \b after "Edge" prevents matching "Edges"/"Edgar".
const EDGE_EXT_LINE_RE = /^\s*Edge\b/;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
// IPv6 — moderately permissive; covers canonical and `::` shorthand forms.
const IPV6_RE = new RegExp(
    '(?<![\\w:.])(?:' +
        '(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|' +
        '(?:[0-9a-f]{1,4}:){1,7}:|' +
        '(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|' +
        '(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|' +
        '(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|' +
        '(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|' +
        '(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|' +
        '[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}|' +
        ':(?::[0-9a-f]{1,4}){1,7}' +
    ')(?![\\w:.])',
    'gi',
);
// Matches both real URLs (http(s)://) and defanged forms (hxxp(s)://) common in
// malware reports. The defanged form is refanged before being handed to lookup
// services so VT/who.is/urlscan resolve the real URL.
const URL_RE = /\b(?:https?|hxxps?):\/\/[^\s"'<>()\[\]]+/gi;

function refangUrl(v) {
    return v.replace(/^hxxp(s?):\/\//i, 'http$1://');
}
// DNS contexts where a bare hostname follows the bracketed keyword.
const DNS_DOMAIN_CTX_RE = /\[Dhcp(?:Domain(?:SearchList)?)\]\s*/g;
const BARE_DOMAIN_RE = /\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b/gi;

const IP_LOOKUP_ITEMS = [
    { label: 'virustotal', url: (v) => `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}` },
    { label: 'who.is', url: (v) => `https://who.is/whois-ip/ip-address/${encodeURIComponent(v)}` },
    { label: 'abuseipdb', url: (v) => `https://www.abuseipdb.com/check/${encodeURIComponent(v)}` },
    { label: 'urlscan.io', url: (v) => `https://urlscan.io/ip/${encodeURIComponent(v)}` },
];

const LOOKUP_KINDS = {
    'chrome-ext-id': {
        title: (v) => `Chrome extension ID: ${v}`,
        menuHeader: 'open extension id in',
        items: [
            { label: 'crxplorer', url: (v) => `https://crxplorer.com/extension/${v}` },
            { label: 'chrome web store', url: (v) => `https://chromewebstore.google.com/detail/${v}` },
            { label: 'chrome-stats', url: (v) => `https://chrome-stats.com/d/${v}` },
            { label: 'crxviewer', url: (v) => `https://robwu.nl/crxviewer/?crx=${encodeURIComponent(`https://chromewebstore.google.com/detail/${v}`)}` },
            { label: 'google search', url: (v) => `https://www.google.com/search?q=${encodeURIComponent(v)}` },
            { label: 'copy id instead', copy: true },
        ],
    },
    'edge-ext-id': {
        title: (v) => `Edge extension ID: ${v}`,
        menuHeader: 'open extension id in',
        items: [
            { label: 'edge add-ons', url: (v) => {
                const tmpl = (window.logAnalyzerConfig || {}).edgeAddonRedirectUrlTemplate || '';
                return tmpl.replace('__CRXID__', encodeURIComponent(v));
            } },
            { label: 'crxviewer', url: (v) => `https://robwu.nl/crxviewer/?crx=${encodeURIComponent(`https://microsoftedge.microsoft.com/addons/detail/${v}`)}` },
            { label: 'google search', url: (v) => `https://www.google.com/search?q=${encodeURIComponent(v)}` },
            { label: 'copy id instead', copy: true },
        ],
    },
    'ipv4': {
        title: (v) => `IPv4 address: ${v}`,
        menuHeader: 'open ip address in',
        items: IP_LOOKUP_ITEMS,
    },
    'ipv6': {
        title: (v) => `IPv6 address: ${v}`,
        menuHeader: 'open ip address in',
        items: IP_LOOKUP_ITEMS,
    },
    'url': {
        title: (v) => `URL: ${v}`,
        menuHeader: 'open url in',
        items: [
            { label: 'virustotal', url: (v) => `https://www.virustotal.com/gui/search?query=${encodeURIComponent(refangUrl(v))}` },
            { label: 'who.is', url: (v) => {
                const refanged = refangUrl(v);
                let host = refanged;
                try { host = new URL(refanged).hostname || refanged; } catch (e) { /* keep raw */ }
                return `https://who.is/whois/${encodeURIComponent(host)}`;
            } },
            { label: 'urlscan.io', url: (v) => `https://urlscan.io/search/#${encodeURIComponent(refangUrl(v))}` },
        ],
    },
    'domain': {
        title: (v) => `domain: ${v}`,
        menuHeader: 'open domain in',
        items: [
            { label: 'virustotal', url: (v) => `https://www.virustotal.com/gui/domain/${encodeURIComponent(v)}` },
            { label: 'who.is', url: (v) => `https://who.is/whois/${encodeURIComponent(v)}` },
            { label: 'urlscan.io', url: (v) => `https://urlscan.io/domain/${encodeURIComponent(v)}` },
        ],
    },
};

function collectRegexSpans(re, line, type) {
    const out = [];
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(line)) !== null) {
        out.push({
            start: m.index,
            end: m.index + m[0].length,
            type,
            text: m[0],
        });
    }
    return out;
}

// FRST "Version: 1.0.3.11" entries have the same dotted-decimal shape as IPv4
// — suppress them so clicks don't surface bogus VT/AbuseIPDB lookups.
const VERSION_PREFIX_RE = /(?:^|[\s(\[])(?:File\s+Version|Product\s+Version|Version)\s*:?\s*$/i;
// Installed Programs entries always carry a "(Version: ...)" segment and never
// contain real IPs — bail on IPv4 detection for the whole line when seen.
const INSTALLED_PROGRAM_LINE_RE = /\(Version:\s/i;

function collectIpv4Spans(line) {
    if (INSTALLED_PROGRAM_LINE_RE.test(line)) return [];

    const out = [];
    IPV4_RE.lastIndex = 0;
    let m;
    while ((m = IPV4_RE.exec(line)) !== null) {
        const preceding = line.slice(Math.max(0, m.index - 32), m.index);
        if (VERSION_PREFIX_RE.test(preceding)) continue;
        // Version dirs inside a Windows path (e.g. ...\Drive File Stream\125.0.0.0\drivefsext.dll).
        const prevChar = line.charAt(m.index - 1);
        const nextChar = line.charAt(m.index + m[0].length);
        if ((prevChar === '\\' || prevChar === '/') && (nextChar === '\\' || nextChar === '/')) continue;
        out.push({
            start: m.index,
            end: m.index + m[0].length,
            type: 'ipv4',
            text: m[0],
        });
    }
    return out;
}

// Hosts entries: optional "Hosts:" prefix, IPv4, whitespace, then one or more
// hostnames (often IDN — must tolerate unicode chars). Comments after `#` are
// ignored. We rely on the line shape rather than a domain regex so accented
// labels like "activación.cyberlink.com" still get picked up.
const HOSTS_LINE_PREFIX_RE = /^(\s*(?:Hosts:\s*)?)(\d{1,3}(?:\.\d{1,3}){3})(\s+)/;

function collectHostsSpans(line) {
    const prefix = HOSTS_LINE_PREFIX_RE.exec(line);
    if (!prefix) return [];
    const hostsStart = prefix[0].length;
    const commentIdx = line.indexOf('#', hostsStart);
    const hostsEnd = commentIdx === -1 ? line.length : commentIdx;
    const out = [];
    const tokenRe = /\S+/g;
    const segment = line.slice(hostsStart, hostsEnd);
    let tm;
    while ((tm = tokenRe.exec(segment)) !== null) {
        const token = tm[0];
        if (!token.includes('.')) continue;
        if (token.includes('*')) continue;
        if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(token)) continue;
        out.push({
            start: hostsStart + tm.index,
            end: hostsStart + tm.index + token.length,
            type: 'domain',
            text: token,
        });
    }
    return out;
}

function collectDnsDomainSpans(line) {
    const out = [];
    DNS_DOMAIN_CTX_RE.lastIndex = 0;
    let ctx;
    while ((ctx = DNS_DOMAIN_CTX_RE.exec(line)) !== null) {
        const segStart = ctx.index + ctx[0].length;
        const nextBracket = line.indexOf('[', segStart);
        const segEnd = nextBracket === -1 ? line.length : nextBracket;
        const segment = line.slice(segStart, segEnd);
        BARE_DOMAIN_RE.lastIndex = 0;
        let m;
        while ((m = BARE_DOMAIN_RE.exec(segment)) !== null) {
            out.push({
                start: segStart + m.index,
                end: segStart + m.index + m[0].length,
                type: 'domain',
                text: m[0],
            });
        }
    }
    return out;
}

function findHighlightSpans(line) {
    const spans = [];

    DATE_HIGHLIGHT_RE.lastIndex = 0;
    let match;
    while ((match = DATE_HIGHLIGHT_RE.exec(line)) !== null) {
        const parsed = parseFrstDate(match[0]);
        const bucket = classifyDateAgainstClusters(parsed);
        if (!bucket) continue;
        spans.push({
            start: match.index,
            end: match.index + match[0].length,
            type: 'date',
            text: match[0],
            bucket,
        });
    }

    const extIdKind = EDGE_EXT_LINE_RE.test(line) ? 'edge-ext-id' : 'chrome-ext-id';
    spans.push(...collectRegexSpans(CHROME_EXT_ID_RE, line, extIdKind));
    spans.push(...collectRegexSpans(URL_RE, line, 'url'));
    spans.push(...collectIpv4Spans(line));
    spans.push(...collectRegexSpans(IPV6_RE, line, 'ipv6'));
    spans.push(...collectDnsDomainSpans(line));
    spans.push(...collectHostsSpans(line));

    spans.sort((a, b) => {
        if (a.start !== b.start) return a.start - b.start;
        return (b.end - b.start) - (a.end - a.start);
    });
    const filtered = [];
    let lastEnd = -1;
    for (const span of spans) {
        if (span.start < lastEnd) continue;
        filtered.push(span);
        lastEnd = span.end;
    }
    return filtered;
}

function createLookupTrigger(text, kind) {
    const config = LOOKUP_KINDS[kind];
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `lookup-trigger lookup-trigger-${kind}`;
    btn.textContent = text;
    btn.title = config ? config.title(text) : text;
    btn.setAttribute('aria-haspopup', 'menu');
    btn.setAttribute('aria-expanded', 'false');
    btn.dataset.lookupKind = kind;
    btn.dataset.lookupValue = text;
    btn.addEventListener('click', (event) => {
        event.stopPropagation();
        openLookupMenu(btn, text, kind);
    });
    return btn;
}

function buildInnerHighlightNode(span) {
    if (span.type === 'date') {
        const el = document.createElement('span');
        el.className = `date-cluster-${span.bucket}`;
        el.textContent = span.text;
        return el;
    }
    return createLookupTrigger(span.text, span.type);
}

function appendLineTextWithDateHighlight(textEl, line, filepathHighlight = null) {
    const innerSpans = findHighlightSpans(line);
    const fp = filepathHighlight
        && Number.isInteger(filepathHighlight.start)
        && Number.isInteger(filepathHighlight.end)
        && filepathHighlight.end > filepathHighlight.start
        ? filepathHighlight
        : null;

    function emitChunk(parent, start, end) {
        let cursor = start;
        for (const span of innerSpans) {
            if (span.end <= cursor) continue;
            if (span.start >= end) break;
            if (span.start < start || span.end > end) continue;
            if (span.start > cursor) {
                parent.appendChild(document.createTextNode(line.slice(cursor, span.start)));
            }
            parent.appendChild(buildInnerHighlightNode(span));
            cursor = span.end;
        }
        if (cursor < end) {
            parent.appendChild(document.createTextNode(line.slice(cursor, end)));
        }
    }

    if (!innerSpans.length && !fp) {
        textEl.textContent = line;
        return;
    }

    if (!fp) {
        emitChunk(textEl, 0, line.length);
        return;
    }

    const fpStart = Math.max(0, Math.min(fp.start, line.length));
    const fpEnd = Math.max(fpStart, Math.min(fp.end, line.length));

    if (fpStart > 0) {
        emitChunk(textEl, 0, fpStart);
    }
    if (fpEnd > fpStart) {
        const wrapper = document.createElement('span');
        wrapper.className = `filepath-highlight ${fp.css_class || ''}`.trim();
        emitChunk(wrapper, fpStart, fpEnd);
        textEl.appendChild(wrapper);
    }
    if (fpEnd < line.length) {
        emitChunk(textEl, fpEnd, line.length);
    }
}

let lookupMenuEl = null;
let lookupMenuTrigger = null;

function ensureLookupMenu() {
    if (lookupMenuEl && document.body.contains(lookupMenuEl)) {
        return lookupMenuEl;
    }
    const menu = document.createElement('div');
    menu.className = 'lookup-menu';
    menu.setAttribute('role', 'menu');
    menu.hidden = true;
    menu.addEventListener('click', (event) => event.stopPropagation());
    document.body.appendChild(menu);
    lookupMenuEl = menu;
    return menu;
}

function closeLookupMenu() {
    if (lookupMenuTrigger) {
        lookupMenuTrigger.setAttribute('aria-expanded', 'false');
        lookupMenuTrigger = null;
    }
    if (lookupMenuEl) {
        lookupMenuEl.hidden = true;
        lookupMenuEl.innerHTML = '';
    }
}

function openLookupMenu(trigger, value, kind) {
    if (lookupMenuTrigger === trigger && lookupMenuEl && !lookupMenuEl.hidden) {
        closeLookupMenu();
        return;
    }

    const config = LOOKUP_KINDS[kind];
    if (!config) return;

    const menu = ensureLookupMenu();
    menu.innerHTML = '';

    const header = document.createElement('div');
    header.className = 'lookup-menu-header';
    header.textContent = config.menuHeader;
    menu.appendChild(header);

    config.items.forEach((item) => {
        if (item.copy) {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'lookup-menu-item';
            btn.setAttribute('role', 'menuitem');
            btn.textContent = item.label;
            btn.addEventListener('click', (event) => {
                event.preventDefault();
                navigator.clipboard.writeText(value).then(() => {
                    btn.textContent = 'copied';
                    setTimeout(() => closeLookupMenu(), 600);
                }, () => {
                    btn.textContent = 'copy failed';
                    setTimeout(() => closeLookupMenu(), 800);
                });
            });
            menu.appendChild(btn);
            return;
        }
        const link = document.createElement('a');
        link.className = 'lookup-menu-item';
        link.setAttribute('role', 'menuitem');
        link.href = item.url(value);
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.textContent = item.label;
        link.addEventListener('click', () => closeLookupMenu());
        menu.appendChild(link);
    });

    if (lookupMenuTrigger && lookupMenuTrigger !== trigger) {
        lookupMenuTrigger.setAttribute('aria-expanded', 'false');
    }
    lookupMenuTrigger = trigger;
    trigger.setAttribute('aria-expanded', 'true');

    menu.hidden = false;
    const rect = trigger.getBoundingClientRect();
    const menuWidth = menu.offsetWidth || 220;
    const menuHeight = menu.offsetHeight || 0;
    let left = rect.left;
    if (left + menuWidth > window.innerWidth - 8) {
        left = window.innerWidth - menuWidth - 8;
    }
    if (left < 8) left = 8;
    let top = rect.bottom + 4;
    if (top + menuHeight > window.innerHeight - 8) {
        top = Math.max(8, rect.top - menuHeight - 4);
    }
    menu.style.left = `${left + window.scrollX}px`;
    menu.style.top = `${top + window.scrollY}px`;
}

function setupLookupMenu() {
    document.addEventListener('click', () => closeLookupMenu());
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeLookupMenu();
    });
    window.addEventListener('resize', () => closeLookupMenu());
    document.addEventListener('scroll', () => closeLookupMenu(), true);
}

function renderLogLines() {
    const container = document.getElementById('logLines');
    const savedScrollTop = container.scrollTop;
    container.innerHTML = '';

    analyzedLines.forEach((entry, index) => {
        const line = entry.line;
        const cssClass = entry.css_class || 'status-unknown';
        const status = entry.dominant_status || '?';
        // Badge always reflects the verdict's colour even when the line itself is
        // styled as unknown (e.g. parsed-entry filepath-fallback matches).
        const badgeClass = STATUS_CLASS_MAP[status] || 'status-unknown';

        const lineDiv = document.createElement('div');
        lineDiv.className = copiedLineIndexes.has(index)
            ? `log-line ${cssClass} copied`
            : `log-line ${cssClass}`;
        // The legend filter hides lines by VERDICT, so it reads this attribute
        // rather than cssClass -- a fallback-only match is styled 'status-unknown'
        // but its verdict (and its legend count) is the badge's status.
        lineDiv.dataset.verdictClass = badgeClass;

        const badge = document.createElement('button');
        badge.type = 'button';
        badge.className = `status-badge ${badgeClass}`;
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
        appendLineTextWithDateHighlight(text, line, entry.filepath_highlight);

        const copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'line-copy-trigger';
        copyBtn.dataset.lineIndex = String(index);
        copyBtn.setAttribute('aria-label', 'copy line or component');
        copyBtn.setAttribute('aria-haspopup', 'menu');
        copyBtn.setAttribute('aria-expanded', 'false');
        copyBtn.title = 'copy line or component';
        copyBtn.innerHTML = '⎘';
        copyBtn.addEventListener('click', (event) => {
            event.stopPropagation();
            openLineCopyMenu(copyBtn, index);
        });

        const searchBtn = document.createElement('button');
        searchBtn.type = 'button';
        searchBtn.className = 'line-search-trigger';
        searchBtn.dataset.lineIndex = String(index);
        searchBtn.setAttribute('aria-label', 'search component on google');
        searchBtn.setAttribute('aria-haspopup', 'menu');
        searchBtn.setAttribute('aria-expanded', 'false');
        searchBtn.title = 'search component on google';
        searchBtn.innerHTML = '⌕';
        searchBtn.addEventListener('click', (event) => {
            event.stopPropagation();
            openLineSearchMenu(searchBtn, index);
        });

        lineDiv.appendChild(badge);
        lineDiv.appendChild(text);
        lineDiv.appendChild(copyBtn);
        lineDiv.appendChild(searchBtn);

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

// The text a line contributes to the Fixlist. Some entries (e.g. Windows
// Defender exclusions) carry a backend-provided replacement — a PowerShell
// remediation snippet — that is inserted instead of the raw log line.
function fixlistTextForEntry(entry) {
    if (entry && entry.fixlist_replacement) return entry.fixlist_replacement;
    return entry ? (entry.line || '') : '';
}

// Presence lookup over the fixlist text, used to keep the "copied" marks in
// sync. A replacement can span several lines (a browser extension becomes a
// `Comment:` plus the extension folder), so a plain per-line Set isn't enough —
// those have to be matched as a run of consecutive lines.
function buildFixlistPresence(value) {
    const lines = String(value || '').split('\n');
    const singles = new Set(lines.filter((segment) => segment.length > 0));
    return function has(text) {
        if (!text) return false;
        if (!text.includes('\n')) return singles.has(text);
        const block = text.split('\n');
        for (let start = 0; start + block.length <= lines.length; start++) {
            if (block.every((segment, offset) => lines[start + offset] === segment)) {
                return true;
            }
        }
        return false;
    };
}

function removeLine(line, index) {
    ensureFixlistPanelActive();
    const textarea = document.getElementById('selectedLines');
    const cursorPos = textarea.selectionStart;
    const effectiveLine = fixlistTextForEntry(analyzedLines[index]) || line;
    const escaped = effectiveLine.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp('(?:^|\\n)' + escaped + '(?:\\n|$)');
    const match = textarea.value.match(pattern);
    if (match) {
        const matchStart = textarea.value.indexOf(match[0]);
        let removal = match[0];
        let replaceWith = '';
        if (match[0].startsWith('\n') && match[0].endsWith('\n')) {
            replaceWith = '\n';
        }
        applyTextareaEdit(textarea, matchStart, matchStart + removal.length, replaceWith);

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
    scheduleDraftSave();
}

function syncCopiedIndexesWithTextarea() {
    const textarea = document.getElementById('selectedLines');
    if (!textarea || copiedLineIndexes.size === 0) {
        return;
    }
    const isPresent = buildFixlistPresence(textarea.value);
    const staleIndexes = [];
    copiedLineIndexes.forEach((index) => {
        const entry = analyzedLines[index];
        if (!isPresent(fixlistTextForEntry(entry))) {
            staleIndexes.push(index);
        }
    });
    staleIndexes.forEach((index) => {
        copiedLineIndexes.delete(index);
        setCopiedState(index, false);
    });
}

// syncCopiedIndexesWithTextarea() only prunes, which is enough while edits only
// ever remove lines. An undo can put removed lines back, so after one the marks
// have to be derived from the text in both directions.
function recomputeCopiedIndexesFromTextarea() {
    const textarea = document.getElementById('selectedLines');
    if (!textarea || !analyzedLines.length) {
        return;
    }
    const isInFixlist = buildFixlistPresence(textarea.value);
    analyzedLines.forEach((entry, index) => {
        const isPresent = isInFixlist(fixlistTextForEntry(entry));
        if (isPresent === copiedLineIndexes.has(index)) {
            return;
        }
        if (isPresent) {
            copiedLineIndexes.add(index);
        } else {
            copiedLineIndexes.delete(index);
        }
        setCopiedState(index, isPresent);
    });
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

    ensureFixlistPanelActive();
    const textarea = document.getElementById('selectedLines');
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const effectiveLine = fixlistTextForEntry(analyzedLines[index]) || line;

    applyTextareaEdit(textarea, start, end, effectiveLine + '\n');

    textarea.selectionStart = textarea.selectionEnd = start + effectiveLine.length + 1;
    textarea.focus();

    copiedLineIndexes.add(index);
    setCopiedState(index, true);
    scheduleDraftSave();
}

function insertAllStatus(status) {
    ensureFixlistPanelActive();
    syncCopiedIndexesWithTextarea();
    const textarea = document.getElementById('selectedLines');
    const insertPosition = textarea.selectionStart;
    const addedIndexes = [];
    const addedLines = [];

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
            addedLines.push(fixlistTextForEntry(entry));
            addedIndexes.push(index);
        }
    }

    if (addedLines.length > 0) {
        // The whole batch goes in as one edit, so a mis-clicked bulk button
        // costs a single Ctrl+Z rather than one per line.
        const block = addedLines.join('\n') + '\n';
        applyTextareaEdit(textarea, insertPosition, insertPosition, block);

        const caret = insertPosition + block.length;
        textarea.selectionStart = textarea.selectionEnd = caret;
        textarea.focus();
        addedIndexes.forEach((idx) => {
            copiedLineIndexes.add(idx);
            setCopiedState(idx, true);
        });
        scheduleDraftSave();
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
    scheduleDraftSave();
}

const PENDING_FIXLIST_PAYLOAD_KEY = 'fenrishub_pending_fixlist_payload';

function submitFixlistDirectly({ content, sourceUploadId, fixlistId, responseText }) {
    if (!CREATE_FIXLIST_URL) {
        alert('Fixlist endpoint is not configured.');
        return;
    }
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = CREATE_FIXLIST_URL;

    const addField = (name, value) => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = name;
        input.value = value;
        form.appendChild(input);
    };

    addField('csrfmiddlewaretoken', getCookie('csrftoken') || '');
    addField('content', content || '');
    // Always posted, even when empty: the server treats an absent field as
    // "preserve", so clearing the response has to send the empty string.
    addField('response', responseText || '');
    if (sourceUploadId) {
        addField('source_upload_id', sourceUploadId);
    }
    if (fixlistId) {
        addField('fixlist_id', fixlistId);
    }

    // The work is about to become a real Fixlist row, so stop guarding the
    // navigation. The draft is flagged rather than deleted, so a failed POST
    // is still recoverable.
    setSuppressUnloadGuard(true);
    markDraftSubmitted();

    document.body.appendChild(form);
    form.submit();
}

function consumePendingFixlistPayload() {
    let raw = null;
    try {
        raw = sessionStorage.getItem(PENDING_FIXLIST_PAYLOAD_KEY);
        sessionStorage.removeItem(PENDING_FIXLIST_PAYLOAD_KEY);
    } catch (e) {
        return null;
    }
    if (!raw) return null;
    try {
        return JSON.parse(raw);
    } catch (e) {
        return null;
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
    const payload = consumePendingFixlistPayload();
    if (!payload || !payload.content) {
        alert('Add at least one line before saving.');
        return;
    }
    submitFixlistDirectly(payload);
}

function goToCreateFixlist() {
    const selected = document.getElementById('selectedLines').value;
    if (!selected.trim()) {
        alert('Add at least one line before saving.');
        return;
    }

    const uploadSelect = document.getElementById('uploadSourceSelect');
    const sourceUploadId = uploadSelect ? (uploadSelect.value || '').trim() : '';
    const responseElement = document.getElementById('responseText');
    const responseText = responseElement ? responseElement.value : '';

    sessionStorage.setItem(
        PENDING_FIXLIST_PAYLOAD_KEY,
        JSON.stringify({ content: selected, sourceUploadId, fixlistId: EDIT_FIXLIST_ID, responseText }),
    );
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