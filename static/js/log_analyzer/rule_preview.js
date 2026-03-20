function buildReviewList(containerId, values, emptyText, options = {}) {
    const list = document.getElementById(containerId);
    if (!list) {
        return;
    }
    list.innerHTML = '';

    const hideWhenEmpty = Boolean(options.hideWhenEmpty);
    const section = list.closest('.review-section');

    if (!Array.isArray(values) || values.length === 0) {
        if (hideWhenEmpty) {
            if (section) {
                section.hidden = true;
            }
            return;
        }

        if (section) {
            section.hidden = false;
        }

        const li = document.createElement('li');
        li.textContent = emptyText;
        list.appendChild(li);
        return;
    }

    if (section) {
        section.hidden = false;
    }

    values.forEach((value) => {
        const li = document.createElement('li');
        li.textContent = value;
        list.appendChild(li);
    });
}

function formatRuleDetailValue(value) {
    if (value === null || value === undefined) {
        return '(none)';
    }
    if (typeof value === 'string' && !value.length) {
        return '(empty)';
    }
    if (typeof value === 'boolean') {
        return value ? 'true' : 'false';
    }
    return String(value);
}

function collectInlineHighlightMatches(sourceText, change) {
    if (typeof sourceText !== 'string' || !sourceText.length || !change) {
        return [];
    }

    const fields = [
        { key: 'entry_type', className: 'parsed-entry-type' },
        { key: 'clsid', className: 'parsed-clsid' },
        { key: 'filepath', className: 'parsed-filepath' },
        { key: 'arguments', className: 'parsed-arguments' },
        { key: 'company', className: 'parsed-company' },
        { key: 'name', className: 'parsed-name' },
        { key: 'filename', className: 'parsed-filename' },
    ];

    const lowerSource = sourceText.toLowerCase();
    const candidates = [];

    fields.forEach((field, priority) => {
        const rawValue = change[field.key];
        if (rawValue === null || rawValue === undefined) {
            return;
        }

        const needle = String(rawValue).trim();
        if (!needle) {
            return;
        }

        const lowerNeedle = needle.toLowerCase();
        let fromIndex = 0;

        while (fromIndex < lowerSource.length) {
            const start = lowerSource.indexOf(lowerNeedle, fromIndex);
            if (start === -1) {
                break;
            }

            candidates.push({
                start,
                end: start + lowerNeedle.length,
                className: field.className,
                priority,
            });

            fromIndex = start + lowerNeedle.length;
        }
    });

    candidates.sort((a, b) => {
        if (a.start !== b.start) {
            return a.start - b.start;
        }
        const aLen = a.end - a.start;
        const bLen = b.end - b.start;
        if (aLen !== bLen) {
            return bLen - aLen;
        }
        return a.priority - b.priority;
    });

    const accepted = [];
    candidates.forEach((candidate) => {
        const overlaps = accepted.some(
            (existing) => !(candidate.end <= existing.start || candidate.start >= existing.end)
        );
        if (!overlaps) {
            accepted.push(candidate);
        }
    });

    accepted.sort((a, b) => a.start - b.start);
    return accepted;
}

function appendHighlightedRuleLine(container, sourceText, change) {
    const text = typeof sourceText === 'string' ? sourceText : '';
    if (!text.length) {
        return;
    }

    const matches = collectInlineHighlightMatches(text, change);
    if (!matches.length) {
        container.textContent = text;
        return;
    }

    let cursor = 0;
    matches.forEach((match) => {
        if (cursor < match.start) {
            container.appendChild(document.createTextNode(text.slice(cursor, match.start)));
        }

        const span = document.createElement('span');
        span.className = match.className;
        span.textContent = text.slice(match.start, match.end);
        container.appendChild(span);

        cursor = match.end;
    });

    if (cursor < text.length) {
        container.appendChild(document.createTextNode(text.slice(cursor)));
    }
}

let currentRulePreview = null;
let selectedRuleCandidateIds = [];

function normalizeRuleCandidateId(changeId) {
    return String(changeId);
}

function rerenderCurrentRuleCandidates() {
    renderRuleCandidates(((currentRulePreview || {}).rule_changes) || []);
}

function truncateRuleDescription(value, maxLength = 140) {
    const text = typeof value === 'string' ? value.trim() : '';
    if (!text) {
        return '';
    }
    if (text.length <= maxLength) {
        return text;
    }
    return `${text.slice(0, Math.max(0, maxLength - 3))}...`;
}

function setRuleDescriptionOverride(change, nextValue) {
    const changeId = normalizeRuleCandidateId(change.id);
    const normalizedValue = typeof nextValue === 'string' ? nextValue : '';
    ruleDescriptionOverrides.set(changeId, normalizedValue);
    change.description = normalizedValue;
}

function renderRuleDescriptionNote(element, description) {
    if (!element) {
        return;
    }

    const previewText = truncateRuleDescription(description);
    if (!previewText) {
        element.hidden = true;
        element.textContent = '';
        return;
    }

    element.hidden = false;
    element.textContent = `description: ${previewText}`;
}

function toggleRuleCandidateExpanded(changeId) {
    const normalizedId = normalizeRuleCandidateId(changeId);
    expandedRuleCandidateId = expandedRuleCandidateId === normalizedId ? null : normalizedId;
    rerenderCurrentRuleCandidates();
}

function removeRuleCandidate(changeId) {
    const normalizedId = normalizeRuleCandidateId(changeId);
    removedRuleCandidateIds.add(normalizedId);
    if (expandedRuleCandidateId === normalizedId) {
        expandedRuleCandidateId = null;
    }
    rerenderCurrentRuleCandidates();
}

function buildRuleDetailRows(change) {
    const rows = [
        { key: 'from status', value: `${change.from_status} (${STATUS_LABEL_MAP[change.from_status] || 'unknown'})` },
        { key: 'to status', value: `${change.to_status} (${STATUS_LABEL_MAP[change.to_status] || 'unknown'})` },
        { key: 'match type', value: change.match_type },
        { key: 'existing rule id', value: change.existing_rule_id },
        { key: 'entry type', value: change.entry_type },
        { key: 'name', value: change.name },
        { key: 'filepath', value: change.filepath },
        { key: 'normalized filepath', value: change.normalized_filepath },
        { key: 'filename', value: change.filename },
        { key: 'company', value: change.company },
        { key: 'clsid', value: change.clsid },
        { key: 'arguments', value: change.arguments },
        { key: 'file not signed', value: change.file_not_signed },
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

function changeTypeMeta(action) {
    if (action === 'discard-new') {
        return { symbol: 'x', label: 'discard new', className: 'discard' };
    }
    if (action === 'update-existing-status') {
        return { symbol: '>', label: 'update existing status', className: 'status-update' };
    }
    if (action === 'update') {
        return { symbol: '~', label: 'save update', className: 'update' };
    }
    return { symbol: '+', label: 'save new', className: 'save' };
}

function renderContradictionLists(preview) {
    const contradictions = (preview || {}).contradictions || {};

    const overrideConflicts = (contradictions.override_vs_existing_dominant || []).map((item) => (
        `change ${item.id}: selected ${item.selected_status}, existing dominant ${item.existing_dominant_status} [${item.existing_status_codes}] | ${item.line}`
    ));
    buildReviewList(
        'overrideConflictsList',
        overrideConflicts,
        'No dominant-status contradictions were detected.'
    );

    const overlapConflicts = (contradictions.overlaps_other_status_rules || []).map((item) => {
        const overlapStatuses = Array.isArray(item.overlap_statuses) ? item.overlap_statuses.join(', ') : '';
        return `change ${item.id}: selected ${item.selected_status}, overlapping statuses: [${overlapStatuses}] | ${item.line}`;
    });
    buildReviewList(
        'overlapConflictsList',
        overlapConflicts,
        'No overlapping-status contradictions were detected.'
    );
}

function renderContradictionListsForRule() {
    renderContradictionLists(currentRulePreview || {});
}

function renderRuleCandidates(ruleChanges) {
    const container = document.getElementById('ruleCandidatesList');
    const legendContainer = document.getElementById('ruleLegend');
    if (!container) {
        return;
    }
    container.innerHTML = '';
    if (legendContainer) {
        legendContainer.innerHTML = '';
    }

    if (!Array.isArray(ruleChanges) || ruleChanges.length === 0) {
        selectedRuleCandidateIds = [];
        const empty = document.createElement('div');
        empty.className = 'rule-candidate-meta';
        empty.textContent = 'No valid rule candidates were generated from pending changes.';
        container.appendChild(empty);
        refreshFinalReviewSummary([]);
        renderPlannedExistingRuleChanges([]);
        return;
    }

    if (legendContainer) {
        const changeLegend = [
            { symbol: '+', label: 'save new rule', className: 'save' },
            { symbol: '~', label: 'save update', className: 'update' },
            { symbol: '>', label: 'update existing status only', className: 'status-update' },
            { symbol: 'x', label: 'discard new rule', className: 'discard' },
        ];
        changeLegend.forEach((item) => {
            const legendItem = document.createElement('div');
            legendItem.className = 'legend-item legend-item-symbol';

            const symbol = document.createElement('span');
            symbol.className = `rule-change-symbol rule-change-${item.className}`;
            symbol.textContent = item.symbol;

            const label = document.createElement('span');
            label.textContent = item.label;

            legendItem.appendChild(symbol);
            legendItem.appendChild(label);
            legendContainer.appendChild(legendItem);
        });

        const legendBreak = document.createElement('div');
        legendBreak.className = 'legend-row-break';
        legendContainer.appendChild(legendBreak);

        const colorLegend = [
            { label: 'CLSID', color: '#f0a070' },
            { label: 'name', color: '#a0f070' },
            { label: 'filepath', color: '#f070f0' },
            { label: 'filename', color: '#f0f070' },
            { label: 'company', color: '#70f0f0' },
            { label: 'arguments', color: '#f0a0a0' },
        ];
        colorLegend.forEach((item) => {
            const legendItem = document.createElement('div');
            legendItem.className = 'legend-item legend-item-color';

            const swatch = document.createElement('div');
            swatch.className = 'legend-swatch';
            swatch.style.backgroundColor = item.color;

            const label = document.createElement('span');
            label.textContent = item.label;

            legendItem.appendChild(swatch);
            legendItem.appendChild(label);
            legendContainer.appendChild(legendItem);
        });
    }

    const nextSelectedRuleIds = [];
    let renderedRowCount = 0;
    const validChangeIds = new Set(ruleChanges.map((change) => normalizeRuleCandidateId(change.id)));
    [...ruleDescriptionOverrides.keys()].forEach((changeId) => {
        if (!validChangeIds.has(changeId)) {
            ruleDescriptionOverrides.delete(changeId);
        }
    });
    [...removedRuleCandidateIds].forEach((changeId) => {
        if (!validChangeIds.has(changeId)) {
            removedRuleCandidateIds.delete(changeId);
        }
    });
    if (expandedRuleCandidateId && !validChangeIds.has(expandedRuleCandidateId)) {
        expandedRuleCandidateId = null;
    }

    ruleChanges.forEach((change) => {
        const changeId = normalizeRuleCandidateId(change.id);
        const isRemoved = removedRuleCandidateIds.has(changeId);

        const row = document.createElement('div');
        row.className = 'rule-candidate-item';

        const plan = buildRuleResolutionPlan(change);
        if (!plan.forceUnchecked && !isRemoved) {
            nextSelectedRuleIds.push(changeId);
        }

        if (ruleDescriptionOverrides.has(changeId)) {
            const descriptionOverride = ruleDescriptionOverrides.get(changeId);
            change.description = descriptionOverride;
        }

        if (isRemoved) {
            return;
        }

        renderedRowCount += 1;

        const action = plan.effectiveAction;
        const actionMeta = changeTypeMeta(action);

        const symbol = document.createElement('span');
        symbol.className = `rule-change-symbol rule-change-${actionMeta.className}`;
        symbol.textContent = actionMeta.symbol;
        symbol.setAttribute('aria-label', actionMeta.label);
        symbol.setAttribute('title', actionMeta.label);

        const content = document.createElement('div');
        content.className = 'rule-candidate-content';

        const header = document.createElement('div');
        header.className = 'rule-candidate-header';

        const body = document.createElement('div');
        body.className = 'rule-candidate-body';

        const text = document.createElement('div');
        text.className = 'rule-candidate-text';
        text.appendChild(
            document.createTextNode(
                `${actionMeta.label} | ${change.from_status} -> ${change.to_status} | ${change.match_type} | `
            )
        );

        const sourceLine = document.createElement('span');
        sourceLine.className = 'rule-candidate-source-line';
        appendHighlightedRuleLine(sourceLine, change.source_text || '', change);
        text.appendChild(sourceLine);

        body.appendChild(text);

        const resolutionLabels = resolutionSummaryForRule(change.id);
        const planNotes = [];
        if (resolutionLabels.length > 0) {
            planNotes.push(`resolution: ${resolutionLabels.join(', ')}`);
        }
        if (plan.hasUpdateExisting) {
            planNotes.push('new rule will not be submitted; selected existing rules will receive the new status');
        } else if (plan.hasDiscard) {
            planNotes.push('new rule will be discarded and not submitted');
        }
        if (!plan.suppressNewRule && plan.disableRuleIds.length > 0) {
            planNotes.push(`existing rules to disable: ${plan.disableRuleIds.map((id) => `#${id}`).join(', ')}`);
        }
        if (planNotes.length > 0) {
            const note = document.createElement('div');
            note.className = 'rule-resolution-note';
            note.textContent = planNotes.join(' | ');
            body.appendChild(note);
        }

        const descriptionEditor = document.createElement('div');
        descriptionEditor.className = 'rule-description-inline';

        const descriptionLabel = document.createElement('span');
        descriptionLabel.className = 'rule-description-inline-label';
        descriptionLabel.textContent = 'description:';
        descriptionEditor.appendChild(descriptionLabel);

        const descriptionInput = document.createElement('textarea');
        descriptionInput.className = 'rule-description-inline-input';
        descriptionInput.rows = 1;
        descriptionInput.placeholder = 'Optional description saved with this rule';
        descriptionInput.value = typeof change.description === 'string' ? change.description : '';
        descriptionInput.addEventListener('click', (event) => event.stopPropagation());
        descriptionInput.addEventListener('keydown', (event) => event.stopPropagation());
        descriptionInput.addEventListener('input', () => {
            setRuleDescriptionOverride(change, descriptionInput.value);
        });
        descriptionEditor.appendChild(descriptionInput);
        body.appendChild(descriptionEditor);

        const controls = document.createElement('div');
        controls.className = 'rule-candidate-controls';

        const removeButton = document.createElement('button');
        removeButton.type = 'button';
        removeButton.className = 'rule-candidate-remove';
        removeButton.textContent = '×';
        removeButton.setAttribute('title', 'Remove this change from the review list');
        removeButton.setAttribute('aria-label', 'Remove this change from the review list');
        removeButton.addEventListener('click', (event) => {
            event.stopPropagation();
            removeRuleCandidate(changeId);
        });
        controls.appendChild(removeButton);

        header.appendChild(body);
        header.appendChild(controls);
        content.appendChild(header);

        row.appendChild(symbol);
        row.appendChild(content);
        container.appendChild(row);
    });

    if (renderedRowCount === 0) {
        const empty = document.createElement('div');
        empty.className = 'rule-candidate-meta';
        empty.textContent = 'All rule candidates are currently removed from the review list.';
        container.appendChild(empty);
    }

    selectedRuleCandidateIds = nextSelectedRuleIds;
    refreshFinalReviewSummary(ruleChanges);
    renderPlannedExistingRuleChanges(ruleChanges);
}

function selectedRuleIdsFromModal() {
    return [...selectedRuleCandidateIds];
}

function resetRuleReviewDraftState() {
    currentRulePreview = null;
    selectedRuleCandidateIds = [];
    ruleDescriptionOverrides.clear();
    removedRuleCandidateIds.clear();
    expandedRuleCandidateId = null;

    if (typeof resetConflictWizardState === 'function') {
        resetConflictWizardState();
    }
}

function cancelRuleWorkflow(options = {}) {
    const { restoreFocus = true } = options;
    sessionStorage.removeItem(CONFLICT_RESOLUTION_STORAGE_KEY);
    resetRuleReviewDraftState();
    setRuleSubmitTarget(RULE_SUBMIT_TARGET_CREATE_FIXLIST);
    closeConflictWizardModal({ restoreFocus: false });
    closeRuleReviewModal({ restoreFocus });
}

function renderRulePreview(preview) {
    const safePreview = preview || {};
    currentRulePreview = safePreview;
    const summary = safePreview.summary || {};
    const summaryEl = document.getElementById('ruleReviewSummary');
    if (summaryEl) {
        summaryEl.textContent =
            `pending edits: ${summary.pending_changes || 0}, ` +
            `rule candidates: ${summary.rule_candidates || 0}, ` +
            `creates: ${summary.create_candidates || 0}, ` +
            `updates: ${summary.update_candidates || 0}, ` +
            `dominant conflicts: ${summary.override_conflicts || 0}, ` +
            `overlap conflicts: ${summary.overlap_conflicts || 0}`;
    }

    renderRuleCandidates(safePreview.rule_changes || []);
    renderContradictionLists(safePreview);

    const invalidChanges = (safePreview.invalid_changes || []).map((item) => {
        const idx = item.index === null || item.index === undefined ? '?' : item.index;
        return `index ${idx}: ${item.error || 'Invalid change.'}`;
    });
    buildReviewList(
        'invalidChangesList',
        invalidChanges,
        'No invalid pending changes detected.',
        { hideWhenEmpty: true }
    );
}

let rulePreviewInFlight = false;

async function fetchRulePreview(pendingChanges) {
    if (rulePreviewInFlight) {
        return;
    }

    rulePreviewInFlight = true;
    try {
        const response = await fetch(PREVIEW_RULE_CHANGES_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken'),
            },
            body: JSON.stringify({ pending_changes: pendingChanges }),
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to preview pending rule changes.');
        }

        const preview = await response.json();
        renderRulePreview(preview);
        initializeConflictWizard(preview);
        const firstUnresolvedIndex = findNextWizardIndex(0);
        if (firstUnresolvedIndex !== -1) {
            conflictWizardState.index = firstUnresolvedIndex;
            closeRuleReviewModal({ restoreFocus: false });
            openConflictWizardModal();
        } else {
            openRuleReviewModal();
        }
    } catch (error) {
        alert(error.message || 'Failed to preview pending rule changes.');
    } finally {
        rulePreviewInFlight = false;
    }
}

async function persistPendingRuleChanges(pendingChanges, selectedRuleIds, conflictResolutions) {
    const response = await fetch(PERSIST_RULE_CHANGES_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken'),
        },
        body: JSON.stringify({
            pending_changes: pendingChanges,
            selected_rule_change_ids: selectedRuleIds,
            conflict_resolutions: conflictResolutions,
        }),
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || 'Failed to persist selected rules.');
    }

    return response.json();
}

async function submitWithRulePersist(persistSelectedRules) {
    const pendingPayload = getPendingStatusChangesPayload();
    const submitTarget = ruleSubmitTarget;

    if (persistSelectedRules && pendingPayload.length > 0) {
        const selectedRuleIds = selectedRuleIdsFromModal();
        const conflictResolutions = serializeConflictResolutions();

        try {
            await persistPendingRuleChanges(pendingPayload, selectedRuleIds, conflictResolutions);
        } catch (error) {
            alert(error.message || 'Failed to persist selected rules.');
            return;
        }

        // Rules are already persisted by API call above.
        sessionStorage.removeItem(CONFLICT_RESOLUTION_STORAGE_KEY);
        sessionStorage.removeItem(PENDING_STATUS_STORAGE_KEY);
    } else {
        sessionStorage.removeItem(CONFLICT_RESOLUTION_STORAGE_KEY);
        if (submitTarget === RULE_SUBMIT_TARGET_RESCAN) {
            sessionStorage.removeItem(PENDING_STATUS_STORAGE_KEY);
        }
    }

    closeConflictWizardModal({ restoreFocus: false });
    closeRuleReviewModal({ restoreFocus: false });

    if (submitTarget === RULE_SUBMIT_TARGET_RESCAN) {
        resetRuleReviewDraftState();
        setRuleSubmitTarget(RULE_SUBMIT_TARGET_CREATE_FIXLIST);
        if (typeof parseLogs === 'function') {
            await parseLogs();
        }
        return;
    }

    resetRuleReviewDraftState();
    window.location.href = CREATE_FIXLIST_URL;
}