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

function changeTypeLabel(action) {
    if (action === 'update-existing-status') {
        return 'update existing status';
    }
    if (action === 'update') {
        return 'save update';
    }
    return 'save new';
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
    if (!container) {
        return;
    }
    container.innerHTML = '';

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

    const nextSelectedRuleIds = [];
    let renderedRowCount = 0;
    const validChangeIds = new Set(ruleChanges.map((change) => normalizeRuleCandidateId(change.id)));
    [...ruleDescriptionOverrides.keys()].forEach((changeId) => {
        if (!validChangeIds.has(changeId)) {
            ruleDescriptionOverrides.delete(changeId);
        }
    });
    [...ruleTagOverrides.keys()].forEach((changeId) => {
        if (!validChangeIds.has(changeId)) {
            ruleTagOverrides.delete(changeId);
        }
    });
    [...ruleLogTypeOverrides.keys()].forEach((changeId) => {
        if (!validChangeIds.has(changeId)) {
            ruleLogTypeOverrides.delete(changeId);
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

        if (isRemoved || plan.hasDiscard) {
            return;
        }

        renderedRowCount += 1;

        const actionLabel = changeTypeLabel(plan.effectiveAction);

        const finalStatus = change.to_status || '?';
        const finalStatusClass = STATUS_CLASS_MAP[finalStatus] || 'status-unknown';
        const statusBadge = document.createElement('span');
        statusBadge.className = `status-badge ${finalStatusClass}`;
        statusBadge.textContent = finalStatus;
        statusBadge.setAttribute('title', `final status: ${finalStatus} (${STATUS_LABEL_MAP[finalStatus] || 'unknown'})`);

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
                `${actionLabel} | ${change.from_status} -> ${change.to_status} | ${change.match_type}`
                + `${change.match_unit === 'block' ? ' (block)' : ''} | `
            )
        );

        const sourceLine = document.createElement('span');
        sourceLine.className = 'rule-candidate-source-line';
        // A block rule's source is the block's lines.
        if ((change.source_text || '').includes('\n')) {
            sourceLine.style.whiteSpace = 'pre-wrap';
        }
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

        const tagUrls = (window.logAnalyzerConfig || {}).ruleTagUrls;
        if (tagUrls && typeof window.createRuleTagPicker === 'function') {
            const tagEditor = document.createElement('div');
            tagEditor.className = 'rule-tags-inline';
            // Same reason as the description: typing and clicking in here must
            // not reach the row's expand toggle or the modal's shortcuts.
            tagEditor.addEventListener('click', (event) => event.stopPropagation());
            tagEditor.addEventListener('keydown', (event) => event.stopPropagation());
            const picker = window.createRuleTagPicker({
                root: tagEditor,
                initialTags: ruleTagOverrides.get(changeId) || [],
                descriptionInput,
                // Tag conditions also look at the rule's source line and status.
                contextProvider: () => ({
                    source_text: change.source_text || '',
                    status: finalStatus,
                    match_type: change.match_type || '',
                }),
                urls: { list: tagUrls.list, suggest: tagUrls.suggest },
                placeholder: 'add tag (optional)...',
                onChange: () => {
                    ruleTagOverrides.set(changeId, picker.getTags());
                },
            });
            body.appendChild(tagEditor);
        }

        if (window.RuleForm) {
            body.appendChild(buildRuleLogScopeEditor(change, changeId));
        }

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

        row.appendChild(statusBadge);
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

// "applies to": the candidate's log type scope. The server sends the scope the
// rule gets (the default for this log, or an existing rule's own); a pick here
// is sent back as the change's log_types.
function buildRuleLogScopeEditor(change, changeId) {
    const editor = document.createElement('div');
    editor.className = 'rule-log-scope-inline';
    // Same reason as the description: clicks must not reach the row's toggle.
    editor.addEventListener('click', (event) => event.stopPropagation());
    editor.addEventListener('keydown', (event) => event.stopPropagation());

    const label = document.createElement('span');
    label.className = 'rule-description-inline-label';
    label.textContent = 'applies to:';
    editor.appendChild(label);

    const root = document.createElement('div');
    editor.appendChild(root);
    const value = ruleLogTypeOverrides.has(changeId)
        ? ruleLogTypeOverrides.get(changeId)
        : (change.log_types === undefined ? RuleForm.ALL_LOG_TYPES : change.log_types);
    const picked = RuleForm.logScopeChoices((currentRulePreview || {}).log_type_choices || [], value);
    RuleForm.createLogScopePicker({
        root,
        choices: picked.choices,
        unknown: picked.unknown,
        value,
        onChange: (next) => {
            ruleLogTypeOverrides.set(changeId, next);
        },
    });
    return editor;
}

// A rule being saved whose review pick is "selected log types" with none
// ticked; the server would refuse it, so saving stops and says so. Candidates
// left unselected do not block (their empty pick is not sent).
function emptyLogScopeOverride() {
    const selected = new Set(selectedRuleIdsFromModal().map(String));
    return [...ruleLogTypeOverrides.entries()].some(
        ([changeId, value]) => selected.has(String(changeId)) && Array.isArray(value) && value.length === 0
    );
}

function selectedRuleIdsFromModal() {
    return [...selectedRuleCandidateIds];
}

function resetRuleReviewDraftState() {
    currentRulePreview = null;
    selectedRuleCandidateIds = [];
    ruleDescriptionOverrides.clear();
    ruleTagOverrides.clear();
    ruleLogTypeOverrides.clear();
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
        const preview = await Fenris.postJson(PREVIEW_RULE_CHANGES_URL, {
            pending_changes: pendingChanges,
            log_type: currentLogType,
        }, { errorMessage: 'Failed to preview pending rule changes.' });
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
    return Fenris.postJson(PERSIST_RULE_CHANGES_URL, {
        pending_changes: pendingChanges,
        selected_rule_change_ids: selectedRuleIds,
        conflict_resolutions: conflictResolutions,
        log_type: currentLogType,
    }, { errorMessage: 'Failed to persist selected rules.' });
}

async function submitWithRulePersist(persistSelectedRules) {
    const pendingPayload = getPendingStatusChangesPayload();
    const submitTarget = ruleSubmitTarget;

    if (persistSelectedRules && pendingPayload.length > 0) {
        if (emptyLogScopeOverride()) {
            alert('A rule has "selected log types" with none ticked. Tick at least one log type, or pick "all log types".');
            return;
        }
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
        clearPendingAnalyzerChanges();
        resetRuleReviewDraftState();
        setRuleSubmitTarget(RULE_SUBMIT_TARGET_CREATE_FIXLIST);
        if (typeof parseLogs === 'function') {
            await parseLogs();
        }
        return;
    }

    resetRuleReviewDraftState();
    const payload = consumePendingFixlistPayload();
    if (!payload || !payload.content) {
        alert('Add at least one line before saving.');
        return;
    }
    submitFixlistDirectly(payload);
}