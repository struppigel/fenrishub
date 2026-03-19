function resetConflictWizardState() {
    conflictWizardState = {
        queue: [],
        index: 0,
        resolutions: {},
        discardedRuleIds: new Set(),
    };
}

function statusDominance(statuses) {
    const available = new Set((statuses || []).filter(Boolean));
    for (const code of STATUS_PRECEDENCE_ORDER) {
        if (available.has(code)) {
            return code;
        }
    }
    return '?';
}

function precedenceSummary(newStatus, existingStatus) {
    const winner = statusDominance([newStatus, existingStatus]);
    const winnerLabel = STATUS_LABEL_MAP[winner] || 'unknown';
    const newLabel = STATUS_LABEL_MAP[newStatus] || 'unknown';
    const existingLabel = STATUS_LABEL_MAP[existingStatus] || 'unknown';
    if (!newStatus || !existingStatus) {
        return 'Insufficient data to compute precedence.';
    }
    if (newStatus === existingStatus) {
        return `Both rules resolve to ${winner} (${winnerLabel}), so either rule set produces the same status.`;
    }
    const winnerSource = winner === newStatus ? 'new rule' : 'existing rule';
    return (
        `new: ${newStatus} (${newLabel}), existing: ${existingStatus} (${existingLabel}). ` +
        `If both stay enabled, ${winner} (${winnerLabel}) wins by status precedence (${winnerSource}).`
    );
}

function rebuildDiscardedRuleIds() {
    const next = new Set();
    Object.values(conflictWizardState.resolutions).forEach((resolution) => {
        if (resolution.action === CONFLICT_ACTION_DISCARD_NEW) {
            next.add(String(resolution.change_id));
        }
    });
    conflictWizardState.discardedRuleIds = next;
}

function buildConflictWizardQueue(preview) {
    const queue = [];
    const ruleMap = new Map((preview.rule_changes || []).map((change) => [String(change.id), change]));

    const overrideConflicts = ((preview.contradictions || {}).override_vs_existing_dominant || []);
    overrideConflicts.forEach((conflict) => {
        const changeId = String(conflict.id);
        const newRule = ruleMap.get(changeId);
        if (!newRule) {
            return;
        }
        const matchingRules = Array.isArray(conflict.matching_rules) ? conflict.matching_rules : [];
        matchingRules.forEach((existingRule) => {
            if (!existingRule || existingRule.id === null || existingRule.id === undefined) {
                return;
            }
            queue.push(
                {
                    key: `override:${changeId}:${existingRule.id}`,
                    contradiction_type: 'override_vs_existing_dominant',
                    change_id: changeId,
                    line: conflict.line,
                    selected_status: conflict.selected_status,
                    existing_status_codes: conflict.existing_status_codes,
                    existing_dominant_status: conflict.existing_dominant_status,
                    existing_rule: existingRule,
                    new_rule: newRule,
                }
            );
        });
    });

    const overlapConflicts = ((preview.contradictions || {}).overlaps_other_status_rules || []);
    overlapConflicts.forEach((conflict) => {
        const changeId = String(conflict.id);
        const newRule = ruleMap.get(changeId);
        if (!newRule) {
            return;
        }
        const matchingRules = Array.isArray(conflict.matching_rules) ? conflict.matching_rules : [];
        matchingRules.forEach((existingRule) => {
            if (!existingRule || existingRule.id === null || existingRule.id === undefined) {
                return;
            }
            queue.push(
                {
                    key: `overlap:${changeId}:${existingRule.id}`,
                    contradiction_type: 'overlaps_other_status_rules',
                    change_id: changeId,
                    line: conflict.line,
                    selected_status: conflict.selected_status,
                    overlap_statuses: conflict.overlap_statuses || [],
                    existing_rule: existingRule,
                    new_rule: newRule,
                }
            );
        });
    });

    return queue;
}

function initializeConflictWizard(preview) {
    resetConflictWizardState();
    conflictWizardState.queue = buildConflictWizardQueue(preview || {});
}

function findNextWizardIndex(startIndex) {
    for (let i = startIndex; i < conflictWizardState.queue.length; i++) {
        const item = conflictWizardState.queue[i];
        if (!conflictWizardState.resolutions[item.key]) {
            return i;
        }
    }
    return -1;
}

function currentWizardItem() {
    if (!Array.isArray(conflictWizardState.queue) || conflictWizardState.queue.length === 0) {
        return null;
    }
    const idx = Math.max(0, Math.min(conflictWizardState.index, conflictWizardState.queue.length - 1));
    conflictWizardState.index = idx;
    return conflictWizardState.queue[idx];
}

function resolutionActionLabel(action) {
    if (action === CONFLICT_ACTION_UPDATE_EXISTING) {
        return 'change existing status';
    }
    if (action === CONFLICT_ACTION_KEEP_BOTH) {
        return 'keep both rules';
    }
    if (action === CONFLICT_ACTION_KEEP_NEW_DISABLE_OTHER) {
        return 'keep new and disable existing';
    }
    if (action === CONFLICT_ACTION_DISCARD_NEW) {
        return 'discard new rule';
    }
    return '';
}

function resolutionSummaryForRule(changeId) {
    const normalizedId = String(changeId);
    const entries = Object.values(conflictWizardState.resolutions).filter(
        (resolution) => String(resolution.change_id) === normalizedId
    );
    if (entries.length === 0) {
        return [];
    }

    const labels = [];
    entries.forEach((resolution) => {
        const label = resolutionActionLabel(resolution.action);
        if (label && !labels.includes(label)) {
            labels.push(label);
        }
    });
    return labels;
}

function getResolutionsForChange(changeId) {
    const normalizedId = String(changeId);
    return Object.values(conflictWizardState.resolutions).filter(
        (resolution) => String(resolution.change_id) === normalizedId
    );
}

function buildRuleResolutionPlan(change) {
    const entries = getResolutionsForChange(change.id);
    const hasDiscard = entries.some((entry) => entry.action === CONFLICT_ACTION_DISCARD_NEW);
    const hasUpdateExisting = entries.some((entry) => entry.action === CONFLICT_ACTION_UPDATE_EXISTING);
    const disableRuleIds = [
        ...new Set(
            entries
                .filter((entry) => entry.action === CONFLICT_ACTION_KEEP_NEW_DISABLE_OTHER)
                .map((entry) => entry.existing_rule_id)
                .filter((value) => value !== null && value !== undefined)
        ),
    ];
    const updateRuleIds = [
        ...new Set(
            entries
                .filter((entry) => entry.action === CONFLICT_ACTION_UPDATE_EXISTING)
                .map((entry) => entry.existing_rule_id)
                .filter((value) => value !== null && value !== undefined)
        ),
    ];

    let effectiveAction = (change.action || 'create').toLowerCase();
    let suppressNewRule = false;
    let forceUnchecked = false;
    if (hasDiscard) {
        effectiveAction = 'discard-new';
        suppressNewRule = true;
        forceUnchecked = true;
    } else if (hasUpdateExisting) {
        effectiveAction = 'update-existing-status';
        suppressNewRule = true;
    }

    return {
        entries,
        hasDiscard,
        hasUpdateExisting,
        disableRuleIds,
        updateRuleIds,
        effectiveAction,
        suppressNewRule,
        forceUnchecked,
    };
}

function renderPlannedExistingRuleChanges(ruleChanges) {
    const changeById = new Map((ruleChanges || []).map((change) => [String(change.id), change]));
    const selectedIds = new Set(selectedRuleIdsFromModal());
    const lines = [];
    const dedupe = new Set();

    selectedIds.forEach((changeId) => {
        const change = changeById.get(String(changeId));
        if (!change) {
            return;
        }
        const plan = buildRuleResolutionPlan(change);

        if (plan.hasUpdateExisting) {
            const nextStatus = `${change.to_status} (${STATUS_LABEL_MAP[change.to_status] || 'unknown'})`;
            plan.updateRuleIds.forEach((ruleId) => {
                const key = `update:${ruleId}:${change.to_status}`;
                if (!dedupe.has(key)) {
                    dedupe.add(key);
                    lines.push(`rule #${ruleId}: status will be changed to ${nextStatus}`);
                }
            });
        }

        if (!plan.suppressNewRule && plan.disableRuleIds.length > 0) {
            plan.disableRuleIds.forEach((ruleId) => {
                const key = `disable:${ruleId}`;
                if (!dedupe.has(key)) {
                    dedupe.add(key);
                    lines.push(`rule #${ruleId}: will be disabled`);
                }
            });
        }
    });

    buildReviewList(
        'plannedExistingRuleChangesList',
        lines,
        'No existing rules will be modified by current selections.'
    );
}

function refreshFinalReviewSummary(ruleChanges) {
    const summaryEl = document.getElementById('ruleReviewSummary');
    if (!summaryEl) {
        return;
    }

    const selectedIds = new Set(selectedRuleIdsFromModal());
    const totalCandidates = Array.isArray(ruleChanges) ? ruleChanges.length : 0;
    let createCount = 0;
    let updateCount = 0;
    const statusUpdateRuleIds = new Set();
    const disableRuleIds = new Set();

    (ruleChanges || []).forEach((change) => {
        const changeId = String(change.id);
        if (!selectedIds.has(changeId)) {
            return;
        }

        const plan = buildRuleResolutionPlan(change);
        if (plan.hasUpdateExisting) {
            plan.updateRuleIds.forEach((ruleId) => statusUpdateRuleIds.add(String(ruleId)));
            return;
        }

        if (plan.suppressNewRule) {
            return;
        }

        if ((change.action || 'create').toLowerCase() === 'update') {
            updateCount += 1;
        } else {
            createCount += 1;
        }

        plan.disableRuleIds.forEach((ruleId) => disableRuleIds.add(String(ruleId)));
    });

    const skippedCount = Math.max(0, totalCandidates - selectedIds.size);
    summaryEl.textContent =
        `selected candidates: ${selectedIds.size}/${totalCandidates}, ` +
        `new creates: ${createCount}, ` +
        `new updates: ${updateCount}, ` +
        `existing status changes: ${statusUpdateRuleIds.size}, ` +
        `existing disables: ${disableRuleIds.size}, ` +
        `skipped: ${skippedCount}`;
}

function serializeConflictResolutions() {
    return Object.values(conflictWizardState.resolutions).map((resolution) => ({
        conflict_key: resolution.conflict_key,
        contradiction_type: resolution.contradiction_type,
        change_id: resolution.change_id,
        existing_rule_id: resolution.existing_rule_id,
        action: resolution.action,
    }));
}

function renderWizardRulePanel(containerId, rows) {
    const container = document.getElementById(containerId);
    if (!container) {
        return;
    }

    container.innerHTML = '';
    const grid = document.createElement('div');
    grid.className = 'wizard-rule-grid';

    rows.forEach((row) => {
        const key = document.createElement('div');
        key.className = 'wizard-rule-key';
        key.textContent = row.key;

        const val = document.createElement('div');
        val.className = 'wizard-rule-value';
        val.textContent = formatRuleDetailValue(row.value);

        grid.appendChild(key);
        grid.appendChild(val);
    });

    container.appendChild(grid);
}

function renderConflictWizardActions(item) {
    const panel = document.getElementById('wizardActionPanel');
    if (!panel) {
        return;
    }

    panel.innerHTML = '';
    const currentResolution = conflictWizardState.resolutions[item.key];
    const selectedAction = currentResolution ? currentResolution.action : '';
    const statusText = `${item.selected_status} (${STATUS_LABEL_MAP[item.selected_status] || 'unknown'})`;

    const options = [
        {
            value: CONFLICT_ACTION_UPDATE_EXISTING,
            title: `only change status of existing rule to ${statusText}`,
            description: 'Does not create a new rule for this conflict pair.',
        },
        {
            value: CONFLICT_ACTION_KEEP_BOTH,
            title: 'keep both rules',
            description: 'Both rules remain enabled; precedence decides runtime status.',
        },
        {
            value: CONFLICT_ACTION_KEEP_NEW_DISABLE_OTHER,
            title: 'keep new rule and disable existing conflicting rule',
            description: 'Existing conflicting rule is soft-disabled (is_enabled=false).',
        },
        {
            value: CONFLICT_ACTION_DISCARD_NEW,
            title: 'discard own new rule',
            description: 'This new rule is removed from persistence for all of its contradictions.',
        },
    ];

    options.forEach((option) => {
        const label = document.createElement('label');
        label.className = 'wizard-action-option';

        const title = document.createElement('div');
        title.className = 'wizard-action-title';

        const radio = document.createElement('input');
        radio.type = 'radio';
        radio.name = 'wizardActionChoice';
        radio.value = option.value;
        radio.checked = selectedAction === option.value;
        radio.addEventListener('change', () => {
            setWizardResolution(item, option.value);
        });

        title.appendChild(radio);
        title.appendChild(document.createTextNode(option.title));

        const description = document.createElement('div');
        description.className = 'wizard-action-description';
        description.textContent = option.description;

        label.appendChild(title);
        label.appendChild(description);
        panel.appendChild(label);
    });
}

function setWizardResolution(item, action) {
    if (!item) {
        return;
    }

    const baseResolution = {
        conflict_key: item.key,
        contradiction_type: item.contradiction_type,
        change_id: item.change_id,
        existing_rule_id: item.existing_rule ? item.existing_rule.id : null,
        action,
    };

    conflictWizardState.resolutions[item.key] = baseResolution;

    if (action === CONFLICT_ACTION_DISCARD_NEW) {
        conflictWizardState.queue.forEach((queueItem) => {
            if (String(queueItem.change_id) === String(item.change_id)) {
                conflictWizardState.resolutions[queueItem.key] = {
                    ...baseResolution,
                    conflict_key: queueItem.key,
                    contradiction_type: queueItem.contradiction_type,
                    existing_rule_id: queueItem.existing_rule ? queueItem.existing_rule.id : null,
                };
            }
        });
    }

    rebuildDiscardedRuleIds();
}

function renderConflictWizardStep() {
    const item = currentWizardItem();
    const progressEl = document.getElementById('conflictWizardProgress');
    const precedenceEl = document.getElementById('wizardPrecedenceSummary');
    const nextButton = document.getElementById('wizardNextButton');

    if (!item) {
        if (progressEl) {
            progressEl.textContent = 'No contradictions detected.';
        }
        if (precedenceEl) {
            precedenceEl.textContent = 'No contradiction wizard steps are required.';
        }
        if (nextButton) {
            nextButton.textContent = 'continue';
        }
        return;
    }

    const total = conflictWizardState.queue.length;
    if (progressEl) {
        progressEl.textContent = (
            `conflict ${conflictWizardState.index + 1} of ${total} | ` +
            `pending change id: ${item.change_id} | existing db rule id: ${item.existing_rule ? item.existing_rule.id : '?'} | type: ${item.contradiction_type}`
        );
    }

    const newRule = item.new_rule || {};
    const existingRule = item.existing_rule || {};

    renderWizardRulePanel('wizardNewRulePanel', [
        { key: 'pending_change_id', value: newRule.id },
        { key: 'status', value: `${newRule.to_status} (${STATUS_LABEL_MAP[newRule.to_status] || 'unknown'})` },
        { key: 'match_type', value: newRule.match_type },
        { key: 'source_text', value: newRule.source_text },
        { key: 'description', value: newRule.description },
        { key: 'entry_type', value: newRule.entry_type },
        { key: 'filepath', value: newRule.filepath },
        { key: 'name', value: newRule.name },
        { key: 'company', value: newRule.company },
        { key: 'arguments', value: newRule.arguments },
    ]);

    renderWizardRulePanel('wizardExistingRulePanel', [
        { key: 'existing_rule_db_id', value: existingRule.id },
        { key: 'status', value: `${existingRule.status} (${STATUS_LABEL_MAP[existingRule.status] || 'unknown'})` },
        { key: 'match_type', value: existingRule.match_type },
        { key: 'source_text', value: existingRule.source_text },
        { key: 'description', value: existingRule.description },
        { key: 'entry_type', value: existingRule.entry_type },
        { key: 'filepath', value: existingRule.filepath },
        { key: 'name', value: existingRule.name },
        { key: 'company', value: existingRule.company },
        { key: 'arguments', value: existingRule.arguments },
        { key: 'reason', value: existingRule.reason },
    ]);

    if (precedenceEl) {
        precedenceEl.textContent = precedenceSummary(newRule.to_status, existingRule.status);
    }

    renderConflictWizardActions(item);

    if (nextButton) {
        nextButton.textContent = conflictWizardState.index >= total - 1
            ? 'finish contradictions'
            : 'next conflict';
    }
}

function advanceConflictWizard() {
    const item = currentWizardItem();
    if (!item) {
        closeConflictWizardModal({ restoreFocus: false });
        renderRulePreview(currentRulePreview || {});
        openRuleReviewModal();
        return;
    }

    const resolution = conflictWizardState.resolutions[item.key];
    if (!resolution) {
        alert('Choose a resolution action before continuing.');
        return;
    }

    const nextIndex = findNextWizardIndex(conflictWizardState.index + 1);
    if (nextIndex === -1) {
        closeConflictWizardModal({ restoreFocus: false });
        renderRulePreview(currentRulePreview || {});
        openRuleReviewModal();
        return;
    }

    conflictWizardState.index = nextIndex;
    renderConflictWizardStep();
}