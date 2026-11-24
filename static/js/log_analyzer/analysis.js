async function requestLogAnalysis(logText, uploadId = '') {
    const payload = { log: logText };
    if (uploadId) {
        payload.upload_id = uploadId;
    }

    return Fenris.postJson(ANALYZE_LOG_URL, payload, { errorMessage: 'Failed to analyze log.' });
}

const _lineDetailsCache = new Map();

async function requestLineDetails(line, status, blockLines = null, blockEntry = false) {
    const blockKey = blockLines ? blockLines.join('\n') : '';
    const cacheKey = line + '\0' + status + '\0' + currentLogType + '\0' + blockKey + '\0' + (blockEntry ? '1' : '0');
    const cached = _lineDetailsCache.get(cacheKey);
    if (cached) {
        return cached;
    }

    const payload = { line, status, log_type: currentLogType };
    // The block the line is in: block rules, and a Spor block's parsed rule.
    if (blockLines) {
        payload.block_lines = blockLines;
        // Whether the analysis read a Spor entry from the block (not, e.g.,
        // in a Spor log before 0.7.0): only then is its parsed type read.
        payload.block_entry = Boolean(blockEntry);
    }
    const result = await Fenris.postJson(LINE_DETAILS_URL, payload, { errorMessage: 'Failed to inspect line details.' });
    _lineDetailsCache.set(cacheKey, result);
    return result;
}

let questionCursorModeActive = false;
let cleanCursorModeActive = false;
let lineInspectorInFlight = false;

const IGNORE_FIREWALL_RULES_KEY = 'fenrishub_ignore_firewall_rules';

// The right column hosts two editors — the fixlist and the (not yet persisted)
// response to the user — and shows one at a time. Both stay in the DOM while
// the other is showing, so the browser keeps their text, caret and scroll
// position across a switch. Which one is up is picked from two tabs
// ("fixlist" / "response"). Every log opens on the fixlist; the choice is not
// remembered across page loads.
const ACTIVE_RIGHT_PANEL_KEY = 'fenrishub_right_panel_active';
let activeRightPanel = 'fix';

function getActiveRightTextarea() {
    return document.getElementById(activeRightPanel === 'response' ? 'responseText' : 'selectedLines');
}

function applyRightPanelTabsState() {
    document.querySelectorAll('#panelTabs [data-panel-view]').forEach((tab) => {
        const isSelected = tab.dataset.panelView === activeRightPanel;
        tab.classList.toggle('is-selected', isSelected);
        tab.setAttribute('aria-selected', isSelected ? 'true' : 'false');
    });
}

// Share of the row the log takes; the rest goes to the right column. Dragged
// via the splitter between the panels, double-click resets to an even split.
const LOG_PANEL_RATIO_KEY = 'fenrishub_log_panel_ratio';
const LOG_PANEL_RATIO_MIN = 0.15;
const LOG_PANEL_RATIO_MAX = 0.85;
const LOG_PANEL_RATIO_DEFAULT = 0.5;
const LOG_PANEL_RATIO_KEY_STEP = 0.02;
let logPanelRatio = LOG_PANEL_RATIO_DEFAULT;

function clampLogPanelRatio(ratio) {
    if (!Number.isFinite(ratio)) return LOG_PANEL_RATIO_DEFAULT;
    return Math.min(LOG_PANEL_RATIO_MAX, Math.max(LOG_PANEL_RATIO_MIN, ratio));
}

function applyLogPanelRatio(ratio) {
    logPanelRatio = clampLogPanelRatio(ratio);
    const box = document.querySelector('.textareas-box');
    if (box) {
        box.style.setProperty('--log-panel-fr', `${logPanelRatio}fr`);
        box.style.setProperty('--fix-panel-fr', `${1 - logPanelRatio}fr`);
    }
    const splitter = document.getElementById('panelSplitter');
    if (splitter) {
        splitter.setAttribute('aria-valuenow', String(Math.round(logPanelRatio * 100)));
    }
}

function saveLogPanelRatio() {
    Fenris.storage.set(LOG_PANEL_RATIO_KEY, logPanelRatio);
}

function initPanelSplitter() {
    const stored = Fenris.storage.get(LOG_PANEL_RATIO_KEY);
    applyLogPanelRatio(stored === null ? LOG_PANEL_RATIO_DEFAULT : parseFloat(stored));

    const splitter = document.getElementById('panelSplitter');
    const box = document.querySelector('.textareas-box');
    if (!splitter || !box) return;

    let dragging = false;

    function ratioFromPointer(clientX) {
        const rect = box.getBoundingClientRect();
        const style = getComputedStyle(box);
        const contentLeft = rect.left + parseFloat(style.paddingLeft) + parseFloat(style.borderLeftWidth);
        const contentWidth = box.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
        const panelsWidth = contentWidth - splitter.offsetWidth;
        if (panelsWidth <= 0) return logPanelRatio;
        return (clientX - contentLeft - splitter.offsetWidth / 2) / panelsWidth;
    }

    function endDrag(event) {
        if (!dragging) return;
        dragging = false;
        document.body.classList.remove('panel-resizing');
        if (splitter.hasPointerCapture(event.pointerId)) {
            splitter.releasePointerCapture(event.pointerId);
        }
        saveLogPanelRatio();
    }

    splitter.addEventListener('pointerdown', (event) => {
        if (event.button !== 0) return;
        event.preventDefault();
        dragging = true;
        splitter.setPointerCapture(event.pointerId);
        document.body.classList.add('panel-resizing');
    });
    splitter.addEventListener('pointermove', (event) => {
        if (!dragging) return;
        applyLogPanelRatio(ratioFromPointer(event.clientX));
    });
    splitter.addEventListener('pointerup', endDrag);
    splitter.addEventListener('pointercancel', endDrag);
    splitter.addEventListener('dblclick', () => {
        applyLogPanelRatio(LOG_PANEL_RATIO_DEFAULT);
        saveLogPanelRatio();
    });
    splitter.addEventListener('keydown', (event) => {
        let delta = 0;
        if (event.key === 'ArrowLeft') delta = -LOG_PANEL_RATIO_KEY_STEP;
        else if (event.key === 'ArrowRight') delta = LOG_PANEL_RATIO_KEY_STEP;
        else return;
        event.preventDefault();
        applyLogPanelRatio(logPanelRatio + delta);
        saveLogPanelRatio();
    });
}

// The whole right column can be closed so the log takes the full row. The
// choice is remembered across page loads. Inserting lines, snippets or
// speeches while it is closed still edits the hidden textareas and leaves the
// column closed; only the toggle buttons open it again.
const RIGHT_PANEL_CLOSED_KEY = 'fenrishub_right_panel_closed';
let rightPanelClosed = false;

function applyRightPanelClosed(closed) {
    rightPanelClosed = Boolean(closed);
    const box = document.querySelector('.textareas-box');
    if (box) box.classList.toggle('right-panel-closed', rightPanelClosed);
    const expanded = rightPanelClosed ? 'false' : 'true';
    ['rightPanelOpenButton', 'rightPanelCloseButton'].forEach((id) => {
        const button = document.getElementById(id);
        if (button) button.setAttribute('aria-expanded', expanded);
    });
}

function setRightPanelClosed(closed) {
    const target = Boolean(closed);
    if (target === rightPanelClosed) return;
    const panel = document.getElementById('rightPanel');
    const focusWasInside = Boolean(panel && panel.contains(document.activeElement));
    applyRightPanelClosed(target);
    Fenris.storage.setFlag(RIGHT_PANEL_CLOSED_KEY, target);
    if (target) {
        if (focusWasInside) {
            const openButton = document.getElementById('rightPanelOpenButton');
            if (openButton) openButton.focus();
        }
    } else {
        const textarea = getActiveRightTextarea();
        if (textarea) textarea.focus();
    }
}

function initRightPanelToggle() {
    applyRightPanelClosed(Fenris.storage.flag(RIGHT_PANEL_CLOSED_KEY));

    const openButton = document.getElementById('rightPanelOpenButton');
    if (openButton) openButton.addEventListener('click', () => setRightPanelClosed(false));
    const closeButton = document.getElementById('rightPanelCloseButton');
    if (closeButton) closeButton.addEventListener('click', () => setRightPanelClosed(true));
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

    applyRightPanelTabsState();
}

function setActiveRightPanel(panel, { focus = true } = {}) {
    const target = panel === 'response' ? 'response' : 'fix';
    if (target === activeRightPanel) return;
    activeRightPanel = target;
    applyRightPanelState();
    // A snippet counts as used per panel (speech_suggestions.js).
    if (typeof refreshSnippetSuggestions === 'function') {
        refreshSnippetSuggestions();
    }
    if (focus) {
        const textarea = getActiveRightTextarea();
        if (textarea) textarea.focus();
    }
}

function initRightPanelState() {
    activeRightPanel = 'fix';
    // Clean up the tab choice older versions stored, which made a new log
    // open on the response.
    Fenris.storage.remove(ACTIVE_RIGHT_PANEL_KEY);
    applyRightPanelState();
}

// The single entry point behind the tabs.
function selectRightPanelView(view) {
    setActiveRightPanel(view);
    const textarea = getActiveRightTextarea();
    if (textarea) textarea.focus();
}

// Inserting or removing a line always targets the fixlist, so flip back to it
// to keep the edit visible.
function ensureFixlistPanelActive() {
    setActiveRightPanel('fix');
}

function initIgnoreFirewallRulesState() {
    const checkbox = document.getElementById('bulkIgnoreFirewallRules');
    if (!checkbox) return;
    checkbox.checked = Fenris.storage.flag(IGNORE_FIREWALL_RULES_KEY, checkbox.checked);
    checkbox.addEventListener('change', () => {
        Fenris.storage.setFlag(IGNORE_FIREWALL_RULES_KEY, checkbox.checked);
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

// The tags that count for the line - those of the rules deciding its verdict -
// each with its description.
function renderLineInspectorTags(entry) {
    const section = document.getElementById('lineInspectorTagsSection');
    const list = document.getElementById('lineInspectorTags');
    if (!section || !list) {
        return;
    }
    const rows = typeof lineInspectorTagRows === 'function' ? lineInspectorTagRows(entry.tag_ids) : [];
    list.innerHTML = '';
    section.hidden = rows.length === 0;
    rows.forEach((row) => {
        const item = document.createElement('li');
        const chip = document.createElement('span');
        chip.className = `tag-chip${typeof tagChipCategoryClass === 'function' ? tagChipCategoryClass(row) : ''}`;
        chip.textContent = row.name;
        item.appendChild(chip);
        if (row.description) {
            item.appendChild(document.createTextNode(` - ${row.description}`));
        } else {
            const none = document.createElement('span');
            none.className = 'small-note';
            none.textContent = ' no description yet';
            item.appendChild(none);
        }
        list.appendChild(item);
    });
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
            `matches: ${effectiveMatches.length + shadowedMatches.length}`
            + (Array.isArray(inspection.conditional_matches) && inspection.conditional_matches.length
                ? `, conditional: ${inspection.conditional_matches.length}` : ''),
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

    renderLineInspectorTags(entry);
    if (typeof renderLineInspectorCorrelations === 'function') {
        renderLineInspectorCorrelations(entry);
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
        // Rules with conditions on facts: whether those hold depends on the
        // whole log, so the inspection (one line) lists them unchecked; the
        // line's reasons say whether they applied.
        const conditionalMatches = Array.isArray(inspection.conditional_matches) ? inspection.conditional_matches : [];
        const allMatches = [
            ...effectiveMatches.map((match) => ({ ...match, _scope: 'effective' })),
            ...shadowedMatches.map((match) => ({ ...match, _scope: 'shadowed' })),
            ...conditionalMatches.map((match) => ({ ...match, _scope: 'conditional' })),
        ];

        // A verdict this line got from another line of its block (a rule that
        // applies to its whole block): the one-line inspection cannot see the
        // block, but the line's analysis says why.
        const blockReasons = (Array.isArray(entry.reasons) ? entry.reasons : [])
            .filter((reason) => reason.includes('applies to its block'));
        blockReasons.forEach((reason) => {
            const item = document.createElement('li');
            item.textContent = `block | ${reason}`;
            matchesListEl.appendChild(item);
        });

        if (!allMatches.length && !blockReasons.length) {
            const empty = document.createElement('li');
            empty.textContent = 'No enabled rules currently match this line.';
            matchesListEl.appendChild(empty);
        } else {
            allMatches.forEach((match) => {
                const item = document.createElement('li');
                const scopeLabel = match._scope === 'effective' ? 'effective' : match._scope;
                const matcherText = match.matcher ? ` | matcher: ${match.matcher}` : '';
                const conditionsText = match._scope === 'conditional'
                    ? ' | if ' + (Array.isArray(match.conditions) ? match.conditions : []).map((condition) =>
                        `${condition.require ? 'requires' : 'forbids'} "${condition.fact}" (${condition.scope})`
                    ).join(' and ') + ' (see the line\'s reasons)'
                    : '';
                const priorityText = (match.priority !== undefined && match.priority !== null)
                    ? ` | priority: ${match.priority}`
                    : '';
                const reasonText = match.reason ? ` | reason: ${match.reason}` : '';
                const ownerText = ` | owner: ${match.owner_username || '—'}`;
                item.appendChild(document.createTextNode(`${scopeLabel} | `));
                item.appendChild(buildStatusSymbolNode(match.status));
                item.appendChild(document.createTextNode(
                    ` (${STATUS_LABEL_MAP[match.status] || 'unknown'}) | ` +
                    `${match.match_type}${priorityText}${matcherText} | ${match.source_text}${reasonText}${ownerText}${conditionsText}`,
                ));
                // The rule's tags. A shadowed rule's tags do not reach the line.
                (Array.isArray(match.tags) ? match.tags : []).forEach((tag) => {
                    item.appendChild(document.createTextNode(' '));
                    const chip = document.createElement('span');
                    chip.className = `tag-chip${typeof tagChipCategoryClass === 'function' ? tagChipCategoryClass(tag) : ''}`;
                    chip.textContent = tag.name;
                    const known = typeof ruleTagsById !== 'undefined' ? ruleTagsById.get(tag.id) : null;
                    chip.title = (known && known.description) || tag.name;
                    item.appendChild(chip);
                });
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
        // Its block: for block rules, and (a Spor entry, also of one line) the
        // block the analysis read the entry from.
        const blockIndexes = blockIndexesFor(index);
        const blockLines = Number.isInteger(entry._blockStart) || entry._blockEntryType
            ? blockIndexes.map((i) => analyzedLines[i].line || '')
            : null;
        // The analysis read an entry from the block: its first line carries it.
        const blockHead = analyzedLines[blockIndexes[0]];
        const detailsPayload = await requestLineDetails(
            entry.line || '', entry.dominant_status || '?', blockLines, Boolean(blockHead && blockHead._blockEntryType),
        );
        renderLineInspector(detailsPayload, entry);
        openLineInspectorModal(options);
    } catch (error) {
        alert(error.message || 'Failed to inspect line details.');
    } finally {
        lineInspectorInFlight = false;
    }
}

// Alert warnings are hidden where they are: each one's x hides it, and the
// first open one carries a "hide all" while two or more are open. Hidden ones
// are only put away, never removed: once any are hidden, a "⚠ n hidden alerts"
// link at the end of the toolbar brings all of them back. "hide all" is
// remembered, so the next log's alerts start hidden behind that link until it
// is clicked; a single x is not remembered.
const ANALYSIS_WARNINGS_HIDDEN_KEY = 'fenrishub_analysis_warnings_collapsed';

function getAnalysisWarningElements() {
    return [...document.querySelectorAll('#analysisWarnings > .analysis-warning')];
}

function applyAnalysisWarningsVisibility() {
    const container = document.getElementById('analysisWarnings');
    if (!container) return;
    const warnings = getAnalysisWarningElements();
    const open = warnings.filter((warning) => !warning.hidden);
    const hiddenCount = warnings.length - open.length;
    container.hidden = open.length === 0;
    warnings.forEach((warning) => {
        const hideAll = warning.querySelector('.analysis-warning-hide-all');
        if (hideAll) hideAll.hidden = !(open.length > 1 && warning === open[0]);
    });
    const restore = document.getElementById('analysisWarningsRestore');
    if (restore) {
        restore.hidden = hiddenCount === 0;
        restore.textContent = `⚠ ${hiddenCount} hidden alert${hiddenCount === 1 ? '' : 's'}`;
    }
}

function readStoredAnalysisWarningsHidden() {
    return Fenris.storage.flag(ANALYSIS_WARNINGS_HIDDEN_KEY);
}

function setAllAnalysisWarningsHidden(hidden) {
    Fenris.storage.setFlag(ANALYSIS_WARNINGS_HIDDEN_KEY, hidden);
    getAnalysisWarningElements().forEach((warning) => {
        warning.hidden = hidden;
    });
    applyAnalysisWarningsVisibility();
}

function initAnalysisWarningsRestore() {
    const restore = document.getElementById('analysisWarningsRestore');
    if (restore) {
        restore.addEventListener('click', () => setAllAnalysisWarningsHidden(false));
    }
    applyAnalysisWarningsVisibility();
}

/* The facts found in the log (payload.facts, names added when served): one
 * chip per fact; a click scrolls to the next line it was found on. Facts
 * about the whole log have no line. */
function renderFactsFound(facts) {
    const container = document.getElementById('analysisFacts');
    if (!container) return;
    const list = (Array.isArray(facts) ? facts : []).filter((fact) => fact && fact.name);
    container.innerHTML = '';
    container.hidden = list.length === 0;
    if (!list.length) return;

    const label = document.createElement('span');
    label.className = 'analysis-facts-label';
    label.textContent = 'facts found:';
    container.appendChild(label);

    list.forEach((fact) => {
        const indexes = Array.isArray(fact.line_indexes) ? fact.line_indexes : [];
        const lineNos = Array.isArray(fact.line_nos) ? fact.line_nos : [];
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.className = 'analysis-fact';
        const count = indexes.length ? ` (${indexes.length})` : '';
        chip.textContent = fact.name + count;
        const where = indexes.length
            ? `on line${lineNos.length === 1 ? '' : 's'} ${lineNos.slice(0, 10).join(', ')}${lineNos.length > 10 ? ', …' : ''}`
            : 'in the whole log';
        chip.title = (fact.description ? fact.description + '\n' : '') + 'found ' + where
            + (fact.wholelog && indexes.length ? ' and in the whole log' : '');
        if (!indexes.length) {
            chip.disabled = true;
        } else {
            let next = 0;
            chip.addEventListener('click', () => {
                // The next of the fact's lines that is shown; lines a filter
                // hides are skipped, and if all are hidden the chip says so.
                for (let tried = 0; tried < indexes.length; tried += 1) {
                    const index = indexes[next % indexes.length];
                    next += 1;
                    if (scrollToAnalyzedLine(index)) return;
                }
                flashFactChipHidden(chip);
            });
        }
        container.appendChild(chip);
    });
}

function flashFactChipHidden(chip) {
    if (!chip.dataset.label) chip.dataset.label = chip.textContent;
    chip.textContent = 'lines hidden by a filter';
    chip.classList.add('analysis-fact-hidden');
    clearTimeout(chip.hiddenTimer);
    chip.hiddenTimer = setTimeout(() => {
        chip.textContent = chip.dataset.label;
        chip.classList.remove('analysis-fact-hidden');
    }, 1800);
}

// Scrolls to an analyzed line and marks it; false when it is not shown (filtered).
function scrollToAnalyzedLine(index) {
    const badge = document.querySelector(`#logLines .status-badge[data-line-index="${index}"]`);
    const row = badge ? badge.closest('.log-line') : null;
    if (!row || row.offsetParent === null) return false;
    cancelScrollAnchorSettle();
    row.scrollIntoView({ block: 'center' });
    row.classList.remove('correlation-flash', 'correlation-flash-fade');
    void row.offsetWidth;
    row.classList.add('correlation-flash');
    setTimeout(() => {
        row.classList.add('correlation-flash-fade');
        row.classList.remove('correlation-flash');
        setTimeout(() => row.classList.remove('correlation-flash-fade'), 900);
    }, 2500);
    return true;
}

function renderWarnings(warnings) {
    const container = document.getElementById('analysisWarnings');
    const warningList = Array.isArray(warnings) ? warnings : [];
    container.innerHTML = '';
    const startHidden = readStoredAnalysisWarningsHidden();

    if (warningList.length === 0) {
        applyAnalysisWarningsVisibility();
        return;
    }
    warningList.forEach((warning) => {
        const warningElement = document.createElement('div');
        warningElement.className = 'analysis-warning';
        warningElement.hidden = startHidden;

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
        closeButton.title = 'hide this alert';
        closeButton.addEventListener('click', () => {
            warningElement.hidden = true;
            applyAnalysisWarningsVisibility();
        });

        // Shown only on the first open warning while two or more are open
        // (applyAnalysisWarningsVisibility).
        const hideAllButton = document.createElement('button');
        hideAllButton.type = 'button';
        hideAllButton.className = 'analysis-warning-hide-all';
        hideAllButton.textContent = 'hide all';
        hideAllButton.title = 'hide all alerts, also for the next logs';
        hideAllButton.hidden = true;
        hideAllButton.addEventListener('click', () => setAllAnalysisWarningsHidden(true));

        const actionsElement = document.createElement('div');
        actionsElement.className = 'analysis-warning-header-actions';
        actionsElement.appendChild(hideAllButton);
        actionsElement.appendChild(closeButton);

        headerElement.appendChild(titleElement);
        headerElement.appendChild(actionsElement);
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

        // Speeches and snippets suggested for this warning: those triggered by
        // the built-in tag of its code or by its alert rules' tags
        // (speech_suggestions.js).
        warningElement.dataset.tagIds = JSON.stringify(Array.isArray(warning.tag_ids) ? warning.tag_ids : []);
        if (typeof renderWarningSpeechRow === 'function') {
            renderWarningSpeechRow(warningElement);
        }

        container.appendChild(warningElement);
    });

    applyAnalysisWarningsVisibility();
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

    let selectedUploadId = '';
    try {
        const uploadSelect = document.getElementById('uploadSourceSelect');
        selectedUploadId = uploadSelect ? (uploadSelect.value || '').trim() : '';
        if (selectedUploadId) {
            console.log('Parsing with upload_id:', selectedUploadId);
        }
        _lineDetailsCache.clear();
        const payload = await requestLogAnalysis(logInput, selectedUploadId);
        // The background re-scan after a cached analysis mostly comes back the
        // same: drawing thousands of lines again would only freeze the page.
        if (!analysisPayloadIsShown(payload)) {
            applyAnalysisPayload(payload, { resetCopied: true, preservePendingChanges: true });
        }

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

    // applyAnalysisPayload has drawn the lines (or they are unchanged).
    if (typeof refreshCentralboxSuggestions === 'function') {
        refreshCentralboxSuggestions(selectedUploadId);
    }
    if (typeof refreshCaseCorrelations === 'function') {
        refreshCaseCorrelations(selectedUploadId);
    }

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
        // The re-render kept the line in place: focusing must not scroll it.
        // Only a badge that still ended up outside the list is brought in.
        badge.focus({ preventScroll: true });
        const list = document.getElementById('logLines');
        if (list) {
            const view = list.getBoundingClientRect();
            const rect = badge.getBoundingClientRect();
            if (rect.top < view.top || rect.bottom > view.bottom) {
                badge.scrollIntoView({ block: 'nearest' });
            }
        }
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
    // On a partially coloured line (substring, regex, file path or filepath fallback
    // decides the verdict) the badge shows the verdict but no full-line rule for
    // it exists yet. Clicking even the same status must register an override so
    // the workflow can persist a full exact/parsed rule for this line; clicking
    // the override's status again takes it back.
    const partiallyColored = verdictIsPartiallyColored(entry);

    if (currentStatus === newStatus && !partiallyColored) {
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
        // A Spor block's lines share one change, kept on its first line.
        const target = pendingTargetForIndex(index);
        const lineKey = target.key;
        const existing = pendingStatusChanges.get(lineKey);
        // A Spor block's change is its first line's: it is taken back when
        // that line would be back at its own status, not when the clicked
        // sub-line would be (that status becomes the block's rule).
        const targetBase = target.entry._baseDominantStatus || baseStatus;

        let removeOverride;
        if (partiallyColored) {
            removeOverride = Boolean(existing) && existing.new_status === newStatus;
        } else if (target.blockText) {
            removeOverride = Boolean(existing) && newStatus === targetBase;
        } else {
            removeOverride = newStatus === baseStatus;
        }

        if (removeOverride) {
            pendingStatusChanges.delete(lineKey);
        } else {
            let id = existing ? existing.id : null;
            let order = existing ? existing.order : null;

            if (!id) {
                pendingChangeSequence += 1;
                id = String(pendingChangeSequence);
                order = pendingChangeSequence;
            }

            const change = {
                id,
                order,
                line: target.entry.line,
                original_status: targetBase,
                new_status: newStatus,
            };
            if (target.blockText) {
                change.block_text = target.blockText;
            }
            pendingStatusChanges.set(lineKey, change);
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
    ['uninstall_key_path', 'registry key'],
    ['uninstall_key', 'key name'],
];

let lineCopyMenuEl = null;
let lineCopyMenuTrigger = null;
let lineSearchMenuEl = null;
let lineSearchMenuTrigger = null;

// Shared by the copy and search menus so both offer the exact same item set:
// the whole line, parsed components, and any detected URLs/domains/IPs.
function buildLineLookupItems(entry) {
    const items = [{ key: 'whole line', value: entry.line || '' }];
    const components = (entry && typeof entry.components === 'object') ? entry.components : {};
    LINE_COPY_COMPONENT_LABELS.forEach(([key, label]) => {
        const value = components ? components[key] : '';
        if (value) {
            items.push({ key: label, value });
        }
    });

    // Refanged URLs, bare domains and IPs detected in the line, so the user can act
    // on the resolvable form directly without retyping (defanged "hxxp://..." → "http://...").
    const lookupKeys = { url: 'url', domain: 'domain', ipv4: 'ip', ipv6: 'ip' };
    const seenLookups = new Set();
    for (const span of findHighlightSpans(entry.line || '')) {
        const key = lookupKeys[span.type];
        if (!key) continue;
        const value = span.type === 'url' ? refangUrl(span.text) : span.text;
        if (seenLookups.has(value)) continue;
        seenLookups.add(value);
        items.push({ key, value });
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

// A named global (not Fenris.copyText directly) so tests can stub it.
function copyToClipboard(value) {
    return Fenris.copyText(value);
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

    const items = buildLineLookupItems(entry);
    // Hashes of the line's files found in related logs (case_correlations.js),
    // shown with the file each belongs to; only the hash is copied.
    if (typeof correlationHashValues === 'function') {
        correlationHashValues(caseCorrelationsFor(entry)).forEach((found) => {
            items.push({
                key: found.hash.length === 64 ? 'sha256' : 'md5', value: found.hash, label: correlationHashLabel(found),
            });
        });
    }

    PopupMenu.fill(menu, 'copy to clipboard', items.map(({ key, value, label }) => ({
        key, value, label,
        run: async () => {
            const ok = await copyToClipboard(value);
            if (!ok) {
                alert('Failed to copy to clipboard.');
            }
            closeLineCopyMenu();
        },
    })));

    menu.hidden = false;
    if (lineCopyMenuTrigger && lineCopyMenuTrigger !== trigger) {
        lineCopyMenuTrigger.setAttribute('aria-expanded', 'false');
    }
    lineCopyMenuTrigger = trigger;
    trigger.setAttribute('aria-expanded', 'true');
    PopupMenu.place(menu, trigger);
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

    // Hashes of the line's file found in related logs (case_correlations.js):
    // looked up on VirusTotal, like the hash menus of the log page.
    const correlatedHashes = typeof correlationHashValues === 'function'
        ? correlationHashValues(caseCorrelationsFor(entry)) : [];

    const items = buildLineLookupItems(entry).map(({ key, value }) => ({
        key, value, url: 'https://www.google.com/search?q=' + encodeURIComponent(value),
    }));
    correlatedHashes.forEach((found) => {
        const { hash } = found;
        const value = correlationHashLabel(found);
        items.push({ key: 'virustotal', value, url: 'https://www.virustotal.com/gui/file/' + hash });
        // centralbox reports exist for SHA-256 only (as in the log view's search menu).
        if (hash.length === 64) items.push({ key: 'centralbox', value, url: 'https://centralbox.dev/analysis/' + hash });
    });

    PopupMenu.fill(menu, correlatedHashes.length ? 'search' : 'search on google', items.map(({ key, value, url }) => ({
        key, value,
        run: () => {
            Fenris.openUrl(url);
            closeLineSearchMenu();
        },
    })));

    menu.hidden = false;
    if (lineSearchMenuTrigger && lineSearchMenuTrigger !== trigger) {
        lineSearchMenuTrigger.setAttribute('aria-expanded', 'false');
    }
    lineSearchMenuTrigger = trigger;
    trigger.setAttribute('aria-expanded', 'true');
    PopupMenu.place(menu, trigger);
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
// Punctuation that ends the surrounding log text rather than the URL itself.
// FRST joins several URLs on one line with "; " (e.g. `FF Notifications: ... ->
// hxxps://a.example; hxxps://b.example`), and sentences/lists leave a trailing
// `.`, `,` or `:` glued to the match — none of it belongs in a VT/urlscan lookup.
const URL_TRAILING_PUNCT_RE = /[;,.:!?]+$/;

// Shared with the log page (common.js).
function refangUrl(v) {
    return Fenris.refangUrl(v);
}
// DNS contexts where a bare hostname follows the bracketed keyword.
const DNS_DOMAIN_CTX_RE = /\[Dhcp(?:Domain(?:SearchList)?)\]\s*/g;
const BARE_DOMAIN_RE = /\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b/gi;

// The lookups themselves are shared with the log page and the correlation
// info box (common.js: Fenris.lookups).
const IP_LOOKUP_ITEMS = [...Fenris.lookups.ip, { label: 'copy ip instead', copy: true }];

const LOOKUP_KINDS = {
    'chrome-ext-id': {
        title: (v) => `Chrome extension ID: ${v}`,
        menuHeader: 'open extension id in',
        items: [
            { label: 'crxplorer', url: (v) => `https://crxplorer.com/extension/${v}` },
            { label: 'crxaminer', url: (v) => `https://crxaminer.tech/scan/${v}` },
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
            // Edge also installs Chrome Web Store extensions, which keep their store ID.
            { label: 'crxplorer', url: (v) => `https://crxplorer.com/extension/${v}` },
            { label: 'crxaminer', url: (v) => `https://crxaminer.tech/scan/${v}` },
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
        items: [...Fenris.lookups.url, { label: 'copy url instead', copy: refangUrl }],
    },
    'domain': {
        title: (v) => `domain: ${v}`,
        menuHeader: 'open domain in',
        items: [...Fenris.lookups.domain, { label: 'copy domain instead', copy: true }],
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

function collectUrlSpans(line) {
    const out = [];
    URL_RE.lastIndex = 0;
    let m;
    while ((m = URL_RE.exec(line)) !== null) {
        const text = m[0].replace(URL_TRAILING_PUNCT_RE, '');
        if (!text) continue;
        out.push({
            start: m.index,
            end: m.index + text.length,
            type: 'url',
            text,
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
    spans.push(...collectUrlSpans(line));
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

// The parts of a line coloured on their own, on top of the line's own colour
// (css_class): matched substrings and regex matches, file paths, and pending
// rules' tokens. Clamped
// to the line, sorted, and trimmed so no two overlap.
function collectPartialHighlights(entry) {
    if (!entry || !Array.isArray(entry.highlights)) {
        return [];
    }
    const line = entry.line || '';
    const clamped = entry.highlights
        .filter((hl) => hl && Number.isInteger(hl.start) && Number.isInteger(hl.end))
        .map((hl) => ({
            start: Math.max(0, Math.min(hl.start, line.length)),
            end: Math.max(0, Math.min(hl.end, line.length)),
            css_class: STATUS_CLASS_MAP[hl.status] || 'status-unknown',
        }))
        .filter((hl) => hl.end > hl.start)
        .sort((a, b) => a.start - b.start);

    const highlights = [];
    let lastEnd = 0;
    for (const hl of clamped) {
        const start = Math.max(hl.start, lastEnd);
        if (start >= hl.end) continue;
        highlights.push({ ...hl, start });
        lastEnd = hl.end;
    }
    return highlights;
}

function appendLineTextWithDateHighlight(textEl, line, highlights = []) {
    const innerSpans = findHighlightSpans(line);

    if (!innerSpans.length && !highlights.length) {
        textEl.textContent = line;
        return;
    }

    // Colour is the innermost layer: [start, end) goes out as text split at the
    // highlight edges. A highlight can then begin or end anywhere -- even inside
    // a lookup trigger -- and the trigger still comes out whole and clickable.
    function appendColouredText(parent, start, end) {
        let cursor = start;
        for (const hl of highlights) {
            if (hl.end <= cursor) continue;
            if (hl.start >= end) break;
            const from = Math.max(hl.start, cursor);
            const to = Math.min(hl.end, end);
            if (from > cursor) {
                parent.appendChild(document.createTextNode(line.slice(cursor, from)));
            }
            const piece = document.createElement('span');
            piece.className = `partial-highlight ${hl.css_class || ''}`.trim();
            piece.textContent = line.slice(from, to);
            parent.appendChild(piece);
            cursor = to;
        }
        if (cursor < end) {
            parent.appendChild(document.createTextNode(line.slice(cursor, end)));
        }
    }

    let cursor = 0;
    for (const span of innerSpans) {
        if (span.start > cursor) {
            appendColouredText(textEl, cursor, span.start);
        }
        const node = buildInnerHighlightNode(span);
        node.textContent = '';
        appendColouredText(node, span.start, span.end);
        textEl.appendChild(node);
        cursor = span.end;
    }
    if (cursor < line.length) {
        appendColouredText(textEl, cursor, line.length);
    }
}

let lookupMenuEl = null;
let lookupMenuTrigger = null;

// Statuses offerable as a rule from the lookup menu. `?` is dropped from
// EDITABLE_STATUSES because a `?` rule carries no classification and is
// discarded server-side as a no-op.
const LOOKUP_RULE_STATUSES = EDITABLE_STATUSES.filter((status) => status !== '?');

// Guests can queue nothing — the persist endpoint rejects them — so the rule
// item is hidden rather than offered and then failing at save time.
function canCreateLookupRules() {
    return Boolean(CURRENT_USERNAME) && !GUEST_TOKEN && Boolean(PERSIST_RULE_CHANGES_URL);
}

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

function positionLookupMenu(menu, trigger) {
    PopupMenu.place(menu, trigger, { align: 'left', fallbackWidth: 220 });
}

function appendLookupMenuHeader(menu, text) {
    const header = document.createElement('div');
    header.className = 'lookup-menu-header';
    header.textContent = text;
    menu.appendChild(header);
}

function createLookupMenuButton(label, extraClass = '') {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = extraClass ? `lookup-menu-item ${extraClass}` : 'lookup-menu-item';
    btn.setAttribute('role', 'menuitem');
    btn.textContent = label;
    return btn;
}

// Second page of the same popup: the lookup items are swapped out for the status
// list in place, so the menu keeps the positioning and dismissal wiring it
// already has instead of needing a nested popup.
function renderLookupStatusMenu(menu, trigger, value, kind) {
    menu.innerHTML = '';
    appendLookupMenuHeader(menu, 'queue substring rule as');

    LOOKUP_RULE_STATUSES.forEach((status) => {
        const label = `${status}  ${STATUS_LABEL_MAP[status] || 'unknown'}`;
        const btn = createLookupMenuButton(label, STATUS_CLASS_MAP[status] || 'status-unknown');
        btn.setAttribute('aria-label', `Queue substring rule with status ${STATUS_LABEL_MAP[status] || 'unknown'}`);
        btn.addEventListener('click', (event) => {
            event.preventDefault();
            if (btn.disabled) return;
            btn.disabled = true;
            // Queued, not written: the rule is persisted with everything else
            // when the analyst saves rules, so it still goes through the preview
            // and conflict review first. It classifies the current lines right
            // away all the same, so the effect is visible before saving.
            queueTokenRule(value, status);
            applyPendingOverrides();
            updateSummary(summarizeEffectiveStatuses(analyzedLines), analyzedLines.length);
            renderLogLines();
            scheduleDraftSave();
            btn.textContent = 'queued for save';
            setTimeout(() => closeLookupMenu(), 800);
        });
        menu.appendChild(btn);
    });

    const back = createLookupMenuButton('back', 'lookup-menu-separator');
    back.addEventListener('click', (event) => {
        event.preventDefault();
        renderLookupItemsMenu(menu, trigger, value, kind);
    });
    menu.appendChild(back);

    positionLookupMenu(menu, trigger);
}

function renderLookupItemsMenu(menu, trigger, value, kind) {
    const config = LOOKUP_KINDS[kind];
    if (!config) return;

    menu.innerHTML = '';
    appendLookupMenuHeader(menu, config.menuHeader);

    config.items.forEach((item) => {
        // `copy` is either `true` (copy the token as shown) or a function that
        // maps it first, e.g. refangUrl so a copied URL is the resolvable form.
        if (item.copy) {
            const btn = createLookupMenuButton(item.label);
            btn.addEventListener('click', async (event) => {
                event.preventDefault();
                const text = typeof item.copy === 'function' ? item.copy(value) : value;
                if (await copyToClipboard(text)) {
                    btn.textContent = 'copied';
                    setTimeout(() => closeLookupMenu(), 600);
                } else {
                    btn.textContent = 'copy failed';
                    setTimeout(() => closeLookupMenu(), 800);
                }
            });
            menu.appendChild(btn);
            return;
        }
        // A lookup that doesn't apply to this value (a URL without a host).
        const href = item.url(value);
        if (!href) return;
        const link = document.createElement('a');
        link.className = 'lookup-menu-item';
        link.setAttribute('role', 'menuitem');
        link.href = href;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.textContent = item.label;
        link.addEventListener('click', () => closeLookupMenu());
        menu.appendChild(link);
    });

    // `value` is the token exactly as the log line carries it, never the
    // refanged form: refangUrl exists to make external lookups resolve, but a
    // rule has to match the text that is actually in the log.
    if (canCreateLookupRules()) {
        const ruleBtn = createLookupMenuButton('queue substring rule', 'lookup-menu-separator');
        ruleBtn.addEventListener('click', (event) => {
            event.preventDefault();
            renderLookupStatusMenu(menu, trigger, value, kind);
        });
        menu.appendChild(ruleBtn);
    }

    positionLookupMenu(menu, trigger);
}

function openLookupMenu(trigger, value, kind) {
    if (lookupMenuTrigger === trigger && lookupMenuEl && !lookupMenuEl.hidden) {
        closeLookupMenu();
        return;
    }

    if (!LOOKUP_KINDS[kind]) return;

    const menu = ensureLookupMenu();

    if (lookupMenuTrigger && lookupMenuTrigger !== trigger) {
        lookupMenuTrigger.setAttribute('aria-expanded', 'false');
    }
    lookupMenuTrigger = trigger;
    trigger.setAttribute('aria-expanded', 'true');

    menu.hidden = false;
    renderLookupItemsMenu(menu, trigger, value, kind);
}

function setupLookupMenu() {
    document.addEventListener('click', () => closeLookupMenu());
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeLookupMenu();
    });
    window.addEventListener('resize', () => closeLookupMenu());
    document.addEventListener('scroll', () => closeLookupMenu(), true);
}

// The hover text is a native title tooltip, which the browser cuts off once it
// gets too long. Reasons (each ending in its rule's "(by owner)") go first so a
// long line can only push itself out of view, and the line is capped because
// its full text is already on the page.
const LINE_TOOLTIP_MAX_LINE_CHARS = 300;

// The line's rule tags, when it has any, come first of all, one row each with
// its description: they name what the line belongs to, the reasons say why.
function buildLineTooltip(line, reasons, tags = []) {
    const shownLine = line.length > LINE_TOOLTIP_MAX_LINE_CHARS
        ? `${line.slice(0, LINE_TOOLTIP_MAX_LINE_CHARS)}…`
        : line;
    const body = reasons.length > 0 ? `${reasons.join('\n')}\n\n${shownLine}` : shownLine;
    if (!tags.length) {
        return body;
    }
    const tagRows = tags.map((tag) => (tag.description ? `tag: ${tag.name} - ${tag.description}` : `tag: ${tag.name}`));
    return `${tagRows.join('\n')}\n\n${body}`;
}

// Deeper indentation is shown at this width, so the text stays readable.
const MAX_LINE_INDENT_CH = 16;

// The topmost line in view and how far it sits below the top of the list.
// A rebuild keeps that line in place rather than the scroll offset in pixels:
// with word wrap on, rows off screen (content-visibility) are new elements of
// the estimated height, not their real one, so the same scrollTop would show
// other lines and the view would jump a little.
function isShownLogLine(row) {
    return Boolean(row && row.dataset.lineIndex) && row.getBoundingClientRect().height > 0;
}

// The shown log line at or after row (blank spacers and lines hidden by a
// filter are skipped), else the nearest one before it.
function nearestShownLogLine(row) {
    for (let r = row; r; r = r.nextElementSibling) {
        if (isShownLogLine(r)) return r;
    }
    for (let r = row && row.previousElementSibling; r; r = r.previousElementSibling) {
        if (isShownLogLine(r)) return r;
    }
    return null;
}

// The row at the top edge of the list, asked of the browser (a scan from the
// first row measures every row above the view: thousands in a big log).
// elementsFromPoint, not elementFromPoint: the status picker may lie on top.
function rowAtTopOfList(container) {
    const view = container.getBoundingClientRect();
    const x = view.left + container.clientLeft + 1;
    const y = view.top + container.clientTop + 1;
    for (const element of document.elementsFromPoint(x, y)) {
        let row = element;
        while (row && row.parentElement !== container) row = row.parentElement;
        if (row) return row;
    }
    return null;
}

function captureScrollAnchor(container) {
    const top = container.getBoundingClientRect().top;
    let row = rowAtTopOfList(container);
    row = row ? nearestShownLogLine(row) : null;
    if (!row) {
        // The list's top is off screen (page scrolled): scan for it.
        for (const child of container.children) {
            if (isShownLogLine(child) && child.getBoundingClientRect().bottom > top) {
                row = child;
                break;
            }
        }
    }
    if (!row) return null;
    return { lineIndex: row.dataset.lineIndex, offset: row.getBoundingClientRect().top - top };
}

// The anchor line, or the nearest shown one if it is hidden now (e.g. set to a
// status the legend filter hides), goes back to where the anchor line was.
function restoreScrollAnchor(container, anchor) {
    if (!anchor) return null;
    const row = nearestShownLogLine(
        container.querySelector(`:scope > .log-line[data-line-index="${anchor.lineIndex}"]`)
    );
    if (!row) return null;
    const top = container.getBoundingClientRect().top;
    container.scrollTop += (row.getBoundingClientRect().top - top) - anchor.offset;
    return row;
}

// The content height a row not laid out yet gets (contain-intrinsic-size in
// log_analyzer.css): one line. Its padding and border come on top.
const ROW_CONTENT_ESTIMATE_PX = 16;

// The vertical padding and border of a row: offsetHeight less these is the
// content height that contain-intrinsic-size takes.
function rowFrameHeight(row) {
    const style = getComputedStyle(row);
    return ['paddingTop', 'paddingBottom', 'borderTopWidth', 'borderBottomWidth']
        .reduce((sum, key) => sum + (parseFloat(style[key]) || 0), 0);
}

// The content height of every row whose height is not the estimate, before a
// rebuild: lines by index, blank spacer rows by the line they stand before and
// their countdown position in that gap (as renderLogLines builds them). A
// rebuilt row starts at that height (applyRowHeight). Without it, every row
// came back at the estimate and took its real (e.g. wrapped) height as it came
// near the view, and the lines in view moved. Rows at the estimate (one line,
// or never laid out) and rows hidden by a filter (0) are left out.
function captureRowHeights(container) {
    const heights = new Map();
    if (document.body.classList.contains('no-word-wrap')) return heights;
    let lineFrame = null;
    let spacerFrame = null;
    const contentHeight = (row, frame) => {
        const height = row.offsetHeight;
        if (height === 0) return 0;
        const content = height - frame;
        return content > 0 && content !== ROW_CONTENT_ESTIMATE_PX ? content : 0;
    };
    let spacers = [];
    for (const child of container.children) {
        if (child.classList.contains('log-blank-line')) {
            if (spacerFrame === null) spacerFrame = rowFrameHeight(child);
            spacers.push(contentHeight(child, spacerFrame));
            continue;
        }
        const lineIndex = child.dataset.lineIndex;
        if (lineIndex === undefined) continue;
        spacers.forEach((content, position) => {
            if (content) heights.set(`${lineIndex}:${spacers.length - position}`, content);
        });
        spacers = [];
        if (lineFrame === null) lineFrame = rowFrameHeight(child);
        const content = contentHeight(child, lineFrame);
        if (content) heights.set(lineIndex, content);
    }
    return heights;
}

function applyRowHeight(row, heights, key) {
    const height = heights.get(key);
    if (height) row.style.containIntrinsicSize = `auto ${height}px`;
}

// Backstop for rows whose height did change (the changed line, a line shown
// anew): for a few frames, while the browser lays out the rows near the view,
// the anchor line is put back where it was if it moved. It stops once the line
// stays put, on the next render, or when the list is scrolled on purpose
// (cancelScrollAnchorSettle: the user's input, a jump to a line).
const SCROLL_SETTLE_MAX_FRAMES = 10;
let scrollAnchorFrameToken = 0;
let scrollSettleInputWatched = false;

function cancelScrollAnchorSettle() {
    scrollAnchorFrameToken += 1;
}

function settleScrollAnchor(container, row, offset) {
    const token = ++scrollAnchorFrameToken;
    if (!scrollSettleInputWatched) {
        scrollSettleInputWatched = true;
        ['wheel', 'pointerdown', 'keydown', 'touchstart'].forEach((type) => {
            document.addEventListener(type, cancelScrollAnchorSettle, { capture: true, passive: true });
        });
    }
    let frame = 0;
    let still = 0;
    const step = () => {
        if (token !== scrollAnchorFrameToken || !row.isConnected) return;
        const top = container.getBoundingClientRect().top;
        const drift = (row.getBoundingClientRect().top - top) - offset;
        if (Math.abs(drift) >= 1) {
            container.scrollTop += drift;
            still = 0;
        } else {
            still += 1;
        }
        frame += 1;
        if (still < 2 && frame < SCROLL_SETTLE_MAX_FRAMES) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
}

function renderLogLines() {
    const container = document.getElementById('logLines');
    const savedScrollTop = container.scrollTop;
    const scrollAnchor = savedScrollTop > 0 ? captureScrollAnchor(container) : null;
    const rowHeights = captureRowHeights(container);
    // Lines still waiting to be shown (shared.js queueReveal) are replaced.
    if (typeof dropFromReveal === 'function') dropFromReveal(() => true);
    container.innerHTML = '';
    // Blank lines of the log, put back between entries as inert spacer rows
    // (the analysis itself has none). They carry no index, so every
    // index-based action below is unaffected.
    const logInputElement = document.getElementById('logInput');
    const blankGaps = typeof computeBlankLineGaps === 'function'
        ? computeBlankLineGaps(logInputElement ? logInputElement.value : '', analyzedLines)
        : null;
    // The log's own indentation (e.g. Spor sub-lines under their item), for
    // display only: entries are stripped, and rules match the stripped line.
    const lineIndents = typeof computeLineIndents === 'function'
        ? computeLineIndents(logInputElement ? logInputElement.value : '', analyzedLines)
        : null;

    analyzedLines.forEach((entry, index) => {
        for (let blank = blankGaps ? blankGaps[index] : 0; blank > 0; blank -= 1) {
            const spacer = document.createElement('div');
            spacer.className = 'log-blank-line';
            spacer.setAttribute('aria-hidden', 'true');
            applyRowHeight(spacer, rowHeights, `${index}:${blank}`);
            container.appendChild(spacer);
        }
        const line = entry.line;
        const cssClass = entry.css_class || 'status-unknown';
        const status = entry.dominant_status || '?';
        // Badge always reflects the verdict's colour even when the line itself is
        // coloured differently (e.g. only a matched substring, regex match or path is coloured,
        // or a lower-priority rule colours the line).
        const badgeClass = STATUS_CLASS_MAP[status] || 'status-unknown';

        const lineDiv = document.createElement('div');
        lineDiv.className = copiedLineIndexes.has(index)
            ? `log-line ${cssClass} copied`
            : `log-line ${cssClass}`;
        // The legend filter hides lines by VERDICT, so it reads this attribute
        // rather than cssClass -- a line coloured only in part is styled
        // 'status-unknown' but its verdict (and its legend count) is the badge's status.
        lineDiv.dataset.verdictClass = badgeClass;
        // The tag filter re-marks lines in place by this (applyTagFilterMatches).
        lineDiv.dataset.lineIndex = String(index);

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
        appendLineTextWithDateHighlight(text, line, collectPartialHighlights(entry));
        const indent = lineIndents ? lineIndents[index] : 0;
        if (indent > 0) {
            text.style.paddingLeft = `${Math.min(indent, MAX_LINE_INDENT_CH)}ch`;
        }

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

        // The line's buttons in one block: with word wrap off it stays at the
        // right edge of the view even when the line is cut off (log_analyzer.css).
        const actions = document.createElement('span');
        actions.className = 'line-actions';
        actions.appendChild(copyBtn);
        actions.appendChild(searchBtn);

        lineDiv.appendChild(badge);
        lineDiv.appendChild(text);
        lineDiv.appendChild(actions);

        const reasons = Array.isArray(entry.reasons) ? entry.reasons : [];
        const lineTags = typeof ruleTagsFor === 'function' ? ruleTagsFor(entry.tag_ids) : [];
        lineDiv.title = buildLineTooltip(line, reasons, lineTags);
        // The line's tags as chips, so they show without hovering; clicking
        // one lists the tag's speeches and snippets.
        // has-chips / has-correlation: what the line holds, as classes for
        // log_analyzer.css (cheaper than :has() rules on thousands of lines).
        if (lineTags.length && typeof buildLineTagChips === 'function') {
            const chipBox = document.createElement('span');
            chipBox.className = 'line-tag-chips';
            buildLineTagChips(entry.tag_ids).forEach((chip) => chipBox.appendChild(chip));
            lineDiv.insertBefore(chipBox, actions);
            lineDiv.classList.add('has-chips');
        }
        // What other logs of the case say about the line's file (case_correlations.js).
        // Last, at the right edge: the copy / search icons appear in front of
        // it on hover, so it never moves under the pointer.
        if (typeof buildCaseCorrelationButton === 'function') {
            const correlationButton = buildCaseCorrelationButton(entry);
            if (correlationButton) {
                actions.appendChild(correlationButton);
                actions.classList.add('has-correlation');
                lineDiv.classList.add('has-correlation');
            }
        }
        // A "suggested B" from centralbox (centralbox_suggestions.js), if any.
        if (typeof buildCentralboxSuggestionChip === 'function') {
            const suggestionChip = buildCentralboxSuggestionChip(entry, index);
            if (suggestionChip) {
                lineDiv.insertBefore(suggestionChip, actions);
                lineDiv.classList.add('has-chips');
            }
        }
        // The tag filter (speech_suggestions.js) hides lines without this class.
        if (typeof lineMatchesTagFilter === 'function' && lineMatchesTagFilter(entry)) {
            lineDiv.classList.add('tag-filter-match');
        }
        lineDiv.addEventListener('click', (event) => {
            if (questionCursorModeActive) {
                openLineInspectorForIndex(index, { triggerElement: lineDiv });
                return;
            }
            if (cleanCursorModeActive) {
                saveStatusSelection(index, 'C');
                return;
            }
            // Writing the response: the line's speech goes in, not the line.
            if (activeRightPanel === 'response' && typeof handleResponseLineClick === 'function') {
                handleResponseLineClick(entry, lineDiv, event);
                return;
            }
            if (copiedLineIndexes.has(index)) {
                removeLine(line, index);
            } else {
                insertLine(line, index);
            }
        });
        applyRowHeight(lineDiv, rowHeights, String(index));
        container.appendChild(lineDiv);
    });
    const anchorRow = restoreScrollAnchor(container, scrollAnchor);
    if (anchorRow) {
        settleScrollAnchor(container, anchorRow, scrollAnchor.offset);
    } else {
        container.scrollTop = savedScrollTop;
    }
}

// Case correlations or centralbox suggestions arrived (case_correlations.js,
// centralbox_suggestions.js): each line gets its info icon and suggestion
// chip anew, in place, like renderLogLines would draw them; the rest of the
// lines stays. A big log has thousands: rebuilding them all froze the page.
function refreshLineExtras() {
    const container = document.getElementById('logLines');
    if (!container) {
        return;
    }
    container.querySelectorAll(':scope > .log-line').forEach((lineDiv) => {
        const index = Number(lineDiv.dataset.lineIndex);
        const entry = analyzedLines[index];
        const actions = lineDiv.querySelector(':scope > .line-actions');
        if (!entry || !actions) {
            return;
        }
        const oldButton = actions.querySelector(':scope > .line-correlation-trigger');
        if (oldButton) oldButton.remove();
        const button = typeof buildCaseCorrelationButton === 'function' ? buildCaseCorrelationButton(entry) : null;
        if (button) actions.appendChild(button);
        actions.classList.toggle('has-correlation', Boolean(button));
        lineDiv.classList.toggle('has-correlation', Boolean(button));

        const oldChip = lineDiv.querySelector(':scope > .centralbox-suggestion-chip');
        if (oldChip) oldChip.remove();
        const chip = typeof buildCentralboxSuggestionChip === 'function'
            ? buildCentralboxSuggestionChip(entry, index) : null;
        if (chip) lineDiv.insertBefore(chip, actions);
        lineDiv.classList.toggle('has-chips', Boolean(chip || lineDiv.querySelector(':scope > .line-tag-chips')));
    });
    // The "correlated" tag filter depends on the correlations.
    applyTagFilterMatches();
}

// The tag filter (speech_suggestions.js setTagFilter): re-marks the rendered
// lines in place instead of rebuilding them all (a big log has thousands).
function applyTagFilterMatches() {
    const container = document.getElementById('logLines');
    if (!container) {
        return;
    }
    const matches = typeof lineMatchesTagFilter === 'function' ? lineMatchesTagFilter : () => false;
    container.querySelectorAll(':scope > .log-line').forEach((lineDiv) => {
        const entry = analyzedLines[Number(lineDiv.dataset.lineIndex)];
        lineDiv.classList.toggle('tag-filter-match', Boolean(entry) && matches(entry));
    });
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
        // A Spor block is one change, on its first line: only for a block that
        // is unknown on every line, with none of them excluded.
        const target = pendingTargetForIndex(index);
        const lines = target.blockText !== null
            ? blockIndexesFor(target.entry._index).map((i) => analyzedLines[i])
            : [entry];
        if (lines.some((line) => (line.dominant_status || '?') !== '?')) continue;
        if (lines.some((line) => exclusions.some((ex) => (line.line || '').includes(ex)))) continue;

        const lineKey = target.key;
        if (pendingStatusChanges.has(lineKey)) continue;

        pendingChangeSequence += 1;
        const change = {
            id: String(pendingChangeSequence),
            order: pendingChangeSequence,
            line: target.entry.line,
            original_status: '?',
            new_status: 'C',
        };
        if (target.blockText) {
            change.block_text = target.blockText;
        }
        pendingStatusChanges.set(lineKey, change);
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

    addField('csrfmiddlewaretoken', Fenris.csrfToken());
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