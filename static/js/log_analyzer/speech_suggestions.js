// Suggesting speeches and snippets for the log in front of the analyst, and
// showing the log's rule tags.
//
// A speech or snippet names the rule tags it fits. After every analysis the
// ones whose tags were found in the log are listed under "suggested" at the
// top of the speeches and snippets menus, and each warning box lists those
// for its own tags (the built-in tag of a hardcoded warning, or its alert
// rules' tags). Nothing is inserted on its own - the analyst still picks.
//
// A speech already in the response is not suggested again: it counts as
// present when its longest fixed passage (the text between placeholders) is
// found in the response, so a reply reloaded from a saved fixlist counts too,
// and deleting the text brings the suggestion back.
//
// Snippets go into whichever right panel is showing, so a snippet is not
// suggested while every one of its lines is already in that panel: one in the
// fixlist is still suggested in the response view, and the other way round.
//
// The tags themselves are drawn in the status legend's second row and as
// chips on each tagged log line, with their notes as tooltips. Clicking a tag
// filters the log to its lines. With the response panel open, clicking a
// tagged log line adds its speech.

let ruleTagsById = new Map();
let lastAnalysisPayload = null;
let activeTagFilterId = null;

const SPEECH_FINGERPRINT_MIN_LENGTH = 12;
const speechFingerprintCache = new Map();

function normalizeForMatch(text) {
    return String(text || '').replace(/\s+/g, ' ').trim().toLowerCase();
}

// The longest fixed passage of a speech, normalized, or '' when it has none
// long enough to recognise it by. Placeholders are filled on insert, so only
// the text between them is the same in the response.
function speechFingerprint(content) {
    const key = String(content || '');
    if (speechFingerprintCache.has(key)) {
        return speechFingerprintCache.get(key);
    }
    // Punctuation at the ends is dropped: the comma after "Hi {USERNAME}" is
    // part of the greeting, not of the passage.
    const pieces = key.split(/\{[A-Z_]+\}/)
        .map((piece) => normalizeForMatch(piece).replace(/^[^a-z0-9]+|[^a-z0-9]+$/g, ''));
    const longest = pieces.reduce((best, piece) => (piece.length > best.length ? piece : best), '');
    const fingerprint = longest.length >= SPEECH_FINGERPRINT_MIN_LENGTH ? longest : '';
    speechFingerprintCache.set(key, fingerprint);
    return fingerprint;
}

function speechIsInResponse(speech, responseText) {
    const fingerprint = speechFingerprint(speech.content);
    return Boolean(fingerprint) && normalizeForMatch(responseText).includes(fingerprint);
}

function withoutUsedSpeeches(speeches, responseText) {
    const normalized = normalizeForMatch(responseText);
    return (speeches || []).filter((speech) => {
        const fingerprint = speechFingerprint(speech.content);
        return !(fingerprint && normalized.includes(fingerprint));
    });
}

function currentResponseText() {
    const textarea = document.getElementById('responseText');
    return textarea ? textarea.value : '';
}

// The panel a snippet would go into right now (fixlist or response).
function currentSnippetTargetText() {
    const textarea = typeof getActiveRightTextarea === 'function'
        ? getActiveRightTextarea()
        : document.getElementById('selectedLines');
    return textarea ? textarea.value : '';
}

const LINE_TAG_CHIP_LIMIT = 3;

// Tags and speeches are listed alphabetically everywhere.
function byName(left, right) {
    return String(left.name || '').localeCompare(String(right.name || ''), undefined, { sensitivity: 'base' });
}

// Pure, so the test page can drive it directly. Snippets carry
// `trigger_tag_ids` too, so this serves both.
function speechesForTags(tagIds, speeches) {
    const found = new Set(tagIds || []);
    if (!found.size) {
        return [];
    }
    return (speeches || [])
        .filter((speech) => (speech.trigger_tag_ids || []).some((id) => found.has(id)))
        .sort(byName);
}

// The tags among `tagIds` that none of `selected` names.
function uncoveredTagIds(tagIds, selected) {
    const covered = new Set();
    (selected || []).forEach((item) => {
        (item.trigger_tag_ids || []).forEach((id) => covered.add(id));
    });
    return (tagIds || []).filter((id) => !covered.has(id));
}

// The trimmed, non-empty lines of `text`.
function nonEmptyLines(text) {
    return String(text || '').replace(/\r\n/g, '\n').split('\n')
        .map((line) => line.trim())
        .filter(Boolean);
}

// A snippet is in `text` when every one of its non-empty lines is a line of it.
function snippetIsInText(snippet, text) {
    const wanted = nonEmptyLines(snippet && snippet.content);
    if (!wanted.length) {
        return false;
    }
    const present = new Set(nonEmptyLines(text));
    return wanted.every((line) => present.has(line));
}

function withoutUsedSnippets(snippets, text) {
    return (snippets || []).filter((snippet) => !snippetIsInText(snippet, text));
}

// The analyst's selected snippets for `tagIds` that are not in `text` yet.
function suggestedSnippetsForTags(tagIds, snippets, text = '') {
    return withoutUsedSnippets(speechesForTags(tagIds, snippets), text);
}

// Other helpers' shared snippets for the tags no selected snippet covers,
// the snippet side of fallbackSpeechesForTags.
function fallbackSnippetsForTags(tagIds, selectedSnippets, sharedSnippets, text = '') {
    return withoutUsedSnippets(
        speechesForTags(uncoveredTagIds(tagIds, selectedSnippets), sharedSnippets), text,
    );
}

// "insert all" adds the menu's speeches in the order the menu lists them.
function speechesToInsertAll(speeches) {
    return [...(speeches || [])].sort(byName);
}

function computeSuggestedSpeechIds(speeches, tagIds, responseText = '') {
    return withoutUsedSpeeches(speechesForTags(tagIds, speeches), responseText).map((speech) => speech.id);
}

// Other helpers' shared speeches for the tags among `tagIds` that none of the
// analyst's own selected speeches covers - a covered tag gets no fallback,
// even when its own speech is already in the response.
function fallbackSpeechesForTags(tagIds, selectedSpeeches, sharedSpeeches, responseText = '') {
    return withoutUsedSpeeches(
        speechesForTags(uncoveredTagIds(tagIds, selectedSpeeches), sharedSpeeches), responseText,
    );
}

// The speeches a click on `entry` (a log line) can add to the response: the
// analyst's own first, other helpers' shared ones when no own speech fits.
function speechesForLineClick(entry, speeches, responseText, sharedSpeeches = []) {
    const tagIds = (entry || {}).tag_ids;
    const own = withoutUsedSpeeches(speechesForTags(tagIds, speeches), responseText);
    if (own.length) {
        return own;
    }
    return fallbackSpeechesForTags(tagIds, speeches, sharedSpeeches, responseText);
}

// {id, name, description, category_id} of the tags in `tagIds`, alphabetically, for tooltips and chips.
function ruleTagsFor(tagIds) {
    return (tagIds || [])
        .map((id) => ruleTagsById.get(id))
        .filter(Boolean)
        .map((tag) => ({
            id: tag.id,
            name: tag.name,
            description: tag.description || '',
            category_id: tag.category_id || null,
        }))
        .sort(byName);
}

// {name, description, category_id} rows for the line inspector's tags section.
function lineInspectorTagRows(tagIds) {
    return ruleTagsFor(tagIds).map((tag) => ({
        name: tag.name,
        description: tag.description,
        category_id: tag.category_id,
    }));
}

// The class giving a tag badge its category colour (rule_tag_picker.js), '' without one.
function tagChipCategoryClass(tag) {
    return typeof tagCategoryClass === 'function' ? tagCategoryClass(tag) : '';
}

function toggleTagFilterFromLine(event, tagId) {
    // Not a click on the line: no copy, no cursor mode, no speech.
    event.stopPropagation();
    setTagFilter(activeTagFilterId === tagId ? null : tagId);
}

// Small chips naming a line's tags; clicking one filters the log to that tag.
// A line with many tags shows the first few and a "+N" chip for the rest.
function buildLineTagChips(tagIds) {
    const tags = ruleTagsFor(tagIds);
    const shown = tags.slice(0, LINE_TAG_CHIP_LIMIT);
    const rest = tags.slice(LINE_TAG_CHIP_LIMIT);
    const chips = shown.map((tag) => {
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.className = `line-tag-chip${tagChipCategoryClass(tag)}`;
        chip.textContent = tag.name;
        chip.title = tag.description ? `${tag.name}: ${tag.description}` : tag.name;
        chip.addEventListener('click', (event) => toggleTagFilterFromLine(event, tag.id));
        return chip;
    });
    if (rest.length) {
        const more = document.createElement('button');
        more.type = 'button';
        more.className = 'line-tag-chip';
        more.textContent = `+${rest.length}`;
        more.title = rest.map((tag) => tag.name).join(', ');
        more.addEventListener('click', (event) => {
            event.stopPropagation();
            openLineMenu(more, rest.map((tag) => ({
                label: tag.name,
                title: tag.description,
                onSelect: (selectEvent) => toggleTagFilterFromLine(selectEvent, tag.id),
            })), clickPoint(event));
        });
        chips.push(more);
    }
    return chips;
}

function lineMatchesTagFilter(entry) {
    return activeTagFilterId !== null && (entry.tag_ids || []).includes(activeTagFilterId);
}

function applyTagFilterClass() {
    const container = document.getElementById('logLines');
    if (container) {
        container.classList.toggle('tag-filter-active', activeTagFilterId !== null);
    }
}

function setTagFilter(tagId) {
    activeTagFilterId = tagId;
    applyTagFilterClass();
    if (typeof renderLogLines === 'function') {
        renderLogLines();
    }
    renderRuleTagsLine(lastAnalysisPayload);
}

function insertSuggestedSpeech(speechId) {
    // Speeches belong in the response; bring it up if the fixlist is showing.
    if (typeof setActiveRightPanel === 'function') {
        setActiveRightPanel('response', { focus: false });
    }
    if (window.insertSpeechById) {
        window.insertSpeechById(speechId);
    }
}

function insertSuggestedSnippet(snippetId) {
    // Snippets go into whichever panel is showing, as from the snippets menu.
    if (window.insertSnippetById) {
        window.insertSnippetById(snippetId);
    }
}

// One "suggested ..." row of a warning box: the analyst's own items, else
// other helpers' shared ones. Nothing when there are neither.
function buildWarningSuggestionRow({ rowClass, noun, own, shared, title, onInsert }) {
    if (!own.length && !shared.length) {
        return null;
    }
    const row = document.createElement('div');
    row.className = `analysis-warning-suggestions ${rowClass}`;
    row.appendChild(document.createTextNode(
        own.length ? `suggested ${noun}:` : `suggested ${noun} from other helpers:`,
    ));
    (own.length ? own : shared).forEach((item) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'analysis-warning-suggestion';
        button.textContent = item.name;
        button.title = title;
        button.addEventListener('click', () => onInsert(item.id));
        row.appendChild(button);
    });
    return row;
}

// Fills (or refills) the "suggested speeches" and "suggested snippets" rows of
// one warning box from its data-tag-ids, so a speech captured later shows up
// without re-rendering the warnings - which would bring back the ones the
// analyst closed.
function renderWarningSpeechRow(warningElement) {
    warningElement.querySelectorAll('.analysis-warning-suggestions').forEach((row) => row.remove());
    let tagIds = [];
    try {
        tagIds = JSON.parse(warningElement.dataset.tagIds || '[]');
    } catch (e) {
        tagIds = [];
    }
    const config = window.logAnalyzerConfig || {};
    const responseText = currentResponseText();
    const snippetText = currentSnippetTargetText();
    const rows = [
        buildWarningSuggestionRow({
            rowClass: 'analysis-warning-speeches',
            noun: 'speeches',
            own: withoutUsedSpeeches(speechesForTags(tagIds, config.speeches), responseText),
            shared: fallbackSpeechesForTags(tagIds, config.speeches, config.sharedTagSpeeches, responseText),
            title: 'insert into the response',
            onInsert: insertSuggestedSpeech,
        }),
        buildWarningSuggestionRow({
            rowClass: 'analysis-warning-snippets',
            noun: 'snippets',
            own: suggestedSnippetsForTags(tagIds, config.snippets, snippetText),
            shared: fallbackSnippetsForTags(tagIds, config.snippets, config.sharedTagSnippets, snippetText),
            title: 'insert into the panel on the right',
            onInsert: insertSuggestedSnippet,
        }),
    ];
    rows.filter(Boolean).forEach((row) => warningElement.appendChild(row));
}

function refreshWarningSpeechRows() {
    document.querySelectorAll('#analysisWarnings .analysis-warning').forEach(renderWarningSpeechRow);
}

function refreshSpeechSuggestions() {
    const config = window.logAnalyzerConfig || {};
    const tagIds = ((lastAnalysisPayload && lastAnalysisPayload.rule_tags) || []).map((tag) => tag.id);
    const responseText = currentResponseText();
    config.suggestedSpeechIds = computeSuggestedSpeechIds(config.speeches, tagIds, responseText);
    config.suggestedSharedSpeechIds = fallbackSpeechesForTags(
        tagIds, config.speeches, config.sharedTagSpeeches, responseText,
    ).map((speech) => speech.id);
    if (window.reloadSpeechMenu) {
        window.reloadSpeechMenu();
    }
}

// Also runs when the right panel switches, since a snippet counts as used
// only in the panel it would go into.
function refreshSnippetSuggestions() {
    const config = window.logAnalyzerConfig || {};
    const tagIds = ((lastAnalysisPayload && lastAnalysisPayload.rule_tags) || []).map((tag) => tag.id);
    const text = currentSnippetTargetText();
    config.suggestedSnippetIds = suggestedSnippetsForTags(tagIds, config.snippets, text)
        .map((snippet) => snippet.id);
    config.suggestedSharedSnippetIds = fallbackSnippetsForTags(
        tagIds, config.snippets, config.sharedTagSnippets, text,
    ).map((snippet) => snippet.id);
    if (window.reloadSnippetMenu) {
        window.reloadSnippetMenu();
    }
}

function updateSpeechSuggestionsFromAnalysis(payload) {
    lastAnalysisPayload = payload || null;
    ruleTagsById = new Map(((payload && payload.rule_tags) || []).map((tag) => [tag.id, tag]));
    // A new analysis may not have the filtered tag at all.
    activeTagFilterId = null;
    applyTagFilterClass();
    renderRuleTagsLine(payload);
    refreshSpeechSuggestions();
    refreshSnippetSuggestions();
}

// The tags row sits inside the status legend; the log and fixlist panels
// above shrink by its height so the legend stays inside the window.
function syncLegendExtraHeight(line) {
    const height = line && !line.hidden ? line.offsetHeight + 6 : 0;
    document.documentElement.style.setProperty('--legend-extra', `${height}px`);
}

function renderRuleTagsLine(payload) {
    const line = document.getElementById('ruleTagsLine');
    if (!line) {
        return;
    }
    const tags = (payload && payload.rule_tags) || [];
    line.innerHTML = '';
    line.hidden = tags.length === 0;
    if (!tags.length) {
        syncLegendExtraHeight(line);
        return;
    }

    line.appendChild(document.createTextNode('tags:'));
    tags.forEach((tag) => {
        const chip = document.createElement('span');
        chip.className = `tag-chip${tagChipCategoryClass(tag)}`;

        // A tag with lines filters the log to them; a built-in or whole-log
        // tag has no lines, so it is a label only.
        if (tag.line_count) {
            const filter = document.createElement('button');
            filter.type = 'button';
            filter.className = 'tag-chip-filter';
            const pressed = activeTagFilterId === tag.id;
            filter.setAttribute('aria-pressed', pressed ? 'true' : 'false');
            const action = pressed ? 'click to show all lines again' : 'click to show only its lines';
            filter.title = tag.description ? `${tag.description}\n\n${action}` : action;
            // "(n)" like the status counts in the legend row above.
            filter.textContent = `${tag.name} (${tag.line_count})`;
            filter.addEventListener('click', (event) => {
                event.stopPropagation();
                setTagFilter(activeTagFilterId === tag.id ? null : tag.id);
            });
            chip.appendChild(filter);
            if (pressed) {
                chip.classList.add('tag-chip-active');
            } else if (activeTagFilterId !== null) {
                // Like a hidden status in the legend: its lines are not shown.
                chip.classList.add('tag-chip-filtered-out');
            }
        } else {
            const label = document.createElement('span');
            label.textContent = tag.builtin ? `${tag.name} (warning)` : `${tag.name} (log)`;
            label.title = tag.description || '';
            chip.appendChild(label);
        }
        line.appendChild(chip);
    });
    syncLegendExtraHeight(line);
}

function closeLineSpeechMenu() {
    const existing = document.getElementById('lineSpeechMenu');
    if (existing) {
        existing.remove();
    }
}

// The click's viewport point, or null for a keyboard "click" (no pointer).
function clickPoint(event) {
    if (!event || (!event.clientX && !event.clientY)) {
        return null;
    }
    return { x: event.clientX, y: event.clientY };
}

// Puts a popup at the clicked point (or below `anchor` without one), kept
// inside the viewport so a click near the right or bottom edge still shows it.
function placeNear(element, anchor, point = null) {
    const rect = anchor.getBoundingClientRect();
    const viewportWidth = document.documentElement.clientWidth || window.innerWidth || 0;
    const viewportHeight = document.documentElement.clientHeight || window.innerHeight || 0;
    let left = point ? point.x + 2 : rect.left + 24;
    let top = point ? point.y + 2 : rect.bottom + 2;
    const width = element.offsetWidth || 0;
    const height = element.offsetHeight || 0;
    if (viewportWidth && left + width > viewportWidth - 8) {
        left = Math.max(8, viewportWidth - width - 8);
    }
    if (viewportHeight && top + height > viewportHeight - 8) {
        // No room below the pointer: open upwards from it.
        top = Math.max(8, (point ? point.y : rect.top) - height - 2);
    }
    element.style.left = `${left + window.scrollX}px`;
    element.style.top = `${top + window.scrollY}px`;
}

// A small menu at a log line: entries are {label, note?, title?, onSelect}.
// Arrow keys move between entries; Escape or a click elsewhere closes it.
function openLineMenu(anchor, entries, point = null) {
    closeLineSpeechMenu();
    const menu = document.createElement('div');
    menu.id = 'lineSpeechMenu';
    menu.className = 'line-speech-menu';
    menu.setAttribute('role', 'menu');
    menu.addEventListener('click', (event) => event.stopPropagation());
    entries.forEach((entry) => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'line-speech-menu-item';
        item.setAttribute('role', 'menuitem');
        item.appendChild(document.createTextNode(entry.label));
        if (entry.note) {
            const note = document.createElement('span');
            note.className = 'small-note line-speech-menu-note';
            note.textContent = ` ${entry.note}`;
            item.appendChild(note);
        }
        if (entry.title) item.title = entry.title;
        item.addEventListener('click', (event) => {
            closeLineSpeechMenu();
            entry.onSelect(event);
        });
        menu.appendChild(item);
    });
    menu.addEventListener('keydown', (event) => {
        if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
        event.preventDefault();
        const items = [...menu.querySelectorAll('button')];
        const index = items.indexOf(document.activeElement);
        const next = event.key === 'ArrowDown' ? index + 1 : index - 1;
        items[(next + items.length) % items.length].focus();
    });
    document.body.appendChild(menu);
    placeNear(menu, anchor, point);
    const first = menu.querySelector('button');
    if (first) first.focus();
}

// Several speeches fit the clicked line: let the analyst pick one, or all.
// Each entry names the line's tags the speech fits.
function openLineSpeechMenu(speeches, anchor, lineTagIds = [], point = null) {
    const lineTags = new Map(ruleTagsFor(lineTagIds).map((tag) => [tag.id, tag.name]));
    const ordered = speechesToInsertAll(speeches);
    openLineMenu(anchor, [
        {
            label: `insert all (${ordered.length})`,
            onSelect: () => ordered.forEach((speech) => insertSuggestedSpeech(speech.id)),
        },
        ...ordered.map((speech) => ({
            label: speech.name,
            note: (speech.trigger_tag_ids || [])
                .filter((id) => lineTags.has(id))
                .map((id) => lineTags.get(id))
                .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }))
                .join(', '),
            onSelect: () => insertSuggestedSpeech(speech.id),
        })),
    ], point);
}

function showLineHint(anchor, message, point = null) {
    const existing = document.getElementById('lineSpeechHint');
    if (existing) existing.remove();
    const hint = document.createElement('div');
    hint.id = 'lineSpeechHint';
    hint.className = 'line-speech-hint';
    hint.setAttribute('role', 'status');
    hint.setAttribute('aria-live', 'polite');
    hint.textContent = message;
    document.body.appendChild(hint);
    placeNear(hint, anchor, point);
    setTimeout(() => hint.remove(), 2000);
}

// A click on a log line while the response panel is open adds the line's
// speech instead of the line: directly when one fits, from a small menu when
// several do, and a short hint when none does. The fixlist is left alone.
function handleResponseLineClick(entry, lineElement, event) {
    // The click must not reach the document, whose listener closes the menu
    // this very click is about to open.
    if (event) event.stopPropagation();
    const config = window.logAnalyzerConfig || {};
    const speeches = speechesForLineClick(
        entry, config.speeches, currentResponseText(), config.sharedTagSpeeches,
    );
    if (speeches.length === 1) {
        insertSuggestedSpeech(speeches[0].id);
    } else if (speeches.length > 1) {
        openLineSpeechMenu(speeches, lineElement, entry.tag_ids, clickPoint(event));
    } else {
        showLineHint(lineElement, 'no speech to add for this line', clickPoint(event));
    }
}

function setupRuleTagsLine() {
    // A narrower window can wrap the tags onto more rows.
    window.addEventListener('resize', () => syncLegendExtraHeight(document.getElementById('ruleTagsLine')));
    document.addEventListener('click', closeLineSpeechMenu);
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeLineSpeechMenu();
    });
    // Suggestions follow the response: a speech typed in or inserted stops
    // being suggested, and comes back when its text is deleted. Snippets
    // follow both panels the same way.
    const response = document.getElementById('responseText');
    if (response) {
        let timer = null;
        response.addEventListener('input', () => {
            clearTimeout(timer);
            timer = setTimeout(() => {
                refreshSpeechSuggestions();
                refreshSnippetSuggestions();
            }, 300);
        });
    }
    const fixlist = document.getElementById('selectedLines');
    if (fixlist) {
        let timer = null;
        fixlist.addEventListener('input', () => {
            clearTimeout(timer);
            timer = setTimeout(refreshSnippetSuggestions, 300);
        });
    }
}
