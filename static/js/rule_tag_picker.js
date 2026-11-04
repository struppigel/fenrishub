// A picker for rule tags, used on the rule forms, the speeches page and in
// the analyzer's rule review. Selected tags are chips; typing filters the
// shared tag list. Only existing tags can be picked; new tags are made in the
// tag editor.
//
// When given a description field it also suggests the tags whose conditions
// the rule being written meets - its description, and through
// `contextProvider` its source line, status and match type. Suggestions are
// dashed chips that do nothing until clicked: a tag's conditions propose, the
// analyst decides. A tag set to apply automatically is filled in already,
// since the rule would get it anyway; removing it leaves it off, because what
// the picker holds on save is what the rule carries.
//
// With `inputName` set, the selection is posted with the surrounding form as
// one hidden input per tag id plus a `tags_present` marker, so a form that
// does not render the picker never clears a rule's tags by omission. Filter
// forms, which only read the tag ids, turn the marker off with
// `presenceMarker: false`, and list bare tag names with
// `showDescriptions: false`.

(function () {
    'use strict';

    let tagListPromise = null;
    let tagCache = [];

    function getCsrfToken(explicit) {
        if (explicit) return explicit;
        const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : '';
    }

    function loadTags(url) {
        if (!tagListPromise) {
            tagListPromise = fetch(url, { credentials: 'same-origin' })
                .then((response) => (response.ok ? response.json() : { tags: [] }))
                .then((data) => {
                    tagCache = Array.isArray(data.tags) ? data.tags : [];
                    return tagCache;
                })
                .catch(() => {
                    tagListPromise = null;
                    return [];
                });
        }
        return tagListPromise;
    }

    function postJson(url, body, csrfToken) {
        return fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken(csrfToken),
            },
            body: JSON.stringify(body),
        }).then((response) => response.json().catch(() => ({})).then((data) => {
            if (!response.ok) {
                throw new Error(data.error || 'Request failed.');
            }
            return data;
        }));
    }

    // ' tag-cat-<id>' when the tag has a category, whose colour base.html
    // writes into a style rule; '' for the default look.
    function tagCategoryClass(tag) {
        const id = tag && Number(tag.category_id);
        return id ? ` tag-cat-${id}` : '';
    }

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    // Pure, so the test page can drive it: the auto-apply tags among
    // `suggestions` to fill in, given what is selected and what was removed.
    function autoTagsToPrefill(suggestions, selectedIds, dismissedIds, fieldsChanged) {
        if (!fieldsChanged) return [];
        const taken = new Set(selectedIds);
        return (suggestions || []).filter(
            (tag) => tag.auto_apply && !taken.has(tag.id) && !dismissedIds.has(tag.id),
        );
    }

    function createRuleTagPicker(options) {
        const root = options.root;
        const urls = options.urls || {};
        const inputName = options.inputName || '';
        const presenceMarker = options.presenceMarker !== false;
        const showDescriptions = options.showDescriptions !== false;
        const descriptionInput = options.descriptionInput || null;
        const onChange = typeof options.onChange === 'function' ? options.onChange : () => {};

        let selected = (options.initialTags || []).map((tag) => ({ ...tag }));
        // Auto tags the analyst took off; never filled in again on this page.
        const dismissedAutoIds = new Set();
        // Returns {source_text, status, match_type} of the rule being written;
        // `contextInputs` are the fields whose changes refresh the suggestions.
        const contextProvider = typeof options.contextProvider === 'function' ? options.contextProvider : () => ({});
        const contextInputs = options.contextInputs || [];

        function snapshot() {
            return JSON.stringify({
                description: descriptionInput ? descriptionInput.value.trim() : '',
                ...contextProvider(),
            });
        }
        // Auto-apply tags only act when a matched field of the rule changes.
        const initialSnapshot = snapshot();
        let suggestions = [];
        let activeIndex = -1;
        let suggestTimer = null;
        let suggestSequence = 0;

        root.classList.add('tag-picker');
        root.innerHTML = '';

        const chips = el('div', 'tag-picker-chips');
        const suggestionRow = el('div', 'tag-picker-suggestions');
        const inputRow = el('div', 'tag-picker-input-row');
        const input = el('input', 'tag-picker-input');
        input.type = 'text';
        input.autocomplete = 'off';
        input.placeholder = options.placeholder || 'add tag...';
        input.setAttribute('aria-label', 'add tag');
        const dropdown = el('div', 'tag-picker-dropdown');
        dropdown.hidden = true;
        inputRow.append(input, dropdown);
        const hiddenInputs = el('div');
        root.append(chips, suggestionRow, inputRow, hiddenInputs);

        function selectedIds() {
            return selected.map((tag) => tag.id);
        }

        function renderHiddenInputs() {
            if (!inputName) return;
            hiddenInputs.innerHTML = '';
            if (presenceMarker) {
                const marker = el('input');
                marker.type = 'hidden';
                marker.name = 'tags_present';
                marker.value = '1';
                hiddenInputs.appendChild(marker);
            }
            selected.forEach((tag) => {
                const hidden = el('input');
                hidden.type = 'hidden';
                hidden.name = inputName;
                hidden.value = String(tag.id);
                hiddenInputs.appendChild(hidden);
            });
        }

        function renderChips() {
            chips.innerHTML = '';
            selected.forEach((tag) => {
                const chip = el('span', `tag-chip${tagCategoryClass(tag)}`);
                chip.title = tag.autoFilled
                    ? 'added because it applies automatically - remove it to leave it off'
                    : (tag.description || '');
                chip.appendChild(el('span', '', tag.name));
                const remove = el('button', 'tag-chip-remove', '×');
                remove.type = 'button';
                remove.setAttribute('aria-label', `remove tag ${tag.name}`);
                remove.addEventListener('click', () => {
                    dismissedAutoIds.add(tag.id);
                    removeTag(tag.id);
                });
                chip.appendChild(remove);
                chips.appendChild(chip);
            });
            chips.hidden = selected.length === 0;
        }

        function descriptionChanged() {
            return snapshot() !== initialSnapshot;
        }

        function renderSuggestions() {
            suggestionRow.innerHTML = '';
            const offered = suggestions.filter((tag) => !selectedIds().includes(tag.id));
            suggestionRow.hidden = offered.length === 0;
            if (!offered.length) return;
            suggestionRow.appendChild(el('span', 'tag-picker-suggestions-label', 'suggested:'));
            offered.forEach((tag) => {
                const chip = el('button', `tag-chip tag-chip-suggested${tagCategoryClass(tag)}`, `+ ${tag.name}`);
                chip.type = 'button';
                chip.title = tag.description
                    ? `${tag.description}\n\nclick to add`
                    : 'this rule meets the tag\'s conditions - click to add';
                chip.addEventListener('click', () => addTag(tag));
                suggestionRow.appendChild(chip);
            });
        }

        // Fills in the auto-apply tags among fresh suggestions. Only once the
        // rule's matched fields differ from how the page opened, so opening an
        // existing rule never adds tags by itself.
        function prefillAutoTags() {
            autoTagsToPrefill(suggestions, selectedIds(), dismissedAutoIds, descriptionChanged())
                .forEach((tag) => addTag(tag, { autoFilled: true }));
        }

        function render() {
            renderChips();
            renderSuggestions();
            renderHiddenInputs();
        }

        function addTag(tag, { autoFilled = false } = {}) {
            if (selectedIds().includes(tag.id)) return;
            selected.push({
                id: tag.id,
                name: tag.name,
                description: tag.description || '',
                category_id: tag.category_id || null,
                autoFilled,
            });
            render();
            onChange(selectedIds());
        }

        function removeTag(id) {
            selected = selected.filter((tag) => tag.id !== id);
            render();
            onChange(selectedIds());
        }

        function closeDropdown() {
            dropdown.hidden = true;
            dropdown.innerHTML = '';
            activeIndex = -1;
        }

        function dropdownOptions() {
            return [...dropdown.querySelectorAll('.tag-picker-option')];
        }

        function setActive(index) {
            const optionsList = dropdownOptions();
            if (!optionsList.length) return;
            activeIndex = (index + optionsList.length) % optionsList.length;
            optionsList.forEach((option, i) => option.classList.toggle('is-active', i === activeIndex));
        }

        function renderDropdown() {
            const query = input.value.trim().toLowerCase();
            dropdown.innerHTML = '';
            activeIndex = -1;
            if (!query) {
                closeDropdown();
                return;
            }
            const taken = selectedIds();
            const matches = tagCache
                .filter((tag) => !taken.includes(tag.id) && tag.name.toLowerCase().includes(query))
                .slice(0, 20);
            matches.forEach((tag) => {
                const option = el('button', 'tag-picker-option');
                option.type = 'button';
                option.appendChild(el('span', '', tag.name));
                if (showDescriptions && tag.description) {
                    option.appendChild(el('span', 'tag-picker-option-note', ` - ${tag.description.slice(0, 80)}`));
                }
                option.addEventListener('mousedown', (event) => event.preventDefault());
                option.addEventListener('click', () => {
                    addTag(tag);
                    input.value = '';
                    closeDropdown();
                });
                dropdown.appendChild(option);
            });
            const exact = tagCache.some((tag) => tag.name.toLowerCase() === query);
            if (!exact && !matches.length) {
                dropdown.appendChild(el(
                    'div', 'tag-picker-option-note small-note',
                    `no tag named "${input.value.trim()}" - create it in the tag editor`,
                ));
            }
            dropdown.hidden = dropdown.childElementCount === 0;
            if (dropdownOptions().length) setActive(0);
        }

        function refreshSuggestions() {
            if (!descriptionInput || !urls.suggest) return;
            const body = { description: descriptionInput.value.trim(), ...contextProvider() };
            const sequence = ++suggestSequence;
            if (!body.description && !body.source_text) {
                suggestions = [];
                renderSuggestions();
                return;
            }
            postJson(urls.suggest, body, options.csrfToken).then((data) => {
                // A slower earlier request must not overwrite a newer answer.
                if (sequence !== suggestSequence) return;
                suggestions = Array.isArray(data.tags) ? data.tags : [];
                prefillAutoTags();
                renderSuggestions();
            }).catch(() => {});
        }

        input.addEventListener('focus', () => loadTags(urls.list));
        input.addEventListener('input', () => {
            loadTags(urls.list).then(renderDropdown);
        });
        input.addEventListener('blur', () => setTimeout(closeDropdown, 100));
        input.addEventListener('keydown', (event) => {
            if (event.key === 'ArrowDown') {
                event.preventDefault();
                setActive(activeIndex + 1);
            } else if (event.key === 'ArrowUp') {
                event.preventDefault();
                setActive(activeIndex - 1);
            } else if (event.key === 'Enter') {
                // Never submit the surrounding form from the tag input.
                event.preventDefault();
                const optionsList = dropdownOptions();
                if (optionsList[activeIndex]) optionsList[activeIndex].click();
            } else if (event.key === 'Escape' && !dropdown.hidden) {
                event.preventDefault();
                event.stopPropagation();
                closeDropdown();
            }
        });

        if (descriptionInput) {
            const scheduleRefresh = () => {
                clearTimeout(suggestTimer);
                suggestTimer = setTimeout(refreshSuggestions, 400);
            };
            descriptionInput.addEventListener('input', scheduleRefresh);
            contextInputs.forEach((element) => {
                element.addEventListener('input', scheduleRefresh);
                element.addEventListener('change', scheduleRefresh);
            });
            refreshSuggestions();
        }

        render();

        return {
            getIds: selectedIds,
            getTags: () => selected.map((tag) => ({ ...tag })),
            setTags(tags) {
                selected = (tags || []).map((tag) => ({ ...tag }));
                render();
            },
            refreshSuggestions,
        };
    }

    window.createRuleTagPicker = createRuleTagPicker;
    window.tagCategoryClass = tagCategoryClass;
    window.autoTagsToPrefill = autoTagsToPrefill;
})();
