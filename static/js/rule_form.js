/* Field logic of the rule form, the add / edit rule page (add_rule.html,
 * ids "rule…"), plus the log type scope picker the analyzer's rule review
 * also uses. The page passes its elements in `els`:
 *   {status, matchType, wholeLog, wholeLogGroup, priority, priorityGroup,
 *    colorWholeLine, colorWholeLineGroup, matchUnit?}
 * and keeps its own wording (labels, help text, placeholders). The editor page
 * also passes {factStatusValue, factGroup, verdictGroups} for recording a
 * fact: a choice in the status dropdown, though a fact is not a status. */
window.RuleForm = (function () {
    /* Only substring, file path and regex rules colour just their match; every
     * other type already colours the whole line, so the choice is offered for
     * those. Whole-log rules colour no lines at all, so not for them either. */
    const COLOR_WHOLE_LINE_MATCH_TYPES = ['substring', 'filepath', 'regex'];

    /* Whole-log only makes sense as an alert on regex / script rules, or as a
     * fact rule (the status dropdown's `els.factStatusValue` choice, on the
     * editor page only), which records a fact about the log. Hides the checkbox (and unticks it)
     * otherwise, and hides the priority, which has no effect on whole-log
     * alerts (fact rules have none at all). Returns whether whole-log is on. */
    function syncWholeLog(els) {
        const factMode = isFactMode(els);
        const eligible = (factMode || els.status.value === 'A')
            && (els.matchType.value === 'regex' || els.matchType.value === 'script');
        els.wholeLogGroup.style.display = eligible ? '' : 'none';
        if (!eligible) els.wholeLog.checked = false;
        const wholeLog = els.wholeLog.checked;
        els.priorityGroup.style.display = wholeLog || factMode ? 'none' : '';
        return wholeLog;
    }

    function isFactMode(els) {
        return Boolean(els.factStatusValue) && els.status.value === els.factStatusValue;
    }

    /* Fact mode: the rule records a fact instead of setting a status, so the
     * fields that only shape a verdict are hidden (`els.verdictGroups`) and
     * the fact picker is shown (`els.factGroup`). Returns whether it is on. */
    function syncFactMode(els) {
        const factMode = isFactMode(els);
        (els.verdictGroups || []).forEach(function (group) { group.hidden = factMode; });
        if (els.factGroup) els.factGroup.hidden = !factMode;
        return factMode;
    }

    function wholeLogActive(els) {
        return els.wholeLog.checked && els.wholeLogGroup.style.display !== 'none';
    }

    function syncColorWholeLine(els) {
        /* A block rule colours the whole lines of its block. */
        const blockRule = Boolean(els.matchUnit) && els.matchUnit.value === 'block';
        const offered = COLOR_WHOLE_LINE_MATCH_TYPES.includes(els.matchType.value) && !wholeLogActive(els)
            && !isFactMode(els) && !blockRule;
        els.colorWholeLineGroup.style.display = offered ? '' : 'none';
        if (!offered) els.colorWholeLine.checked = false;
    }

    /* A new match type brings its default priority, until the user picked one. */
    function applyDefaultPriority(els, defaults) {
        const fallback = defaults[els.matchType.value];
        if (fallback !== undefined && els.priority.dataset.userTouched !== 'true') {
            els.priority.value = String(fallback);
        }
        els.priority.dataset.prevValue = els.priority.value;
    }

    /* Choosing the highest priority asks first; cancelling restores the
     * previous value. `onChange` runs after an accepted change. */
    function bindPriorityConfirm(input, { max, warning, onChange }) {
        input.addEventListener('change', function () {
            if (parseInt(this.value, 10) === max && !confirm(warning)) {
                this.value = this.dataset.prevValue || '';
                return;
            }
            this.dataset.prevValue = this.value;
            this.dataset.userTouched = 'true';
            if (onChange) onChange();
        });
    }

    /* Python source gets a monospace, taller textarea. */
    function styleScriptTextarea(textarea, isScript) {
        textarea.style.fontFamily = isScript ? 'var(--la-font-mono, monospace)' : '';
        textarea.style.minHeight = isScript ? '160px' : '';
    }

    /* ── log type scope picker ──
     * Which log types a rule classifies, as a dropdown: the default types
     * (FRST and Addition), custom types (a selection of exact names, shown
     * only then) or all log types (including ones added later). Shared by the
     * rule editor and the analyzer's rule review.
     *
     * opts: {root, choices: [names], value: 'all' | [names], formNames: bool
     *        (fields named log_scope / log_types for a form POST), unknown:
     *        [names no longer defined anywhere], defaults: [names] (the default
     *        types; DEFAULT_LOG_TYPES without), onChange(value), onInvalid()
     *        (a form submit stopped because nothing is selected)}
     * Returns {getValue, setValue, isTouched, validate, element}. */
    const ALL_LOG_TYPES = 'all';
    /* log_types.DEFAULT_RULE_LOG_TYPES. */
    const DEFAULT_LOG_TYPES = ['FRST&Addition', 'FRST', 'Addition'];
    const SCOPE_DEFAULT = 'default';
    const SCOPE_CUSTOM = 'selected';
    let pickerCount = 0;

    function sameNames(a, b) {
        return a.length === b.length && a.every(function (name) { return b.includes(name); });
    }

    function createLogScopePicker(opts) {
        pickerCount += 1;
        const unknown = new Set(opts.unknown || []);
        const defaults = (opts.defaults || DEFAULT_LOG_TYPES).slice();
        let touched = false;

        const root = opts.root;
        root.classList.add('rule-log-scope');
        root.textContent = '';

        const modes = document.createElement('div');
        modes.className = 'log-scope-modes';
        /* The server reads log_scope "all" as every type and anything else as
         * the posted log_types, so "default" posts the default types. */
        const mode = document.createElement('select');
        mode.className = 'log-scope-mode';
        mode.setAttribute('aria-label', 'log types');
        if (opts.formNames) mode.name = 'log_scope';
        else mode.name = 'log-scope-' + pickerCount;
        const defaultsText = defaults.filter(function (name) { return !name.includes('&'); }).join(', ');
        [
            [SCOPE_DEFAULT, 'default log types (' + defaultsText + ')'],
            [SCOPE_CUSTOM, 'custom log types'],
            [ALL_LOG_TYPES, 'all log types'],
        ].forEach(function (pair) {
            const option = document.createElement('option');
            option.value = pair[0];
            option.textContent = pair[1];
            mode.appendChild(option);
        });
        modes.appendChild(mode);
        root.appendChild(modes);

        const list = document.createElement('div');
        list.className = 'log-type-choices';
        const boxes = (opts.choices || []).map(function (name) {
            const label = document.createElement('label');
            label.className = 'checkbox-label';
            const box = document.createElement('input');
            box.type = 'checkbox';
            box.value = name;
            if (opts.formNames) box.name = 'log_types';
            label.append(box, name);
            if (unknown.has(name)) {
                label.title = 'no longer a known log type';
                label.classList.add('log-type-unknown');
            }
            list.appendChild(label);
            return box;
        });
        root.appendChild(list);

        const error = document.createElement('div');
        error.className = 'regex-warning log-scope-error';
        error.hidden = true;
        error.textContent = 'select at least one log type, or choose default or all log types';
        root.appendChild(error);

        function checkedNames() {
            return boxes.filter(function (box) { return box.checked; }).map(function (box) { return box.value; });
        }

        function setChecked(names) {
            const wanted = new Set(names);
            boxes.forEach(function (box) { box.checked = wanted.has(box.value); });
        }

        function getValue() {
            if (mode.value === ALL_LOG_TYPES) return ALL_LOG_TYPES;
            if (mode.value === SCOPE_DEFAULT) return defaults.slice();
            return checkedNames();
        }

        /* The custom selection, kept while "default" or "all" is chosen so
         * switching back to "custom" restores it. */
        let customNames = null;
        let lastMode = null;

        function sync() {
            const custom = mode.value === SCOPE_CUSTOM;
            if (lastMode === SCOPE_CUSTOM && !custom) customNames = checkedNames();
            if (custom && lastMode !== null && lastMode !== SCOPE_CUSTOM && customNames !== null) {
                setChecked(customNames);
            }
            lastMode = mode.value;
            list.hidden = !custom;
            /* "default" posts the default types through the (hidden) boxes;
             * "all" disables them so no stale selection is sent. */
            if (mode.value === SCOPE_DEFAULT) setChecked(defaults);
            boxes.forEach(function (box) { box.disabled = mode.value === ALL_LOG_TYPES; });
            if (!custom || checkedNames().length) error.hidden = true;
        }

        function setValue(value) {
            /* An explicit value replaces any remembered custom selection. */
            customNames = null;
            lastMode = null;
            if (value === ALL_LOG_TYPES) {
                mode.value = ALL_LOG_TYPES;
                setChecked([]);
            } else if (sameNames(value || [], defaults)) {
                mode.value = SCOPE_DEFAULT;
            } else {
                mode.value = SCOPE_CUSTOM;
                setChecked(value || []);
            }
            sync();
        }

        function validate() {
            const value = getValue();
            const ok = value === ALL_LOG_TYPES || value.length > 0;
            error.hidden = ok;
            return ok;
        }

        function changed() {
            touched = true;
            sync();
            if (opts.onChange) opts.onChange(getValue());
        }
        mode.addEventListener('change', changed);
        boxes.forEach(function (box) { box.addEventListener('change', changed); });

        if (opts.formNames) {
            const form = root.closest('form');
            if (form) {
                /* A picker rebuilt in the same root
                 * replaces the previous one's check instead of adding another. */
                if (root.logScopeSubmitCheck) form.removeEventListener('submit', root.logScopeSubmitCheck);
                root.logScopeSubmitCheck = function (event) {
                    if (event.submitter && event.submitter.formNoValidate) return;
                    if (!validate()) {
                        event.preventDefault();
                        if (opts.onInvalid) opts.onInvalid();
                        root.scrollIntoView({ block: 'nearest' });
                    }
                };
                form.addEventListener('submit', root.logScopeSubmitCheck);
            }
        }

        setValue(opts.value === undefined ? ALL_LOG_TYPES : opts.value);
        return {
            getValue, setValue, validate,
            isTouched: function () { return touched; },
            element: root,
        };
    }

    /* A new rule follows its match type's default scope until the user picks
     * one: file path rules apply to every log type, the rest to `defaults`. */
    function bindLogScopeDefaults(picker, matchTypeSelect, defaults) {
        matchTypeSelect.addEventListener('change', function () {
            if (picker.isTouched()) return;
            picker.setValue(matchTypeSelect.value === 'filepath' ? ALL_LOG_TYPES : defaults.slice());
        });
    }

    /* "all logs" or the comma-joined names, for compact displays. */
    function logScopeLabel(value) {
        if (value === ALL_LOG_TYPES) return 'all logs';
        return (value || []).join(', ') || 'no logs';
    }

    /* `choices` plus any name `value` holds that is not among them (a log type
     * no longer defined), so a picker never drops part of a stored scope. */
    function logScopeChoices(choices, value) {
        const names = (choices || []).slice();
        const unknown = [];
        if (value !== ALL_LOG_TYPES) {
            (value || []).forEach(function (name) {
                if (!names.includes(name)) { names.push(name); unknown.push(name); }
            });
        }
        return { choices: names, unknown: unknown };
    }

    return {
        COLOR_WHOLE_LINE_MATCH_TYPES, ALL_LOG_TYPES,
        syncWholeLog, wholeLogActive, syncColorWholeLine, syncFactMode, isFactMode, applyDefaultPriority,
        bindPriorityConfirm,
        styleScriptTextarea, createLogScopePicker, bindLogScopeDefaults, logScopeLabel, logScopeChoices,
    };
})();
