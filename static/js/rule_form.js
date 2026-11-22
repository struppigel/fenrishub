/* Field logic shared by the two rule forms: the add / edit rule page
 * (add_rule.html, ids "rule…") and the quick-edit panel on the rules list
 * (rules.html, ids "edit…"), plus the log type scope picker the analyzer's
 * rule review also uses. Each page passes its elements in `els`:
 *   {status, matchType, wholeLog, wholeLogGroup, priority, priorityGroup,
 *    colorWholeLine, colorWholeLineGroup}
 * and keeps its own wording (labels, help text, placeholders). */
window.RuleForm = (function () {
    /* Only substring, file path and regex rules colour just their match; every
     * other type already colours the whole line, so the choice is offered for
     * those. Whole-log rules colour no lines at all, so not for them either. */
    const COLOR_WHOLE_LINE_MATCH_TYPES = ['substring', 'filepath', 'regex'];

    /* Whole-log only makes sense as an alert on regex / script rules. Hides the
     * checkbox (and unticks it) otherwise, and hides the priority, which has no
     * effect on whole-log alerts. Returns whether whole-log is on. */
    function syncWholeLog(els) {
        const eligible = els.status.value === 'A'
            && (els.matchType.value === 'regex' || els.matchType.value === 'script');
        els.wholeLogGroup.style.display = eligible ? '' : 'none';
        if (!eligible) els.wholeLog.checked = false;
        const wholeLog = els.wholeLog.checked;
        els.priorityGroup.style.display = wholeLog ? 'none' : '';
        return wholeLog;
    }

    function wholeLogActive(els) {
        return els.wholeLog.checked && els.wholeLogGroup.style.display !== 'none';
    }

    function syncColorWholeLine(els) {
        const offered = COLOR_WHOLE_LINE_MATCH_TYPES.includes(els.matchType.value) && !wholeLogActive(els);
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
     * Which log types a rule classifies: "all log types" (including ones added
     * later) or a selection of exact names. Shared by the rule editor, the rules
     * list's quick edit and the analyzer's rule review.
     *
     * opts: {root, choices: [names], value: 'all' | [names], formNames: bool
     *        (inputs named log_scope / log_types for a form POST), unknown:
     *        [names no longer defined anywhere], onChange(value), onInvalid()
     *        (a form submit stopped because nothing is selected)}
     * Returns {getValue, setValue, isTouched, validate, element}. */
    const ALL_LOG_TYPES = 'all';
    let pickerCount = 0;

    function createLogScopePicker(opts) {
        pickerCount += 1;
        const radioName = opts.formNames ? 'log_scope' : 'log-scope-' + pickerCount;
        const unknown = new Set(opts.unknown || []);
        let touched = false;

        const root = opts.root;
        root.classList.add('rule-log-scope');
        root.textContent = '';

        const modes = document.createElement('div');
        modes.className = 'log-scope-modes';
        function radio(value, text) {
            const label = document.createElement('label');
            label.className = 'checkbox-label';
            const input = document.createElement('input');
            input.type = 'radio';
            input.name = radioName;
            input.value = value;
            label.append(input, text);
            modes.appendChild(label);
            return input;
        }
        const allRadio = radio(ALL_LOG_TYPES, 'all log types');
        const selectedRadio = radio('selected', 'selected log types');
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
        error.textContent = 'select at least one log type, or "all log types"';
        root.appendChild(error);

        function getValue() {
            if (allRadio.checked) return ALL_LOG_TYPES;
            return boxes.filter(function (box) { return box.checked; }).map(function (box) { return box.value; });
        }

        function sync() {
            const all = allRadio.checked;
            list.hidden = all;
            /* Unchecked or hidden boxes are left out of a POST either way; disabling
             * them keeps "all" from sending a stale selection. */
            boxes.forEach(function (box) { box.disabled = all; });
            if (all || boxes.some(function (box) { return box.checked; })) error.hidden = true;
        }

        function setValue(value) {
            const all = value === ALL_LOG_TYPES;
            allRadio.checked = all;
            selectedRadio.checked = !all;
            const names = new Set(all ? [] : (value || []));
            boxes.forEach(function (box) { box.checked = names.has(box.value); });
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
        allRadio.addEventListener('change', changed);
        selectedRadio.addEventListener('change', changed);
        boxes.forEach(function (box) { box.addEventListener('change', changed); });

        if (opts.formNames) {
            const form = root.closest('form');
            if (form) {
                /* A picker rebuilt in the same root (the quick edit does, per rule)
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
        syncWholeLog, wholeLogActive, syncColorWholeLine, applyDefaultPriority, bindPriorityConfirm,
        styleScriptTextarea, createLogScopePicker, bindLogScopeDefaults, logScopeLabel, logScopeChoices,
    };
})();
