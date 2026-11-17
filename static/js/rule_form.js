/* Field logic shared by the two rule forms: the add / edit rule page
 * (add_rule.html, ids "rule…") and the quick-edit panel on the rules list
 * (rules.html, ids "edit…"). Each page passes its elements in `els`:
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

    return {
        COLOR_WHOLE_LINE_MATCH_TYPES,
        syncWholeLog, wholeLogActive, syncColorWholeLine, applyDefaultPriority, bindPriorityConfirm,
        styleScriptTextarea,
    };
})();
