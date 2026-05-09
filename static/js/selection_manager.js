// Persists checkbox selections in sessionStorage so they survive pagination
// and filter changes across the same listing. Used by the dashboard and
// uploaded_logs pages; each listing creates its own manager instance.
(function () {
    function createSelectionManager(config) {
        const storageKey = config.storageKey;
        const formId = config.formId;
        const checkboxClass = config.checkboxClass;
        const inputName = config.inputName;
        const indicatorId = config.indicatorId || 'selectionIndicator';
        const countId = config.countId || 'selectionCount';
        const checkboxSelector = 'input.' + checkboxClass + '[name="' + inputName + '"]';
        const hiddenSelector = 'input[type="hidden"][name="' + inputName + '"]';

        function getStored() {
            try {
                const raw = sessionStorage.getItem(storageKey);
                if (!raw) return new Set();
                return new Set(JSON.parse(raw));
            } catch (e) {
                return new Set();
            }
        }

        function setStored(set) {
            try {
                sessionStorage.setItem(storageKey, JSON.stringify([...set]));
            } catch (e) { /* quota or disabled storage */ }
        }

        function clearStored() {
            try {
                sessionStorage.removeItem(storageKey);
            } catch (e) { /* quota or disabled storage */ }
        }

        function updateIndicator(count) {
            const indicator = document.getElementById(indicatorId);
            const countEl = document.getElementById(countId);
            if (!indicator || !countEl) return;
            countEl.textContent = count;
            indicator.hidden = count === 0;
        }

        function syncToForm() {
            const form = document.getElementById(formId);
            if (!form) return;

            form.querySelectorAll(hiddenSelector).forEach(el => el.remove());

            const stored = getStored();
            const visibleIds = new Set();

            document.querySelectorAll(checkboxSelector).forEach(cb => {
                visibleIds.add(cb.value);
                cb.checked = stored.has(cb.value);
            });

            stored.forEach(id => {
                if (!visibleIds.has(id)) {
                    const hidden = document.createElement('input');
                    hidden.type = 'hidden';
                    hidden.name = inputName;
                    hidden.value = id;
                    form.appendChild(hidden);
                }
            });

            updateIndicator(stored.size);
        }

        function bindCheckboxes() {
            document.querySelectorAll(checkboxSelector).forEach(cb => {
                if (cb.dataset.selectionBound === '1') return;
                cb.dataset.selectionBound = '1';
                cb.addEventListener('change', () => {
                    const stored = getStored();
                    if (cb.checked) {
                        stored.add(cb.value);
                    } else {
                        stored.delete(cb.value);
                    }
                    setStored(stored);
                    syncToForm();
                });
            });
        }

        function seedFromPreChecked() {
            // If the user clicked a checkbox before DOMContentLoaded fired, the
            // change listener wasn't attached yet so the click never reached
            // sessionStorage. Pick up that pre-checked state.
            const stored = getStored();
            let changed = false;
            document.querySelectorAll(checkboxSelector).forEach(cb => {
                if (cb.checked && !stored.has(cb.value)) {
                    stored.add(cb.value);
                    changed = true;
                }
            });
            if (changed) setStored(stored);
        }

        function init() {
            seedFromPreChecked();
            syncToForm();
            bindCheckboxes();

            const form = document.getElementById(formId);
            if (form) {
                form.addEventListener('submit', () => clearStored());
            }

            const clearLink = document.getElementById('clearSelectionLink');
            if (clearLink) {
                clearLink.addEventListener('click', (event) => {
                    event.preventDefault();
                    clearStored();
                    syncToForm();
                });
            }
        }

        return {
            getStored,
            setStored,
            clearStored,
            syncToForm,
            bindCheckboxes,
            seedFromPreChecked,
            updateIndicator,
            init,
        };
    }

    window.createSelectionManager = createSelectionManager;
})();
