/* Behaviour shared by the snippets and speeches list pages (library_list.html):
 * the "view" dialog, the compact (previews hidden) mode and selecting items
 * for the log analyzer. Needs common.js (Fenris) and view_modal.js. */
function initLibraryPage({ noun, compactKey, toggleUrl }) {
    initViewModal();

    /* Compact mode is remembered in localStorage and mirrored to a cookie of
     * the same name, which the server reads to show more items per page. */
    const previewButton = document.getElementById('togglePreviewButton');

    function applyCompactState(compact) {
        document.body.classList.toggle('library-compact', compact);
        if (previewButton) {
            previewButton.setAttribute('aria-pressed', compact ? 'true' : 'false');
            previewButton.textContent = compact ? 'show previews' : 'hide previews';
        }
    }

    function setCompactCookie(compact) {
        const maxAge = 60 * 60 * 24 * 365;
        document.cookie = `${compactKey}=${compact ? '1' : '0'}; path=/; max-age=${maxAge}; SameSite=Lax`;
    }

    const compact = Fenris.storage.flag(compactKey);
    applyCompactState(compact);
    setCompactCookie(compact);
    if (previewButton) {
        previewButton.addEventListener('click', () => {
            const next = !document.body.classList.contains('library-compact');
            Fenris.storage.setFlag(compactKey, next);
            setCompactCookie(next);
            const url = new URL(window.location.href);
            url.searchParams.delete('page');
            window.location.href = url.toString();
        });
    }

    document.querySelectorAll('[data-toggle-pk]').forEach((button) => {
        button.addEventListener('click', () => {
            const formData = new FormData();
            formData.append('pk', button.dataset.togglePk);
            fetch(toggleUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'X-CSRFToken': Fenris.csrfToken() },
                body: formData,
            })
                .then((response) => response.json())
                .then((data) => {
                    button.classList.toggle('active', Boolean(data.selected));
                    button.textContent = data.selected ? 'selected' : 'select';
                    button.title = data.selected
                        ? `deselect ${noun} from log analyzer`
                        : `select ${noun} to be available in log analyzer`;
                });
        });
    });
}
