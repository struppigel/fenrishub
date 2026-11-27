/* The "view" dialog showing an item's full text: the #viewModal markup
 * (.view-modal-* in components.css) and .view-btn buttons whose data-name is
 * the title and whose data-content-id names a hidden element holding the
 * text. Used by the snippets / speeches pages and the rules page. */
function initViewModal() {
    const modal = document.getElementById('viewModal');
    if (!modal) return;
    const modalTitle = document.getElementById('viewModalTitle');
    const modalContent = document.getElementById('viewModalContent');
    const closeButton = document.getElementById('viewModalClose');
    let opener = null;

    function openViewModal(name, content, from) {
        modalTitle.textContent = name;
        modalContent.textContent = content;
        modal.classList.add('show');
        opener = from || null;
        closeButton.focus();
    }

    function closeViewModal() {
        if (!modal.classList.contains('show')) return;
        modal.classList.remove('show');
        if (opener) opener.focus();
        opener = null;
    }

    modal.addEventListener('click', (event) => {
        if (event.target === modal) closeViewModal();
    });
    closeButton.addEventListener('click', closeViewModal);
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeViewModal();
    });
    document.querySelectorAll('.view-btn').forEach((button) => {
        button.addEventListener('click', () => {
            const contentElement = document.getElementById(button.dataset.contentId || '');
            openViewModal(button.dataset.name || '', contentElement ? contentElement.textContent : '', button);
        });
    });
}
