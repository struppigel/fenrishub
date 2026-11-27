/* The "view" dialog: the #viewModal markup (.view-modal-* in components.css)
 * and .view-btn buttons whose data-name is the title. Two kinds of content:
 *  - text: data-content-id names a hidden element whose text is shown in the
 *    <pre> (snippets / speeches pages);
 *  - details: data-details-id names a <template> whose markup is shown in
 *    #viewModalDetails (the rules page: every field of the rule). Falls back
 *    to the text when the page has no #viewModalDetails or no such template. */
function initViewModal() {
    const modal = document.getElementById('viewModal');
    if (!modal) return;
    const modalTitle = document.getElementById('viewModalTitle');
    const modalContent = document.getElementById('viewModalContent');
    const modalDetails = document.getElementById('viewModalDetails');
    const closeButton = document.getElementById('viewModalClose');
    let opener = null;

    function showText(content) {
        modalContent.textContent = content;
        modalContent.hidden = false;
        if (modalDetails) {
            modalDetails.replaceChildren();
            modalDetails.hidden = true;
        }
    }

    function showDetails(template) {
        modalDetails.replaceChildren(template.content.cloneNode(true));
        modalDetails.hidden = false;
        modalContent.textContent = '';
        modalContent.hidden = true;
    }

    function openViewModal(button) {
        modalTitle.textContent = button.dataset.name || '';
        const template = modalDetails && button.dataset.detailsId
            ? document.getElementById(button.dataset.detailsId)
            : null;
        if (template && template.content) {
            showDetails(template);
        } else {
            const contentElement = document.getElementById(button.dataset.contentId || '');
            showText(contentElement ? contentElement.textContent : '');
        }
        modal.classList.add('show');
        opener = button;
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
        button.addEventListener('click', () => openViewModal(button));
    });
}
