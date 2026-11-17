/* Small popup menus anchored to an icon: the analyzer's copy / search /
 * correlation menus and the uploaded log page's token and line menus. They
 * share the .line-copy-menu* markup (static/css/line_copy_menu.css), and how
 * they are placed next to their anchor. Each caller keeps its own open/close
 * state and dismissal rules. */
window.PopupMenu = (function () {
    /* Replace `menu`'s content with a header and one button per item.
     * items: [{key, value, label?, className?, run}]; `label` is shown instead
     * of `value` when given. Clicking an item runs it (the click does not
     * bubble, so document-level "click elsewhere" handlers leave it alone). */
    function fill(menu, headerText, items) {
        menu.innerHTML = '';
        if (headerText) {
            const header = document.createElement('div');
            header.className = 'line-copy-menu-header';
            header.textContent = headerText;
            menu.appendChild(header);
        }
        items.forEach(({ key, value, label: shown, className, run }) => {
            const item = document.createElement('button');
            item.type = 'button';
            item.className = 'line-copy-menu-item' + (className ? ' ' + className : '');
            item.setAttribute('role', 'menuitem');
            const label = document.createElement('span');
            label.className = 'line-copy-menu-key';
            label.textContent = key;
            const preview = document.createElement('span');
            preview.className = 'line-copy-menu-value';
            preview.textContent = shown || value;
            item.append(label, preview);
            item.addEventListener('click', (event) => {
                event.stopPropagation();
                run();
            });
            menu.appendChild(item);
        });
    }

    /* Put a shown `menu` below `anchor` (above it when there is no room),
     * right-aligned with it by default ('left': left-aligned), kept 8px
     * inside the viewport. */
    function place(menu, anchor, { align = 'right', fallbackWidth = 240 } = {}) {
        const rect = anchor.getBoundingClientRect();
        const menuWidth = menu.offsetWidth || fallbackWidth;
        const menuHeight = menu.offsetHeight || 0;
        let left = align === 'left' ? rect.left : rect.right - menuWidth;
        if (align !== 'left' && left < 8) left = Math.max(8, rect.left);
        if (left + menuWidth > window.innerWidth - 8) left = window.innerWidth - menuWidth - 8;
        if (align === 'left' && left < 8) left = 8;
        let top = rect.bottom + 4;
        if (top + menuHeight > window.innerHeight - 8) top = Math.max(8, rect.top - menuHeight - 4);
        menu.style.left = `${left + window.scrollX}px`;
        menu.style.top = `${top + window.scrollY}px`;
    }

    return { fill, place };
})();
