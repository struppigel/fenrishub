// Loading indicator shared by the analyzer and the log search: the status
// text followed by a spinning ring (.status-spinner in components.css).
// The ring is a CSS transform animation, so the browser keeps turning it on
// the compositor while the page's JS is busy (drawing thousands of analyzed
// lines, parsing a big response). A setInterval spinner froze exactly then.
(function () {
    function startStatusSpinner(element, baseText) {
        if (!element) {
            return () => {};
        }
        element.textContent = '';
        const baseSpan = document.createElement('span');
        baseSpan.textContent = baseText;
        // Hidden from screen readers: the text says what is happening.
        const spinSpan = document.createElement('span');
        spinSpan.className = 'status-spinner';
        spinSpan.setAttribute('aria-hidden', 'true');
        element.appendChild(baseSpan);
        element.appendChild(spinSpan);
        return () => spinSpan.remove();
    }

    window.startStatusSpinner = startStatusSpinner;
})();
