// Console-style loading indicator shared by the analyzer and the log search.
// Braille frames render in any modern monospace font and give status lines a
// familiar CLI feel.
(function () {
    const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

    function startStatusSpinner(element, baseText) {
        if (!element) {
            return () => {};
        }
        // The spinner glyph is hidden from screen readers — it ticks ~12 times
        // per second and would spam any aria-live attribute on the parent.
        element.textContent = '';
        const baseSpan = document.createElement('span');
        baseSpan.textContent = baseText;
        const spinSpan = document.createElement('span');
        spinSpan.setAttribute('aria-hidden', 'true');
        spinSpan.textContent = ` ${SPINNER_FRAMES[0]}`;
        element.appendChild(baseSpan);
        element.appendChild(spinSpan);

        let i = 1;
        const id = setInterval(() => {
            spinSpan.textContent = ` ${SPINNER_FRAMES[i % SPINNER_FRAMES.length]}`;
            i += 1;
        }, 80);
        return () => clearInterval(id);
    }

    window.SPINNER_FRAMES = SPINNER_FRAMES;
    window.startStatusSpinner = startStatusSpinner;
})();
