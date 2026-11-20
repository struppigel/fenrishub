/* Token highlighting for log lines shown outside the log page (the
 * correlation info box): the same classes as the log page's highlighting, so
 * log_highlight.css colours them the same way.
 *
 * A port of fixlist/log_highlighting.py: `_inline` (free text: paths,
 * registry keys, GUIDs, hashes, URLs) and `_frst_tokens` (an FRST entry:
 * that plus companies, size / date, warnings). The patterns are Python's
 * pattern sources verbatim (String.raw, `(?P<` written `(?<`), and
 * CorrelationTokensParityTests checks that they stay so.
 *
 * Like the Python highlighters, text is tokenized line by line ('\n', a
 * trailing '\r' kept as plain text), and the token texts joined give the
 * input back, so the text of a highlighted node is the text.
 *
 * LogTokens.tokens(text, frst)          -> [[cls, text], ...] ('' = plain text)
 * LogTokens.append(parent, text, frst)  appends text nodes / <span class=cls>
 * `frst`: the text is FRST / Addition lines (adds the FRST-only tokens).
 * Plain globals, no modules (no build step). */
window.LogTokens = (function () {
    const INLINE_RE = new RegExp(String.raw`(?<url>\bhttps?://[^\s"\'<>()]+)|(?<guid>\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})|(?<hash>\b(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})\b)|(?<path>(?<![A-Za-z0-9\\])[A-Za-z]:\\|\\\\[?.]\\|(?<![A-Za-z0-9\\])(?:HKLM|HKCU|HKU|HKCR|HKCC|HKEY_[A-Z_]+)(?=\\|$))`, 'g');
    // Where a path that started mid-line ends (see _PATH_STOP_RE).
    const PATH_STOP_RE = new RegExp(String.raw` ?->| ?=>| <|\t|"|, |;(?=\s|$)| \((?!x86\))(?![^()\\]*\)(?:\\|\.\w))| \[|$`, 'g');
    const FRST_FILE_DATES_RE = new RegExp(String.raw`^\d{4}-\d\d-\d\d \d\d:\d\d - \d{4}-\d\d-\d\d \d\d:\d\d - \d+ [_A-Z]{5} `);
    const FRST_SPECIAL_RE = new RegExp(String.raw`(?<attention><=+ ?ATTENTION.*$)|(?<unsigned>\[File not signed\]|\(No File\)|\[No File\]|=> No File\b)|(?<company>\((?:[^()\\]{0,160}) -> (?:[^()\\]{0,160})\))|(?<sizedate>\[\d+ \d{4}-\d\d-\d\d\])|(?<count> <\d+>$)`, 'g');

    const CLASS_FOR_KIND = { url: 'hl-url', guid: 'hl-guid', hash: 'hl-hash' };
    const FRST_SPECIAL_CLASS = {
        attention: 'hl-sev-w', unsigned: 'hl-sev-w', company: 'hl-company',
        sizedate: 'hl-dim', count: 'hl-dim',
    };

    function matchedGroup(match) {
        return Object.keys(match.groups).find((name) => match.groups[name] !== undefined);
    }

    // One line of free text (_inline).
    function inline(text) {
        const out = [];
        let pos = 0;
        while (pos < text.length) {
            INLINE_RE.lastIndex = pos;
            const m = INLINE_RE.exec(text);
            if (!m) break;
            const kind = matchedGroup(m);
            const start = m.index;
            const matchEnd = start + m[0].length;
            let end = matchEnd;
            let cls = CLASS_FOR_KIND[kind];
            if (kind === 'path') {
                PATH_STOP_RE.lastIndex = matchEnd;
                end = PATH_STOP_RE.exec(text).index;
                while (end > matchEnd && text[end - 1] === ' ') end -= 1;
                end = Math.max(end, matchEnd);
                cls = 'Hh'.includes(text[start]) ? 'hl-reg' : 'hl-path';
            }
            if (start > pos) out.push(['', text.slice(pos, start)]);
            out.push([cls, text.slice(start, end)]);
            pos = end;
        }
        if (pos < text.length) out.push(['', text.slice(pos)]);
        return out;
    }

    // One FRST entry (_frst_tokens): size/date prefix, companies, warnings, then paths.
    function frstLine(text) {
        const out = [];
        let pos = 0;
        const dates = FRST_FILE_DATES_RE.exec(text);
        if (dates) {
            out.push(['hl-dim', dates[0]]);
            pos = dates[0].length;
        }
        FRST_SPECIAL_RE.lastIndex = pos;
        let m;
        while ((m = FRST_SPECIAL_RE.exec(text)) !== null) {
            if (m.index > pos) out.push(...inline(text.slice(pos, m.index)));
            out.push([FRST_SPECIAL_CLASS[matchedGroup(m)], m[0]]);
            pos = m.index + m[0].length;
        }
        if (pos < text.length) out.push(...inline(text.slice(pos)));
        return out;
    }

    function tokens(text, frst = false) {
        const out = [];
        (typeof text === 'string' ? text : '').split('\n').forEach((raw, index) => {
            if (index) out.push(['', '\n']);
            const cr = raw.endsWith('\r');
            const body = cr ? raw.slice(0, -1) : raw;
            out.push(...(frst ? frstLine(body) : inline(body)));
            if (cr) out.push(['', '\r']);
        });
        return out.filter((token) => token[1]);
    }

    function append(parent, text, frst = false) {
        tokens(text, frst).forEach(([cls, piece]) => {
            if (cls) {
                const span = document.createElement('span');
                span.className = cls;
                span.textContent = piece;
                parent.appendChild(span);
            } else {
                parent.appendChild(document.createTextNode(piece));
            }
        });
        return parent;
    }

    return { tokens, append };
})();
