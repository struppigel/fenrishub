/* Inline highlighting of a rule's parsed fields (entry type, clsid, path, ...)
 * within its source line. Shared by the analyzer's rule review / line inspector
 * and the add/edit rule page, so both colour a rule the same way.
 * Plain globals, no modules (no build step). */

const PATH_DRIVE_MARK = '\u0000DRIVE\u0000';
const PATH_USER_MARK = '\u0000USER\u0000';
const PATH_FFPROFILE_MARK = '\u0000FFPROFILE\u0000';
const REGEX_SPECIAL_CHARS = /[.*+?^${}()|[\]\\]/g;

function escapeRegExp(value) {
    return value.replace(REGEX_SPECIAL_CHARS, '\\$&');
}

function denormalizePathPattern(normalizedPath) {
    if (!normalizedPath) {
        return null;
    }

    let work = normalizedPath;
    if (work.length >= 2 && work[1] === ':') {
        work = PATH_DRIVE_MARK + work.slice(2);
    }
    work = work.replace(/(\\Users\\)username(\\)/gi, `$1${PATH_USER_MARK}$2`);
    work = work.replace(
        /(\\Mozilla\\Firefox\\Profiles\\)profile/gi,
        `$1${PATH_FFPROFILE_MARK}`,
    );

    let pattern = escapeRegExp(work);
    pattern = pattern.replace(escapeRegExp(PATH_DRIVE_MARK), '[A-Za-z]:');
    pattern = pattern.replace(escapeRegExp(PATH_USER_MARK), '[^\\\\]+');
    pattern = pattern.replace(escapeRegExp(PATH_FFPROFILE_MARK), '[^\\\\]+');
    return pattern;
}

function findValuePosition(value, source, fieldKey) {
    if (!value || !source) {
        return null;
    }

    const lowerSource = source.toLowerCase();
    const lowerValue = value.toLowerCase();
    const pos = lowerSource.indexOf(lowerValue);
    if (pos !== -1) {
        return { start: pos, end: pos + value.length };
    }

    if (fieldKey !== 'filepath' && fieldKey !== 'filename') {
        return null;
    }

    const pattern = denormalizePathPattern(value);
    if (!pattern) {
        return null;
    }
    try {
        const regex = new RegExp(pattern, 'i');
        const match = regex.exec(source);
        if (match) {
            return { start: match.index, end: match.index + match[0].length };
        }
    } catch (e) {
        return null;
    }
    return null;
}

function collectInlineHighlightMatches(sourceText, change) {
    if (typeof sourceText !== 'string' || !sourceText.length || !change) {
        return [];
    }

    const fields = [
        { key: 'entry_type', className: 'parsed-entry-type' },
        { key: 'clsid', className: 'parsed-clsid' },
        { key: 'filepath', className: 'parsed-filepath' },
        { key: 'arguments', className: 'parsed-arguments' },
        { key: 'company', className: 'parsed-company' },
        { key: 'name', className: 'parsed-name' },
        { key: 'filename', className: 'parsed-filename' },
    ];

    const candidates = [];

    fields.forEach((field, priority) => {
        const rawValue = change[field.key];
        if (rawValue === null || rawValue === undefined) {
            return;
        }

        const needle = String(rawValue).trim();
        if (!needle) {
            return;
        }

        const position = findValuePosition(needle, sourceText, field.key);
        if (!position) {
            return;
        }

        candidates.push({
            start: position.start,
            end: position.end,
            className: field.className,
            priority,
        });
    });

    candidates.sort((a, b) => {
        if (a.start !== b.start) {
            return a.start - b.start;
        }
        const aLen = a.end - a.start;
        const bLen = b.end - b.start;
        if (aLen !== bLen) {
            return bLen - aLen;
        }
        return a.priority - b.priority;
    });

    const accepted = [];
    candidates.forEach((candidate) => {
        const overlaps = accepted.some(
            (existing) => !(candidate.end <= existing.start || candidate.start >= existing.end)
        );
        if (!overlaps) {
            accepted.push(candidate);
        }
    });

    accepted.sort((a, b) => a.start - b.start);
    return accepted;
}

function appendHighlightedRuleLine(container, sourceText, change) {
    const text = typeof sourceText === 'string' ? sourceText : '';
    if (!text.length) {
        return;
    }

    const matches = collectInlineHighlightMatches(text, change);
    if (!matches.length) {
        container.appendChild(document.createTextNode(text));
        return;
    }

    let cursor = 0;
    matches.forEach((match) => {
        if (cursor < match.start) {
            container.appendChild(document.createTextNode(text.slice(cursor, match.start)));
        }

        const span = document.createElement('span');
        span.className = match.className;
        span.textContent = text.slice(match.start, match.end);
        container.appendChild(span);

        cursor = match.end;
    });

    if (cursor < text.length) {
        container.appendChild(document.createTextNode(text.slice(cursor)));
    }
}
