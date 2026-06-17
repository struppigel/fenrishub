from django import template
from django.utils.html import escape
from django.utils.safestring import mark_safe

from fixlist import frst_extractors as ex
from fixlist.models import log_type_css_slug as _log_type_css_slug

register = template.Library()


@register.filter(name='log_type_css_slug')
def log_type_css_slug(name):
    """CSS class slug for a log_type name. Single source of truth shared with
    context_processors so the badge color rule and the element class always match."""
    return _log_type_css_slug(name or '')


@register.filter(name='chunk_log')
def chunk_log(content, lines_per_chunk=100):
    """Split log content into chunks of N lines for the uploaded-log viewer.

    Each chunk is rendered in its own block so the browser can skip laying out
    off-screen chunks via CSS `content-visibility: auto`, which keeps the page
    responsive (selection, scrolling) on large logs. Chunks carry no trailing
    newline; joining them back with '\\n' reproduces the original, so copy and
    download can reconstruct the full text from the rendered chunks."""
    if not content:
        return []
    try:
        n = int(lines_per_chunk)
    except (TypeError, ValueError):
        n = 100
    if n < 1:
        n = 100
    lines = content.split('\n')
    return ['\n'.join(lines[i:i + n]) for i in range(0, len(lines), n)]

_FIELDS = [
    ('entry_type', 'parsed-entry-type'),
    ('clsid', 'parsed-clsid'),
    ('filepath', 'parsed-filepath'),
    ('arguments', 'parsed-arguments'),
    ('company', 'parsed-company'),
    ('name', 'parsed-name'),
    ('filename', 'parsed-filename'),
]


@register.filter(name='highlight_parsed')
def highlight_parsed(rule, max_chars=120):
    source = rule.source_text or ''
    if rule.match_type != 'parsed':
        truncated = source[:max_chars] + ('...' if len(source) > max_chars else '')
        return escape(truncated)

    candidates = []

    for priority, (attr, css_class) in enumerate(_FIELDS):
        value = (getattr(rule, attr, '') or '').strip()
        if not value:
            continue
        position = ex.find_value_position(value, source, field_name=attr)
        if position is None:
            continue
        start, end = position
        candidates.append((start, end, css_class, priority))

    candidates.sort(key=lambda c: (c[0], -(c[1] - c[0]), c[3]))

    accepted = []
    for cand in candidates:
        if not any(not (cand[1] <= a[0] or cand[0] >= a[1]) for a in accepted):
            accepted.append(cand)
    accepted.sort(key=lambda c: c[0])

    # Truncate-aware rendering: build highlighted HTML up to max_chars of source text
    parts = []
    cursor = 0
    char_count = 0

    for start, end, css_class, _ in accepted:
        if char_count >= max_chars:
            break
        if cursor < start:
            plain = source[cursor:start]
            remaining = max_chars - char_count
            if len(plain) > remaining:
                parts.append(escape(plain[:remaining]))
                char_count += remaining
                break
            parts.append(escape(plain))
            char_count += len(plain)
        if char_count >= max_chars:
            break
        segment = source[start:end]
        remaining = max_chars - char_count
        if len(segment) > remaining:
            parts.append(f'<span class="{css_class}">{escape(segment[:remaining])}</span>')
            char_count += remaining
            break
        parts.append(f'<span class="{css_class}">{escape(segment)}</span>')
        char_count += len(segment)
        cursor = end

    if char_count < max_chars and cursor < len(source):
        remaining = max_chars - char_count
        tail = source[cursor:]
        if len(tail) > remaining:
            parts.append(escape(tail[:remaining]))
            char_count += remaining
        else:
            parts.append(escape(tail))
            char_count += len(tail)

    if char_count >= max_chars and cursor < len(source):
        parts.append('...')

    return mark_safe(''.join(parts))
