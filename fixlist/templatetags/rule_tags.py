from django import template
from django.utils.html import escape
from django.utils.safestring import mark_safe

register = template.Library()

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

    lower_source = source.lower()
    candidates = []

    for priority, (attr, css_class) in enumerate(_FIELDS):
        value = (getattr(rule, attr, '') or '').strip()
        if not value:
            continue
        lower_value = value.lower()
        start = 0
        while start < len(lower_source):
            pos = lower_source.find(lower_value, start)
            if pos == -1:
                break
            candidates.append((pos, pos + len(lower_value), css_class, priority))
            start = pos + len(lower_value)

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
