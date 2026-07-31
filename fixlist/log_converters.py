"""Convert tool logs into a ready-to-post helper response.

Only SecurityCheck logs are supported so far: the BBCode-formatted report is
parsed into outdated software, unwanted programs, remote access tools, risky
Windows settings and notes, then rendered as reddit-flavoured markdown.

Encodings are already handled at upload time (see UploadedLogForm), so the
parser only ever sees decoded text.
"""

import re


LOG_TYPE_SECURITYCHECK = 'SecurityCheck'

# SecurityCheck exists in several locales/versions, so every marker has variants:
# "Warning!" (current EN), "Attention!" (older EN builds), "Внимание!" (RU).
_WARN = r'(?:Warning!|Attention!|Внимание!)'
_DOWNLOAD_LABEL = r'(?:Download\s+Updates?|Скачать\s+обновления)'
_EOL = r'(?:no longer supported|больше не поддерживается)'
_REMOTE = r'(?:Remote desktop software!|Remote access program!|Программа для удал[её]нного)'
_SETTING_LABEL = r'(User Account Control|The elevation prompt for .+?)'
_RECOMMEND = r'(?:It is recommended to uninstall|Uninstallation recommended|Рекомендуется удалить|Рекомендуется деинсталляция)'

_WARN_RE = re.compile(_WARN)
_DOWNLOAD_ONLY_RE = re.compile(_DOWNLOAD_LABEL, re.I)
_DOWNLOAD_URL_RE = re.compile(r'\[url=(.*?)\]\s*' + _DOWNLOAD_LABEL + r'\s*\[/url\]', re.I)
_EOL_RE = re.compile(_EOL, re.I)
_REMOTE_RE = re.compile(_REMOTE, re.I)
_RECOMMEND_RE = re.compile(_RECOMMEND, re.I)
_UAC_RE = re.compile(r'^' + _SETTING_LABEL + r'\s*\[color=red\]\[b\](.+?)\[/b\]')
_LABELLED_SETTING_RE = re.compile(_SETTING_LABEL + r'\s+(.+)$')
_WINDOWS_VERSION_RE = re.compile(r'(Windows \d+ \S+ \(\w+\)) Release: (\w+)')
_LABELLED_URL_RE = re.compile(r'\[url=(.*?)\]([^\[]+)\[/url\]')
_URL_RE = re.compile(r'\[url=(.*?)\]')
_ITALIC_RE = re.compile(r'\[i\].*?\[/i\]')
_BBCODE_TAG_RE = re.compile(r'\[/?[^\]]*\]')
_WHITESPACE_RE = re.compile(r'\s+')
_APP_SPLIT_RE = re.compile(r'\s*\[(?:b|color|i|url)[^\]]*\]')


def _strip_bb(text: str) -> str:
    text = _ITALIC_RE.sub('', text)
    text = _BBCODE_TAG_RE.sub('', text)
    return _WHITESPACE_RE.sub(' ', text.replace('^', '')).strip(' .')


def _app_name(line: str) -> str:
    """Everything before the first bbcode tag is the program name."""
    return _APP_SPLIT_RE.split(line, maxsplit=1)[0].strip()


def _warning_segments(line: str) -> list:
    """Split a line into one chunk per warning marker (a line can carry several).

    Returns (offset, text) pairs; the offset is the chunk's position in the line,
    so a link belonging to a chunk can be looked up without rescanning the rest.
    """
    marks = list(_WARN_RE.finditer(line))
    segments = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(line)
        segments.append((m.end(), line[m.end():end]))
    return segments


def parse_securitycheck(content: str) -> list:
    """Extract the actionable items from a SecurityCheck report.

    Returns dicts with a 'type' of 'update', 'eol', 'unwanted',
    'remote_desktop', 'setting' or 'note'.
    """
    results = []
    windows_version = None
    for line in (content or '').splitlines():
        line = line.strip()
        if not line:
            continue

        win_match = _WINDOWS_VERSION_RE.match(line)
        if win_match:
            windows_version = f"{win_match.group(1)} {win_match.group(2)}"
            continue

        uac_match = _UAC_RE.match(line)
        if uac_match:
            results.append({'type': 'setting', 'setting': uac_match.group(1).strip(),
                            'state': _strip_bb(uac_match.group(2))})
            continue

        # Standalone red system setting, e.g. "Never check for updates" or a
        # fully wrapped "[color=red][b]User Account Control [b]disabled[/b][/b][/color]".
        if line.startswith('[color=red]') and not _app_name(line):
            text = _strip_bb(line)
            if text:
                labelled = _LABELLED_SETTING_RE.match(text)
                if labelled:
                    results.append({'type': 'setting', 'setting': labelled.group(1),
                                    'state': labelled.group(2)})
                else:
                    results.append({'type': 'setting', 'setting': text, 'state': ''})
            continue

        # Standalone advice line printed underneath the program it belongs to.
        if line.startswith('[color=blue]'):
            url_match = _LABELLED_URL_RE.search(line)
            if url_match and 'update errors' in _strip_bb(line).lower():
                results.append({'type': 'note', 'subject': url_match.group(2).strip(),
                                'url': url_match.group(1)})
            else:
                hint = _strip_bb(line)
                if hint and results:
                    previous = results[-1].get('hint')
                    results[-1]['hint'] = f"{previous}; {hint}" if previous else hint
            continue

        has_warning = bool(_WARN_RE.search(line))
        if not has_warning and not _RECOMMEND_RE.search(line):
            continue

        app = _app_name(line)
        if not app:
            continue

        if not has_warning:
            reason = _strip_bb(line[len(app):])
            if reason:
                results.append({'type': 'unwanted', 'app': app, 'reason': reason})
            continue
        if app == 'Extended support has ended' and windows_version:
            app = f"{windows_version} - Extended support has ended"

        handled = False
        segments = _warning_segments(line)
        # Only a notice that belongs to a warning counts; the same words inside
        # a PUP description must not turn the entry into an end-of-life one.
        eol_at = next((offset + m.start() for offset, text in segments
                       for m in [_EOL_RE.search(text)] if m), None)

        # A dead product is not worth updating, so end-of-life wins over the
        # update link such a line often carries as well.
        if eol_at is None:
            for url in _DOWNLOAD_URL_RE.findall(line):
                results.append({'type': 'update', 'app': app, 'url': url})
                handled = True
        else:
            # The replacement link follows the notice; older builds print none.
            url_match = _URL_RE.search(line[eol_at:])
            results.append({'type': 'eol', 'app': app,
                            'url': url_match.group(1) if url_match else None})
            handled = True

        if _REMOTE_RE.search(line):
            results.append({'type': 'remote_desktop', 'app': app})
            handled = True

        for _, segment in segments:
            reason = _strip_bb(segment)
            if not reason:
                continue
            if _DOWNLOAD_ONLY_RE.fullmatch(reason):
                continue
            if _EOL_RE.search(reason) or _REMOTE_RE.search(reason):
                continue
            results.append({'type': 'unwanted', 'app': app, 'reason': reason})
            handled = True

        if not handled:
            results.append({'type': 'unwanted', 'app': app, 'reason': ''})

    return results


def _hint(r: dict) -> str:
    return f" ({r['hint']})" if r.get('hint') else ""


# Section headings, in output order. Outdated / end-of-life software belongs
# with the programs to uninstall, not with the ones that can simply be updated.
SECTIONS = (
    (('update',), "Please update the following software:"),
    (('unwanted', 'eol'), "Please remove the following potentially unwanted programs (PUP):"),
    (('remote_desktop',), "Please let me know whether you recognize this remote desktop software (if not, uninstall it):"),
    (('setting',), "Please check the following Windows settings:"),
)


def _format(results: list, markdown: bool) -> list:
    """Render the parsed results as plain text, or as Reddit-flavoured markdown."""
    def bold(text):
        return f"**{text}**" if markdown else text

    def bullet(text):
        return f"* {text}" if markdown else text

    def link(url, label):
        return f"[{label}]({url})" if markdown else f"{label} {url}"

    def entry(r):
        if r['type'] == 'update':
            label = "New update available, download here" if markdown else "Download Update"
            return f"{bold(r['app'])} | {link(r['url'], label)}"
        if r['type'] == 'eol':
            reason = "No longer supported - please uninstall it"
            if r.get('url'):
                replacement = link(r['url'], "replace it here" if markdown else "replace it with")
                reason = f"{reason} and {replacement}"
            return f"{bold(r['app'])} - {reason}"
        if r['type'] == 'setting':
            state = f" - {r['state']}" if r['state'] else ""
            return f"{bold(r['setting'])}{state}"
        reason = r.get('reason', '')
        return f"{bold(r['app'])} - {reason}" if reason else bold(r['app'])

    lines = []
    for types, heading in SECTIONS:
        section = [r for r in results if r['type'] in types]
        if not section:
            continue
        lines.append(bold(heading))
        lines.extend(bullet(entry(r)) + _hint(r) for r in section)
        lines.append("")

    for r in results:
        if r['type'] == 'note':
            note = f"Note: If {r['subject']} update errors occur, " + link(
                r['url'], "reinstall here" if markdown else "reinstall from")
            lines.append(f"*{note}*" if markdown else note)

    return lines


def format_reddit(results: list) -> str:
    """Render parsed SecurityCheck items as reddit-flavoured markdown."""
    return '\n'.join(_format(results, markdown=True)).rstrip()


def convert_log_to_response(log_type: str, content: str) -> str:
    """Return a ready-to-post response for a supported log type, else ''."""
    if log_type != LOG_TYPE_SECURITYCHECK:
        return ''
    return format_reddit(parse_securitycheck(content))
