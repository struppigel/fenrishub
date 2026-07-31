"""Convert tool logs into a ready-to-post helper response.

Only SecurityCheck logs are supported so far: the BBCode-formatted report is
parsed into outdated software, unwanted programs, remote desktop tools and
notes, then rendered as reddit-flavoured markdown.
"""

import re


LOG_TYPE_SECURITYCHECK = 'SecurityCheck'

_WINDOWS_VERSION_RE = re.compile(r'(Windows \d+ \S+ \(\w+\)) Release: (\w+)')
_DOWNLOAD_UPDATE_URL_RE = re.compile(r'\[url=(.*?)\]Download Update\[/url\]')
_URL_RE = re.compile(r'\[url=(.*?)\]')
_LABELLED_URL_RE = re.compile(r'\[url=(.*?)\]([^\[]+)\[/url\]')
_TRAILING_COLOR_RE = re.compile(r'\s*\[color=red\].*$')
_TRAILING_BOLD_COLOR_RE = re.compile(r'\s*\[b\]\[color=red\].*$')
_TRAILING_BOLD_WARNING_RE = re.compile(r'\s*\[b\]Warning!\[/b\].*$')
_LEADING_BOLD_WARNING_RE = re.compile(r'.*\[b\]Warning!\[/b\]\s*')
_WARNING_REASON_RE = re.compile(r'\[color=red\]Warning!\s*(.*?)\[/color\]')
_BBCODE_TAG_RE = re.compile(r'\[/?[^\]]+\]')


def _plain_reason(line: str) -> str:
    """Strip the leading '[b]Warning![/b]' marker and all BBCode from a line."""
    after = _LEADING_BOLD_WARNING_RE.sub('', line)
    return _BBCODE_TAG_RE.sub('', after).strip()


def parse_securitycheck(content: str) -> list:
    """Extract the actionable items from a SecurityCheck report.

    Returns dicts with a 'type' of 'update', 'eol', 'unwanted',
    'remote_desktop' or 'note'. Branch order matters: the more specific
    markers (download link, end-of-life, remote desktop) have to win over the
    generic '[color=red]...Warning!' line shape.
    """
    results = []
    windows_version = None

    for line in (content or '').splitlines():
        line = line.strip()

        win_match = _WINDOWS_VERSION_RE.match(line)
        if win_match:
            windows_version = f"{win_match.group(1)} {win_match.group(2)}"

        if '[color=red]' in line and 'Warning!' in line and 'Download Update' in line:
            app = _TRAILING_COLOR_RE.sub('', line).strip()
            url_match = _DOWNLOAD_UPDATE_URL_RE.search(line)
            if url_match:
                if app == 'Extended support has ended' and windows_version:
                    app = f"{windows_version} - Extended support has ended"
                results.append({'type': 'update', 'app': app, 'url': url_match.group(1)})

        elif '[color=red]' in line and 'no longer supported' in line.lower():
            app = _TRAILING_BOLD_COLOR_RE.sub('', line).strip()
            url_match = _URL_RE.search(line)
            if url_match:
                results.append({'type': 'eol', 'app': app, 'url': url_match.group(1)})

        elif '[color=blue]' in line and '[url=' in line:
            url_match = _LABELLED_URL_RE.search(line)
            if url_match:
                results.append({
                    'type': 'note',
                    'subject': url_match.group(2).strip(),
                    'url': url_match.group(1),
                })

        elif 'Remote desktop software!' in line:
            app = _TRAILING_BOLD_COLOR_RE.sub('', line).strip()
            if app:
                results.append({'type': 'remote_desktop', 'app': app})

        elif '[color=red]' in line and 'Warning!' in line:
            app = _TRAILING_BOLD_COLOR_RE.sub('', line).strip()
            reason_match = _WARNING_REASON_RE.search(line)
            reason = reason_match.group(1).strip() if reason_match else ''
            if app:
                results.append({'type': 'unwanted', 'app': app, 'reason': reason})

        elif '[b]Warning![/b]' in line:
            app = _TRAILING_BOLD_WARNING_RE.sub('', line).strip()
            if app:
                results.append({'type': 'unwanted', 'app': app, 'reason': _plain_reason(line)})

    return results


def format_reddit(results: list) -> str:
    """Render parsed SecurityCheck items as reddit-flavoured markdown."""
    lines = []

    updates = [r for r in results if r['type'] in ('update', 'eol')]
    unwanted = [r for r in results if r['type'] == 'unwanted']
    remote_desktops = [r for r in results if r['type'] == 'remote_desktop']
    notes = [r for r in results if r['type'] == 'note']

    if updates:
        lines.append("Please update the following software:\n")
        for r in updates:
            if r['type'] == 'update':
                lines.append(f"* {r['app']} | [New update available, download here]({r['url']})")
            else:
                lines.append(f"* {r['app']} | [No longer supported, replace here]({r['url']})")
        lines.append("")

    if unwanted:
        lines.append("Please remove the following potentially unwanted programs (PUP):\n")
        for r in unwanted:
            reason = r.get('reason', '')
            lines.append(f"* **{r['app']}** - {reason}" if reason else f"* **{r['app']}**")
        lines.append("")

    if remote_desktops:
        lines.append("Please let me know whether you recognize this remote desktop software:\n")
        for r in remote_desktops:
            lines.append(f"* {r['app']}")
        lines.append("")

    for r in notes:
        lines.append(f"*Note: If {r['subject']} update errors occur, [reinstall here]({r['url']})*")

    return '\n'.join(lines).rstrip()


def convert_log_to_response(log_type: str, content: str) -> str:
    """Return a ready-to-post response for a supported log type, else ''."""
    if log_type != LOG_TYPE_SECURITYCHECK:
        return ''
    return format_reddit(parse_securitycheck(content))
