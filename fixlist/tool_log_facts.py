"""What FRST Search and Shortcut logs say about files: pure text parsing for
the correlations of FRST lines (case_correlations) and the FRST Search hash
rows (file_hashes). No app imports besides spor_log's Mention.

FRST Search ("Search Files" / "SearchAll"):
- File: blocks: the path on one line, then
  "[created][modified] <size> <attributes> (<company>) <MD5> [File not signed]";
- Folder: lines: "<created> - <modified> <attributes> <path>";
- registry results: "[HKEY_...]" key lines, then '"name"="value"' lines.

Shortcut ("Users shortcut scan result"):
- "Shortcut: <lnk> -> <target> (<company>)" ("(No File)": the target is gone).

Line numbers count content.split('\\n') from 1, like the log page.
"""

import re
from dataclasses import dataclass, field

from .spor_log import Mention, is_path

SECTION_FRST_SEARCH = 'FRST Search'
SECTION_SHORTCUT = 'Shortcut'

_FS_META_RE = re.compile(
    r'^\[([^\[\]]{0,40})\]\[([^\[\]]{0,40})\] (\d{1,15}) (\S{1,15}) \(([^()]{0,200})\) ?([0-9A-Fa-f]{32})?(.{0,200})$'
)
_FS_FOLDER_RE = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d) - (\d{4}-\d\d-\d\d \d\d:\d\d) (\S{1,15}) (.{1,600})$')
_FS_REG_KEY_RE = re.compile(r'^\[(HKEY_[^\]]{1,600}|HK[A-Z]{1,4}\\[^\]]{1,600})\]\s*$')
_FS_REG_VALUE_RE = re.compile(r'^("[^"]{0,300}"|@)=(.{0,2000})$')
_FS_HEADER_RE = re.compile(r'^(File|Folder|Registry):\s*$')
_VALUE_PATH_RE = re.compile(r'[A-Za-z]:\\[^"<>|*?\r\n]{1,600}')
_EXTENSION_END_RE = re.compile(r'^(.{0,600}?\.[A-Za-z0-9]{1,6})(?= |$)')
_UNSIGNED = '[File not signed]'
_SHORTCUT_RE = re.compile(r'^([A-Za-z]{1,40}): (.{1,1200}?) -> (.{1,2000})$')


@dataclass
class FileFacts:
    line_no: int
    path: str
    source: str
    md5: str = ''
    facts: dict = field(default_factory=dict)
    hash_line_no: int = 0   # the line with the MD5 (FRST Search: the line below the path)


def _bodies(content):
    return [raw[:-1] if raw.endswith('\r') else raw for raw in (content or '').split('\n')]


def _value_path(value):
    """The file a registry value names ('' if none): its first path, cut at
    the end of the file name when arguments follow."""
    m = _VALUE_PATH_RE.search(value)
    if not m:
        return ''
    candidate = m.group(0).strip()
    cut = _EXTENSION_END_RE.match(candidate)
    return (cut.group(1) if cut else candidate).strip()


def frst_search_facts(content):
    """(file facts, mentions) of an FRST Search log: a FileFacts per File:
    entry (dates, size, attributes, company, MD5, signed or not), a Mention
    per Folder: line and per registry value that names a file."""
    bodies = _bodies(content)
    files, mentions = [], []
    block = ''
    last_path = None   # (line_no, path) of the path line right above
    reg_key = ''
    for index, body in enumerate(bodies):
        stripped = body.strip()
        header = _FS_HEADER_RE.match(stripped)
        if header:
            block, last_path, reg_key = header.group(1), None, ''
            continue
        if not stripped or set(stripped) == {'='}:
            # A blank line, or the "========" under "File:" / "Folder:".
            last_path = None
            continue
        if stripped.startswith('='):
            # "==== Search result for ... ====": registry results follow.
            block = 'Registry' if 'Search result' in stripped else ''
            last_path = None
            continue
        m = _FS_META_RE.match(stripped)
        if m and last_path is not None:
            created, modified, size, attributes, company, md5, rest = m.groups()
            facts = {'created': created, 'modified': modified, 'size': size.lstrip('0') or '0',
                     'attributes': attributes, 'company': company.strip(),
                     'signed': 'not signed' if _UNSIGNED in rest else ''}
            files.append(FileFacts(last_path[0], last_path[1], 'frst_search', (md5 or '').lower(),
                                   {key: value for key, value in facts.items() if value}, index + 1))
            last_path = None
            continue
        if block == 'File' and is_path(stripped):
            last_path = (index + 1, stripped)
            continue
        m = _FS_FOLDER_RE.match(stripped)
        if m and is_path(m.group(4)):
            created, modified, attributes, path = m.groups()
            mentions.append(Mention(index + 1, path.strip(), SECTION_FRST_SEARCH, 'Folder', modified, '', stripped[:300],
                                    'listed', extra=[['created', created], ['attributes', attributes]]))
            continue
        m = _FS_REG_KEY_RE.match(stripped)
        if m:
            reg_key = m.group(1)
            continue
        m = _FS_REG_VALUE_RE.match(stripped)
        if m and reg_key:
            path = _value_path(m.group(2))
            if path:
                mentions.append(Mention(index + 1, path, SECTION_FRST_SEARCH, 'Registry', '', '', stripped[:300],
                                        'registry', parent=reg_key[:200]))
    return files, mentions


def shortcut_mentions(content):
    """Mentions of a Shortcut log: the target of each shortcut (with the
    shortcut and the target's company, or "No File"), and the shortcut file."""
    out = []
    for index, body in enumerate(_bodies(content)):
        m = _SHORTCUT_RE.match(body.strip())
        if not m:
            continue
        label, lnk, target = m.groups()
        target = target.split(' -> ', 1)[0].strip()
        company = ''
        if target.endswith(')') and ' (' in target:
            cut = target.rfind(' (')
            company = target[cut + 2:-1]
            target = target[:cut].strip()
        text = body.strip()[:300]
        status = 'gone' if company == 'No File' else ''
        if is_path(target):
            out.append(Mention(index + 1, target, SECTION_SHORTCUT, label, '', '', text, 'shortcut target',
                               status=status, extra=[['shortcut', lnk.strip()[:200]],
                                                     ['company', company or 'none']]))
        if is_path(lnk.strip()):
            out.append(Mention(index + 1, lnk.strip(), SECTION_SHORTCUT, label, '', '', text, 'shortcut',
                               extra=[['target', target[:200]]]))
    return out
