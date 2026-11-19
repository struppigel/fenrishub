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


# --- Fixlog: installed-app investigation ------------------------------------
# A fixlist PowerShell snippet that lists every installed app (Uninstall keys)
# with its install folder and the files in it:
#   "<=== <name> [<version>] (<publisher>) ===>"
#   "  Path: <folder> | Created: ... | Files: 27 | Folders: 3" (or "Path: N/A",
#   "Path: <x>" followed by "  [NOT FOUND]" / "  [ACCESS DENIED]" / "  [ERROR] ...")
#   "  [DIR] <created> - <modified> - <n> files - <folder>"
#   "  [<SHA256>] <created> - <modified> - <size> - Signer: <signer> - <path>"
# The signer is "Unsigned", "N/A (not PE)", a name, or a name followed by
# " [INVALID: <status>]".
SECTION_APP_INVESTIGATION = 'app investigation'
MAX_APPS_PER_LOG = 1000
_PS_START = '========= Powershell: ========='
_PS_END = '========= End of Powershell: ========='
_APP_HEADER_RE = re.compile(r'^<=== (.{1,300}) \[([^\[\]]{0,100})\] \((.{0,300})\) ===>\s*$')
_APP_PATH_RE = re.compile(r'^\s+Path: (.{1,600}?)(?: \| (.{0,300}))?\s*$')
_APP_COUNT_RE = re.compile(r'\b(Files|Folders): (\d{1,9})\b')
_APP_STATE_RE = re.compile(r'^\s+\[(NOT FOUND|ACCESS DENIED|ERROR)\]')
_APP_FILE_RE = re.compile(
    r'^\s+\[(?:[0-9A-Fa-f]{64}|N/A|HASH-ERROR)\] .{0,80}? - Signer: (.{0,300}?) - ([A-Za-z]:\\.{1,600})$'
)
_INVALID_SIGNER_RE = re.compile(r'\[INVALID: ([^\]]{0,60})\]\s*$')


@dataclass
class AppFacts:
    line_no: int
    name: str
    version: str = ''
    publisher: str = ''
    path: str = ''
    state: str = ''             # NOT FOUND / ACCESS DENIED / ERROR / N/A / MSI: ... ('' when listed)
    files: int = 0
    folders: int = 0
    is_folder: bool = False     # the path is a folder (else a single file)
    unsigned: int = 0           # PE files without a signature
    invalid: list = field(default_factory=list)   # [path, signer] of PE files whose signature does not hold
    signers: list = field(default_factory=list)   # distinct signers of its PE files, in order


def fixlog_app_facts(content):
    """An AppFacts per app of the installed-app investigation in a Fixlog's
    PowerShell output (only inside "Powershell:" blocks)."""
    apps = []
    if '<=== ' not in (content or ''):
        return apps
    inside = False
    current = None
    for index, body in enumerate(_bodies(content)):
        if body.startswith(_PS_START):
            inside, current = True, None
            continue
        if body.startswith(_PS_END):
            inside, current = False, None
            continue
        if not inside:
            continue
        m = _APP_HEADER_RE.match(body)
        if m:
            if len(apps) >= MAX_APPS_PER_LOG:
                break
            version, publisher = m.group(2).strip(), m.group(3).strip()
            current = AppFacts(index + 1, m.group(1).strip(), '' if version == '?' else version,
                               '' if publisher == '?' else publisher)
            apps.append(current)
            continue
        if current is None or not body.strip():
            continue
        m = _APP_PATH_RE.match(body)
        if m and not current.path and not current.state:
            path, details = m.group(1).strip(), m.group(2) or ''
            if is_path(path):
                current.path = path
            else:
                current.state = path[:120]
            counts = dict(_APP_COUNT_RE.findall(details))
            current.files = int(counts.get('Files', 0))
            current.folders = int(counts.get('Folders', 0))
            current.is_folder = 'Folders' in counts or path.endswith('\\')
            continue
        m = _APP_STATE_RE.match(body)
        if m:
            current.state = m.group(1)
            continue
        m = _APP_FILE_RE.match(body)
        if m:
            signer = m.group(1).strip()
            if signer.startswith('N/A'):
                continue
            if signer == 'Unsigned':
                current.unsigned += 1
                continue
            invalid = _INVALID_SIGNER_RE.search(signer)
            name = signer[:invalid.start()].strip() if invalid else signer
            if invalid and len(current.invalid) < 20:
                current.invalid.append([m.group(2).strip()[:300], f'{name} [{invalid.group(1)}]'[:200]])
            if name and name not in current.signers and len(current.signers) < 10:
                current.signers.append(name[:120])
    return apps


# --- MAU (Malicious App Uninstaller) ----------------------------------------
# Report form: "Analyzing <id>..." per product with "  Key=Value" lines (the
# Uninstall values) and "RESOLVED: Key=Value" lines; "Deleted items:" lists
# "  [File] <path>", "  [Dir] <path>", "  [RegKey] <key>", "  [RegValue] <key>\<value>",
# "  [Service] <name>", "  [Task] <path>"; "Failed to delete: <path>".
# Console form: the same behind "[hh:mm:ss] ", with "   Resolved: <name>",
# "   Publisher: <name>" and "Deleted <kind>: <target>" lines.
MAX_MAU_ITEMS = 2000
_MAU_TIME_RE = re.compile(r'^\[\d{1,2}:\d{2}:\d{2}\] ')
_MAU_ANALYZING_RE = re.compile(r'^Analyzing (.{1,300}?)\.\.\.\s*$')
_MAU_VALUE_RE = re.compile(r'^\s+(DisplayName|DisplayVersion|Publisher|InstallLocation|InstallSource)=(.{0,600})$')
_MAU_RESOLVED_RE = re.compile(r'^RESOLVED: (DisplayName|Publisher|InstallLocation)=(.{0,600})$')
_MAU_CONSOLE_VALUE_RE = re.compile(r'^\s+(Resolved|Publisher): (.{1,300})$')
_MAU_ITEM_RE = re.compile(r'^\s*\[(File|Dir|Directory|RegKey|RegValue|Service|Task)\] (.{1,1000})$')
_MAU_DELETED_RE = re.compile(
    r'^\s*Deleted (file|directory|folder|dir|registry key|registry value|key|value|service|task): (.{1,1000})$',
    re.IGNORECASE,
)
_MAU_FAILED_RE = re.compile(r'^\s*Failed to delete: (.{1,1000})$')
_MAU_UNINSTALL_KEY_RE = re.compile(r'\\Uninstall\\[^\\]{1,300}$', re.IGNORECASE)
_MAU_CONSOLE_KINDS = {
    'file': 'File', 'directory': 'Dir', 'folder': 'Dir', 'dir': 'Dir', 'registry key': 'RegKey', 'key': 'RegKey',
    'registry value': 'RegValue', 'value': 'RegValue', 'service': 'Service', 'task': 'Task',
}
_MAU_ATTRS = {
    'DisplayName': 'name', 'DisplayVersion': 'version', 'Publisher': 'publisher',
    'InstallLocation': 'install_location', 'InstallSource': 'install_source',
}


@dataclass
class MauProduct:
    line_no: int
    ident: str                  # the "Analyzing" id: an MSI product code or a name
    name: str = ''
    version: str = ''
    publisher: str = ''
    install_location: str = ''
    install_source: str = ''
    uninstall_keys: list = field(default_factory=list)


@dataclass
class MauItem:
    line_no: int
    kind: str                   # File / Dir / RegKey / RegValue / Service / Task
    target: str
    failed: bool = False        # "Failed to delete: <path>"


def _mau_value(value):
    value = (value or '').strip()
    return '' if not value or value.startswith('<') else value


def mau_facts(content):
    """(products, deleted items) of a MAU log, report or console form."""
    products, items = [], []
    current = None
    in_deleted = False
    for index, raw in enumerate(_bodies(content)):
        stamp = _MAU_TIME_RE.match(raw)
        body = raw[stamp.end():] if stamp else raw
        if not body.strip():
            continue
        m = _MAU_ANALYZING_RE.match(body)
        if m:
            current = MauProduct(index + 1, m.group(1).strip())
            products.append(current)
            in_deleted = False
            continue
        if body.startswith('Deleted items'):
            in_deleted = True
            continue
        if current is not None and not in_deleted:
            m = _MAU_VALUE_RE.match(body) or _MAU_RESOLVED_RE.match(body)
            if m:
                attr, value = _MAU_ATTRS[m.group(1)], _mau_value(m.group(2))
                if value and not getattr(current, attr):
                    setattr(current, attr, value[:300])
                continue
            m = _MAU_CONSOLE_VALUE_RE.match(body)
            if m:
                attr = 'name' if m.group(1) == 'Resolved' else 'publisher'
                if not getattr(current, attr):
                    setattr(current, attr, _mau_value(m.group(2))[:300])
                continue
        m = _MAU_ITEM_RE.match(body)
        if m:
            kind = 'Dir' if m.group(1) == 'Directory' else m.group(1)
            target = m.group(2).strip()
            if in_deleted and len(items) < MAX_MAU_ITEMS:
                items.append(MauItem(index + 1, kind, target))
            elif current is not None and kind == 'RegKey' and _MAU_UNINSTALL_KEY_RE.search(target) \
                    and target not in current.uninstall_keys:
                # The product's own Uninstall key among its traces.
                current.uninstall_keys.append(target)
            continue
        if len(items) >= MAX_MAU_ITEMS:
            continue
        m = _MAU_DELETED_RE.match(body)
        if m:
            items.append(MauItem(index + 1, _MAU_CONSOLE_KINDS[m.group(1).lower()], m.group(2).strip()))
            continue
        m = _MAU_FAILED_RE.match(body)
        if m:
            items.append(MauItem(index + 1, 'File', m.group(1).strip(), failed=True))
    return products, items
