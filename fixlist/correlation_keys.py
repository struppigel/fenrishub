"""Keys that tie an FRST / Addition line to what another log says about it.

The correlations (case_correlations.py) index everything other logs say under
these keys and look up every key of each analyzed line:

- a file path, the analyzer's normalized and lowercased key, with no prefix:
  the line's own file (`match` 'path') and the files in its command line
  (`match` 'argument': a script run by powershell / wscript, a DLL run by
  rundll32);
- typed keys for things that are not files, with a prefix:
  `run:<value>` (Run / RunOnce values), `svc:<name>` (services and drivers),
  `task:<path>` and `taskid:<guid>` (scheduled tasks), `ext:<id>` (browser
  extensions), `clsid:<guid>` (COM objects), `fw:<rule>` (firewall rules),
  `uninstall:<subkey>` (an installed program's Uninstall key: Addition's
  Installed Programs, Spor's SOFTWARE section, scanner / Fixlog targets) and
  `msi:<guid>` (an MSI product code, which is also its Uninstall subkey) and
  `app:<display name>` (an installed program by its name: Addition's Installed
  Programs, a Fixlog app investigation, MAU; the versions are compared when
  the entries are matched, see installed_program).

Scanner detections, Fixlog results and hash rows give their keys through
target_keys(); analyzed lines through line_keys(). Hives and user SIDs are
left out of typed keys: the related logs come from the same case or forum user.
Pure functions, no database.
"""

import re

from . import frst_extractors as ex
from .file_hashes import _as_path, normalized_path

MATCH_PATH = 'path'
MATCH_ARGUMENT = 'argument'
# Key prefix -> the `match` an entry found through it gets.
TYPED_MATCHES = {
    'run': 'registry',
    'svc': 'service',
    'task': 'task',
    'taskid': 'task',
    'ext': 'extension',
    'clsid': 'clsid',
    'fw': 'firewall',
    'uninstall': 'uninstall',
    'msi': 'msi',
    'app': 'app',
}

_GUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

# --- Targets (scanner detections, Fixlog results), lowercased --------------
# "...\CurrentVersion\Run|evil" (Malwarebytes), "...\Run\\evil" (Fixlog).
_RUN_TARGET_RE = re.compile(r'\\run(?:once)?(?:\\\\|\|)([^\\|]+)$')
_SERVICE_TARGET_RE = re.compile(r'\\currentcontrolset\\services\\([^\\|]+)$')
_TASK_ID_TARGET_RE = re.compile(r'\\schedule\\taskcache\\(?:tasks|logon|boot|plain|maintenance)\\\{(' + _GUID + r')\}$')
_TASK_TREE_TARGET_RE = re.compile(r'\\schedule\\taskcache\\tree\\(.+)$')
_TASK_FILE_RE = re.compile(r'^(?:[a-z]:\\windows\\)?system32\\tasks\\(.+)$')
_CLSID_TARGET_RE = re.compile(r'\\(?:clsid|browser helper objects)\\\{(' + _GUID + r')\}$')
_FIREWALL_TARGET_RE = re.compile(r'\\firewallrules(?:\\\\|\|)(.+)$')
_EXTENSION_ID_RE = re.compile(r'(?<![a-z])([a-p]{32})(?![a-z])')
_EXTENSION_FOLDER_RE = re.compile(r'\\extensions\\([a-p]{32})$')
_TARGET_PREFIX_RE = re.compile(r'^(?:key|value|file|folder|registry(?:\s+key|\s+value)?)\s*:\s*')


_PATH_KEY_RE = re.compile(r'^(?:[a-z]:\\|\\\\)')

# --- Installed programs: Uninstall keys ------------------------------------
# FRST's / Spor's short form: "(HKLM\...\7-Zip) (Version: ..." in an Installed
# Programs line, or "HKLM-x32\...\X" / "HKU\<SID>\...\X" on its own (Spor's
# "key" detail). Subkey names can hold parens ("Firefox 128.0 (x64 en-US)").
_SHORT_UNINSTALL_RE = re.compile(
    r'(?:^|\()(?:HKLM(?:-x32)?|HKU\\S-1-[\d-]{1,80})\\\.\.\.\\(.{1,300}?)(?:\) \(Version:|$)',
    re.IGNORECASE,
)
# The full key in any hive spelling (HKLM, HKEY_LOCAL_MACHINE, "HKLM:", HKU\<SID>,
# WOW6432Node): Malwarebytes, AdwCleaner, Fixlog, MAU targets.
_FULL_UNINSTALL_RE = re.compile(
    r'\\microsoft\\windows\\currentversion\\uninstall\\([^\\"\'|\]\r\n]{1,300})', re.IGNORECASE,
)
_BRACED_GUID_RE = re.compile(r'^\{(' + _GUID + r')\}$', re.IGNORECASE)


def is_path_key(key):
    """True for a file path key, False for a typed one (`run:...`, ...)."""
    return bool(_PATH_KEY_RE.match(key or ''))


def software_keys(text):
    """`uninstall:<subkey>` (and `msi:<guid>` for an MSI product code) of the
    Uninstall key a text names: an Installed Programs line, a Spor "key"
    value, a registry target. The hive is left out like for the other typed
    keys; a wildcard ("Uninstall\\*") names no program."""
    text = (text or '').strip()
    if not text or ('\\...\\' not in text and 'uninstall\\' not in text.lower()):
        return set()
    names = [match.group(1) for match in _SHORT_UNINSTALL_RE.finditer(text)]
    names += [match.group(1) for match in _FULL_UNINSTALL_RE.finditer(text)]
    keys = set()
    for name in names:
        name = name.split(' => ', 1)[0].strip().rstrip('\\').strip()
        if not name or '*' in name:
            continue
        keys.add(f'uninstall:{name.lower()}')
        guid = _BRACED_GUID_RE.match(name)
        if guid:
            keys.add(f'msi:{guid.group(1).lower()}')
    return keys


# An Installed Programs line: "<name> (<hive>\...\<subkey>) (Version: <v> - <publisher>)[ Hidden]".
# The name can hold parens itself, so it ends where the hive starts.
_INSTALLED_PROGRAM_RE = re.compile(
    r'^(.{1,300}?) \((?:HKLM(?:-x32)?|HKU\\S-1-[\d-]{1,80})\\\.\.\.\\.{1,300}\) \(Version: ([^()]{0,100}?) - .{0,300}\)'
)
_SPACES_RE = re.compile(r'\s+')


def app_key(name):
    """`app:<display name>` of an installed program (lowercased, blanks
    collapsed), '' for none."""
    name = _SPACES_RE.sub(' ', (name or '').strip()).lower()
    return f'app:{name}' if name else ''


def installed_program(text):
    """(display name, version) of an Addition Installed Programs line, or None.
    The version is '' when FRST shows none."""
    match = _INSTALLED_PROGRAM_RE.match((text or '').strip())
    if not match:
        return None
    return match.group(1).strip(), match.group(2).strip()


def versions_differ(a, b):
    """True when two program versions are both known and not the same."""
    a, b = (a or '').strip().lower(), (b or '').strip().lower()
    return bool(a and b and a != '?' and b != '?' and a != b)


def msi_key(product_code):
    """`msi:<guid>` of an MSI product code ("{795F9101-...}"), '' if it is none."""
    match = _BRACED_GUID_RE.match((product_code or '').strip())
    return f'msi:{match.group(1).lower()}' if match else ''


def identity_key(kind, name):
    """The typed key of a persistence entry named by another log (Spor's
    PERSISTENCE: spor_log.persistence_identity): `run:<value>`, `svc:<name>`
    or `task:<path>`; '' for anything else."""
    name = (name or '').strip()
    if not name:
        return ''
    if kind == 'task':
        return task_key(name)
    if kind in ('run', 'svc'):
        return f'{kind}:{name.lower()}'
    return ''


def task_key(path):
    """`task:<path>` for a task path in any spelling ("\\Foo", "System32\\Tasks\\Foo")."""
    value = (path or '').strip().strip('"').lower().lstrip('\\')
    match = _TASK_FILE_RE.match(value)
    if match:
        value = match.group(1)
    value = value.strip('\\')
    return f'task:{value}' if value else ''


def target_keys(target, result=''):
    """The keys of a scanner detection's or a Fixlog result's target: its
    path, or the typed keys of a registry target, extension ID, ... `result`
    (a Fixlog's text after " => ") tells a bare service name apart."""
    text = (target or '').strip().strip('"').strip()
    text = _TARGET_PREFIX_RE.sub('', text).strip().strip('"')
    if not text:
        return set()
    keys = set()
    path = _as_path(text)
    if path:
        key = normalized_path(path)
        if key:
            keys.add(key)
            task = _TASK_FILE_RE.match(key)
            if task:
                keys.add(task_key(task.group(1)))
    lowered = text.lower()
    for pattern, prefix in (
        (_RUN_TARGET_RE, 'run'), (_SERVICE_TARGET_RE, 'svc'), (_CLSID_TARGET_RE, 'clsid'),
        (_TASK_ID_TARGET_RE, 'taskid'),
    ):
        match = pattern.search(lowered)
        if match:
            keys.add(f'{prefix}:{match.group(1).strip()}')
    match = _TASK_TREE_TARGET_RE.search(lowered)
    if match:
        keys.add(task_key(match.group(1)))
    match = _FIREWALL_TARGET_RE.search(lowered)
    if match:
        keys.add(f'fw:{match.group(1).strip()}')
    keys.update(software_keys(text))
    if path:
        # Only the extension's own folder: a Fixlog moving its files one by
        # one would otherwise fill an extension line with them.
        match = _EXTENSION_FOLDER_RE.search(lowered.rstrip('\\'))
        if match:
            keys.add(f'ext:{match.group(1)}')
    elif 'extension' in lowered or re.fullmatch(r'[a-p]{32}', lowered):
        keys.update(f'ext:{value}' for value in _EXTENSION_ID_RE.findall(lowered))
    if not keys and result and 'service' in result.lower() and re.fullmatch(r'[\w.\- ]{1,100}', text):
        # Fixlog: "<name> => service removed successfully".
        keys.add(f'svc:{lowered}')
    keys.discard('')
    return keys


# --- Analyzed lines -------------------------------------------------------
_TASK_GUID_LINE_RE = re.compile(r'^Task:\s*\{(' + _GUID + r')\}', re.IGNORECASE)
_CUSTOM_CLSID_LINE_RE = re.compile(r'CLSID\\\{(' + _GUID + r')\}', re.IGNORECASE)
_FIREWALL_NAME_RE = re.compile(r'^FirewallRules: \[([^\]]+)\]')
_FORCED_EXTENSION_RE = re.compile(r'^\w+ HK\w*(?:-x32)?\\.*\\Extension: \[([a-p]{32})\]')

# Paths in a command line: quoted ("C:\a b\x.ps1"), or bare up to a blank,
# quote, comma (rundll32 "x.dll,Entry") or separator. Environment variables
# FRST leaves unexpanded are mapped to the paths normalize_path produces.
_QUOTED_ARG_PATH_RE = re.compile(r'"((?:[A-Za-z]:\\|%[\w()]+%\\)[^"]+)"')
_BARE_ARG_PATH_RE = re.compile(r'(?:^|[\s=\'(])((?:[A-Za-z]:\\|%[\w()]+%\\)[^\s"\',;|<>]+)')
_HAS_EXTENSION_RE = re.compile(r'\.[A-Za-z0-9]{1,5}$')
_ENV_PATHS = {
    'appdata': r'C:\Users\username\AppData\Roaming',
    'localappdata': r'C:\Users\username\AppData\Local',
    'temp': r'C:\Users\username\AppData\Local\Temp',
    'tmp': r'C:\Users\username\AppData\Local\Temp',
    'userprofile': r'C:\Users\username',
    'public': r'C:\Users\Public',
    'programdata': r'C:\ProgramData',
    'allusersprofile': r'C:\ProgramData',
    'systemroot': r'C:\Windows',
    'windir': r'C:\Windows',
    'programfiles': r'C:\Program Files',
    'programfiles(x86)': r'C:\Program Files (x86)',
    'systemdrive': 'C:',
}
_ENV_RE = re.compile(r'^%([\w()]+)%')


def _expand(path):
    match = _ENV_RE.match(path)
    if not match:
        return path
    base = _ENV_PATHS.get(match.group(1).lower())
    return base + path[match.end():] if base else ''


def argument_paths(text):
    """The normalized keys of the files a command line names (files only: a
    path must end in an extension)."""
    keys = []
    if not text or (':\\' not in text and '%\\' not in text):
        return keys
    found = _QUOTED_ARG_PATH_RE.findall(text)
    unquoted = _QUOTED_ARG_PATH_RE.sub(' ', text)
    found += _BARE_ARG_PATH_RE.findall(unquoted)
    for raw in found:
        path = _expand(raw.strip().rstrip('.)'))
        if not path or not _HAS_EXTENSION_RE.search(path):
            continue
        key = normalized_path(path)
        if key and key not in keys:
            keys.append(key)
    return keys


def line_main_path(text, components=None):
    """The normalized key of the file an FRST / Addition line names, or ''.
    The analyzer's parsed filepath when given, else the line parsed again
    (a Defender exclusion "<registry key>|<path>" included)."""
    components = components if isinstance(components, dict) else {}
    path = components.get('filepath') or ''
    text = text or ''
    if not path and ':\\' in text:
        try:
            path = ex.extract_any_frst_path(text) or ''
        except Exception:
            path = ''
        if not path and '|' in text:
            path = _as_path(text.rsplit('|', 1)[1])
    return normalized_path(path)


def line_path_keys(text, components=None, arguments=None):
    """The line's own file first, then the files in its command line."""
    keys = []
    main = line_main_path(text, components)
    if main:
        keys.append(main)
    if arguments is None:
        components = components if isinstance(components, dict) else {}
        arguments = components.get('arguments')
        if arguments is None:
            try:
                entry = ex.get_frst_entry(text or '')
            except Exception:
                entry = None
            arguments = entry.arguments if entry is not None else ''
    for key in argument_paths(arguments or ''):
        if key not in keys:
            keys.append(key)
    return keys


def line_keys(line):
    """[(key, match)] of one analyzed line (an analysis payload entry)."""
    raw = line.get('line') or ''
    text = raw.strip()
    if not text:
        return []
    components = line.get('components') if isinstance(line.get('components'), dict) else {}
    entry_type = line.get('parsed_entry_type') or ''
    result = []
    main = line_main_path(raw, components)
    if main:
        result.append((main, MATCH_PATH))
    for key in argument_paths(components.get('arguments') or ''):
        if key != main:
            result.append((key, MATCH_ARGUMENT))

    name = (components.get('name') or '').strip()
    typed = set()
    if entry_type == 'runkey' and name:
        typed.add(f'run:{name.lower()}')
    elif entry_type == 'service' and name:
        typed.add(f'svc:{name.lower()}')
    elif entry_type in ('scheduled_task', 'scheduled_task_command'):
        if name:
            typed.add(task_key(name))
        match = _TASK_GUID_LINE_RE.match(text)
        if match:
            typed.add(f'taskid:{match.group(1).lower()}')
    elif entry_type == 'firewall':
        match = _FIREWALL_NAME_RE.match(text)
        if match:
            typed.add(f'fw:{match.group(1).strip().lower()}')
    clsid = (components.get('clsid') or '').strip().strip('{}').lower()
    if clsid and re.fullmatch(_GUID, clsid):
        typed.add(f'clsid:{clsid}')
    elif text.startswith('CustomCLSID:'):
        match = _CUSTOM_CLSID_LINE_RE.search(text)
        if match:
            typed.add(f'clsid:{match.group(1).lower()}')
    if entry_type == 'browser_extension' or ' Extension: ' in text[:60]:
        forced = _FORCED_EXTENSION_RE.match(text)
        ids = [forced.group(1)] if forced else _EXTENSION_ID_RE.findall(text.lower())
        typed.update(f'ext:{value}' for value in ids)
    # An Installed Programs line (found by its text: cached payloads may lack
    # the entry type).
    typed.update(software_keys(text))
    program = installed_program(text)
    if program:
        typed.add(app_key(program[0]))
    typed.discard('')
    # The name of a program is the weakest key: an entry found through its
    # Uninstall key or MSI product code too says so.
    for key in sorted(typed, key=lambda key: (key.startswith('app:'), key)):
        result.append((key, TYPED_MATCHES[key.split(':', 1)[0]]))
    return result
