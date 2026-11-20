"""Windows Defender events in Fixlogs (a fixlist's Get-WinEvent output) and
in an Addition log's "Windows Defender:" section: the files they name."""

import re

from ..correlation_keys import argument_paths, is_host_program
from ..file_hashes import _as_path, normalized_path


# Windows Defender events in a Fixlog: a fixlist's PowerShell
# "Get-WinEvent ... Windows Defender/Operational" printed as Format-List
# blocks ("Time : ...", "Threat : ...", "Path : ...", "Action : ...").
# PowerShell wraps long values at a fixed width, even mid-word; the
# continuation lines are indented to the value column.
_DEFENDER_FIELD_RE = re.compile(r'^([A-Za-z][A-Za-z ]*?)\s*:\s?(.*)$')
_DEFENDER_VALUE_COLUMN = len('Path     : ')
# Path entries that name a file on disk ("webfile:_<path>|<url>|...",
# "file:_<archive>-><member>"); process:, behavior:, amsi:, regkey:, ... do not.
_DEFENDER_FILE_ENTRY_RE = re.compile(r'^(?:file|containerfile|webfile):_(.+)$', re.IGNORECASE)


def _defender_events(lines):
    """[(fields {key: value}, {key: line_no})] for every block that starts with "Time :"."""
    events = []
    current = None
    last_key = None
    for index, raw in enumerate(lines):
        line = raw[:-1] if raw.endswith('\r') else raw
        if not line.strip():
            current, last_key = None, None
            continue
        if line[:1] in (' ', '\t'):
            # A wrapped value: glued back on without its indent (trailing
            # spaces of the line before are part of the value).
            if current is not None and last_key is not None:
                indent = line[:_DEFENDER_VALUE_COLUMN]
                rest = line[_DEFENDER_VALUE_COLUMN:] if not indent.strip() else line.lstrip()
                current[0][last_key] += rest
            continue
        match = _DEFENDER_FIELD_RE.match(line)
        if not match:
            current, last_key = None, None
            continue
        key = match.group(1).strip().lower()
        if key == 'time':
            current = ({}, {})
            events.append(current)
        if current is None:
            continue
        current[0][key] = match.group(2)
        current[1][key] = index + 1
        last_key = key
    return events


def iter_defender_detections(content):
    """(line_no of the Threat line, threat, action, path) for every file a
    Defender event in the text names. One per (path, threat): the detection
    (1116, action "Not Applicable") and the action taken (1117) repeat each
    other; an event with a real action wins, whatever the order (Get-WinEvent
    lists the newest first)."""
    found = {}
    for fields, line_nos in _defender_events((content or '').split('\n')):
        threat = (fields.get('threat') or '').strip()
        if not threat or 'path' not in fields:
            continue
        action = (fields.get('action') or '').strip()
        for entry in fields['path'].split(';'):
            match = _DEFENDER_FILE_ENTRY_RE.match(entry.strip())
            if not match:
                continue
            path = _as_path(match.group(1).split('|', 1)[0].split('->', 1)[0].strip())
            key = normalized_path(path)
            if not key:
                continue
            slot = (key, threat.lower())
            known = found.get(slot)
            if known is not None and (not _defender_real_action(action) or _defender_real_action(known[2])):
                continue
            found[slot] = (line_nos.get('threat', line_nos.get('time', 0)), threat, action, path)
    return list(found.values())


def _defender_real_action(action):
    return bool(action) and action.strip().lower() not in ('not applicable', 'n/a', 'none')


# Windows Defender events in an Addition log ("Windows Defender:" section):
# blocks start with "TimeCreated : <date>"; "Name: <threat>", "Path: <entries>"
# and, for an action taken, "Action: <action>". Long values wrap at a fixed
# width without an indent, even mid-word, so continuation lines are glued back
# on as they are, up to the next known field.
_ADDITION_DEFENDER_HEADER = 'Windows Defender:'
_ADDITION_DEFENDER_FIELDS = frozenset({
    'timecreated', 'message', 'name', 'id', 'severity', 'category', 'path', 'detection origin',
    'detection type', 'detection source', 'user', 'process name', 'security intelligence version',
    'engine version', 'action', 'action status', 'error code', 'error description', 'remediation user',
    'status', 'scan id', 'scan type', 'scan parameters', 'stop reason',
})
_ADDITION_FIELD_RE = re.compile(r'^([A-Za-z][A-Za-z ]{0,40}?)\s*:\s?(.*)$')
# The section ends at the next banner: a "==== ... ====" line, or the "===="
# underline of the next "Xyz:" header (whose line is then glued onto nothing:
# it follows a blank line).
_ADDITION_SECTION_END_RE = re.compile(r'^={5,}')
_DEFENDER_CMDLINE_RE = re.compile(r'^cmdline:_(.+)$', re.IGNORECASE)
def _cmdline_target(command_line):
    """The file a Defender "CmdLine:_" detection is about: the first path in
    the command line that is not a host program or a Windows binary, else ''."""
    for key in argument_paths(command_line):
        if not is_host_program(key):
            return key
    return ''


def _addition_defender_events(content):
    """[(fields, line numbers)] for the event blocks of an Addition log's
    "Windows Defender:" section; [] when there is none."""
    if content.startswith(_ADDITION_DEFENDER_HEADER):
        start = 0
    else:
        start = content.find('\n' + _ADDITION_DEFENDER_HEADER)
        if start < 0:
            return []
        start += 1
    # Line numbers count content.split('\n') from 1, like the log page.
    first_line_no = content.count('\n', 0, start) + 1
    # Only the section: it ends at the next "=====" line after its own underline.
    underline_end = content.find('\n', content.find('\n', start) + 1)
    end = content.find('\n=====', underline_end) if underline_end >= 0 else -1
    lines = content[start:end if end >= 0 else len(content)].split('\n')
    events = []
    current = None
    last_key = None
    # lines[0] is the header, lines[1] its "====" underline.
    for offset in range(2, len(lines)):
        raw = lines[offset]
        line = raw[:-1] if raw.endswith('\r') else raw
        if _ADDITION_SECTION_END_RE.match(line):
            break
        match = _ADDITION_FIELD_RE.match(line)
        key = match.group(1).strip().lower() if match else ''
        if key in _ADDITION_DEFENDER_FIELDS:
            if key == 'timecreated':
                current = ({}, {})
                events.append(current)
            if current is not None:
                # Pieces, joined below: wrapped values can run for many lines.
                current[0][key] = [match.group(2)]
                current[1][key] = first_line_no + offset
                last_key = key
            continue
        if not line.strip():
            last_key = None
            continue
        if current is not None and last_key in ('path', 'name', 'action'):
            current[0][last_key].append(line)
    return [({key: ''.join(pieces) for key, pieces in fields.items()}, line_nos) for fields, line_nos in events]


def iter_addition_defender_detections(content):
    """(line_no of the Name line, threat, action, path) for every file a
    Defender event of an Addition log names, one per (path, threat); an event
    with a real action wins. A "CmdLine:_" entry names the program it ran."""
    content = content or ''
    if _ADDITION_DEFENDER_HEADER not in content:
        return []
    found = {}
    for fields, line_nos in _addition_defender_events(content):
        threat = (fields.get('name') or '').strip()
        if not threat or 'path' not in fields:
            continue
        action = (fields.get('action') or '').strip()
        for item in fields['path'].split(';'):
            item = item.strip()
            match = _DEFENDER_FILE_ENTRY_RE.match(item)
            if match:
                path = _as_path(match.group(1).split('|', 1)[0].split('->', 1)[0].strip())
            else:
                cmdline = _DEFENDER_CMDLINE_RE.match(item)
                path = _cmdline_target(cmdline.group(1)) if cmdline else ''
            key = normalized_path(path)
            if not key:
                continue
            slot = (key, threat.lower())
            known = found.get(slot)
            if known is not None and (not _defender_real_action(action) or _defender_real_action(known[2])):
                continue
            found[slot] = (line_nos.get('name', line_nos.get('timecreated', 0)), threat, action, path)
    return list(found.values())
