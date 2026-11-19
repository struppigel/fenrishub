"""Parsing of Spor logs (forensic triage: execution evidence, persistence,
Defender, file hashes). Pure functions, no app imports.

The format, from Spor's README ("Log format (for parsers)"):

- "==================== TITLE - description ====...": a section;
  "--- title ---": a sub-section; "(...)": a comment.
- an item line: "[time] [tags] item [=> target] [ [status]] [=> | , details; ...]
  [<==== !flag !flag]", each part left out when empty. The time is the first
  19 characters when the line starts with a digit; "<==== " splits off the
  flags; the first " => " splits the item from the rest. Paths cannot
  contain "<". They can contain " => " and text like "[gone]": such paths get
  the flag !log-syntax-in-name, and their line is only trusted when the path
  is one the FILES section lists (resolve_item_path).
- "    key: value": belongs to the item above ("path:", "loaded:", "from:", ...).
- FILES: "path => <hash>, signature valid; signer X; ...; amcache sha1 S"
  ("not hashed" instead of the hash when hashing was off).

Lines are `content.split('\\n')` with a trailing CR removed; line numbers
count from 1 like the log page's L<no> ids.
"""

import re
from dataclasses import dataclass, field

SECTION_PREFIX = '=' * 20 + ' '

SECTION_SUMMARY = 'SUMMARY'
SECTION_TIMELINE = 'TIMELINE'
SECTION_DEFENDER = 'DEFENDER'
SECTION_SOFTWARE = 'SOFTWARE'
SECTION_PERSISTENCE = 'PERSISTENCE'
SECTION_FILES = 'FILES'
SECTION_AMCACHE_FILES = 'AMCACHE FILES'
SECTION_LEGEND = 'LEGEND'
# Sections read by their own functions, not as mentions (iter_mentions).
_NOT_MENTION_SECTIONS = frozenset({
    SECTION_SUMMARY, SECTION_TIMELINE, SECTION_FILES, SECTION_AMCACHE_FILES, SECTION_LEGEND,
})

STATUS_WORDS = (
    'gone', 'no access', 'unsigned', 'invalid signature', 'revoked signature', 'expired signature',
    'volume not mounted',
)
BAD_SIGNATURE_STATUSES = frozenset({'invalid signature', 'revoked signature', 'expired signature'})
BAD_SIGNATURES = frozenset({'invalid', 'revoked', 'expired'})
# Flags that are normal on many PCs: no warning by themselves.
QUIET_FLAGS = frozenset({'!lolbin'})
# A path made to look like log text (" => ", "[gone]"): its line cannot be split as usual.
SYNTAX_FLAG = '!log-syntax-in-name'
# SUMMARY lines that write their flags between double blanks, without "<====":
# "[Prefetch] C:\...\x.pdf.lnk  !double-extension  (loaded by C:\...\host.exe)".
INLINE_FLAG_RE = re.compile(r'(?<=  )(![a-zA-Z][a-zA-Z0-9-]{1,40})(?=  |\s*$)')

# " [status]" (also "[> 600 MB, not hashed]"), anywhere in a line.
STATUS_RE = re.compile(
    r' \[(' + '|'.join(re.escape(word) for word in STATUS_WORDS) + r'|> \d{1,9} MB, not hashed)\]'
)
_TIME_RE = re.compile(r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?= |$)')
_TAGS_RE = re.compile(r'^\[([^\[\]\r\n]{1,80})\](?: |$)')
FLAGS_MARK = ' <==== '
_PATH_START_RE = re.compile(r'^(?:[A-Za-z]:\\|\\\\)')
_SUB_LINE_RE = re.compile(r'^( {2,}|\t+)([a-z][a-z0-9 ]{0,30}):(?: (.*)|)$')
# FILES: " => <hash>" or " => not hashed", the last one on the line (a path may contain " => ").
_FILES_VALUE_RE = re.compile(r' => ([0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32}|not hashed)(?=,|;|$)')
_HASH_VALUE_RE = re.compile(r'^(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})$')
# The labelled parts of a FILES line, longest first ("file version" before "version").
FILES_DETAIL_NAMES = (
    'original name', 'amcache sha1', 'file version', 'description', 'thumbprint', 'signature', 'modified',
    'product', 'company', 'created', 'signer', 'note', 'size', 'md5',
)
_DEFENDER_RE = re.compile(r'^Defender (detected|action taken): (.{1,300})$')
# Defender path entries that name a file ("file:_<path>", "webfile:_<path>|<url>|...").
_DEFENDER_FILE_PREFIX_RE = re.compile(r'^(?:file|containerfile|webfile):_', re.IGNORECASE)
# Where a path ends inside the rest of a line: its status, a detail, the next
# part, or the " (svchost DLL)" note of a service hosted by svchost.exe.
SVCHOST_DLL_NOTE = ' (svchost DLL)'
_PATH_END_RE = re.compile(r' \[| => |, |; | \(svchost DLL\)|$')
# SOFTWARE Uninstall entries: "...; folder C:\...\" (the install folder).
_SOFTWARE_FOLDER_RE = re.compile(r'(?:^|; )folder ([^;]{1,400})')
# Sub-lines whose value is a file or folder of its own.
_PATH_SUB_KEYS = frozenset({'loaded', 'path', 'target', 'entry', 'files', 'dll'})
MAX_EXTRA = 6


@dataclass
class SporItem:
    time: str = ''
    tags: str = ''
    item: str = ''      # before the first " => ", without its status
    status: str = ''    # the status word of the item (or, without one, of the target)
    rest: str = ''      # after the first " => " (target and / or details)
    flags: list = field(default_factory=list)
    text: str = ''      # everything after the time and tags, without the flags
    # A !log-syntax-in-name line: `resolved` when its path was found in FILES
    # (then item / status / rest are split behind that path); else the split
    # is the naive one and must not be trusted.
    untrusted: bool = False
    resolved: bool = False

    @property
    def loud_flags(self):
        return [flag for flag in self.flags if flag not in QUIET_FLAGS]

    @property
    def trusted(self):
        return not self.untrusted or self.resolved


def is_path(text):
    return bool(_PATH_START_RE.match(text or ''))


def section_title(body):
    """'TIMELINE' for "==== TIMELINE - last 30 days ... ====", '' for other lines.
    The log's own title banner gives "Spor 0.1.0", the last one "End of log. ..."."""
    if not body.startswith(SECTION_PREFIX):
        return ''
    text = body.strip().strip('=').strip()
    if not text:
        return ''
    return text.split(' - ', 1)[0].strip()


def iter_sections(lines):
    """(title, first line index, end index) per section, the banner at the first index."""
    found = []
    for index, raw in enumerate(lines):
        title = section_title(_body(raw))
        if title:
            found.append((title, index))
    for number, (title, start) in enumerate(found):
        end = found[number + 1][1] if number + 1 < len(found) else len(lines)
        yield title, start, end


def section_ranges(lines):
    """{title: (start, end)}: the first section of each title."""
    ranges = {}
    for title, start, end in iter_sections(lines):
        ranges.setdefault(title, (start, end))
    return ranges


def resolve_item_path(text, known):
    """The longest path of `known` ({lowercased path: path}) that `text`
    starts with (case-insensitive), as `text` writes it; '' if none."""
    lower = text.lower()
    best = ''
    for key in known:
        if len(key) > len(best) and lower.startswith(key):
            rest = lower[len(key):]
            # The path must end there: its status, " => ", the details or the line's end.
            if not rest or rest.startswith((' [', ' => ', ', ', '; ')):
                best = key
    return text[:len(best)]


def split_item(body, known=None):
    """The parts of an item line (see the module docstring). `known`
    ({lowercased path: path}, known_paths) resolves !log-syntax-in-name lines."""
    item = SporItem()
    text = body.rstrip()
    m = _TIME_RE.match(text)
    if m:
        item.time = m.group(0)
        text = text[m.end():].lstrip(' ')
    cut = text.find(FLAGS_MARK)
    if cut != -1:
        item.flags = text[cut + len(FLAGS_MARK):].split()
        text = text[:cut]
    elif text.startswith(FLAGS_MARK.lstrip()):
        item.flags = text[len(FLAGS_MARK.lstrip()):].split()
        text = ''
    m = _TAGS_RE.match(text)
    if m:
        item.tags = m.group(1)
        text = text[m.end():]
    item.text = text
    if SYNTAX_FLAG in item.flags:
        item.untrusted = True
        path = resolve_item_path(text, known) if known else ''
        if path:
            item.resolved = True
            item.item = path
            remainder = text[len(path):]
            m = STATUS_RE.match(remainder)
            if m:
                item.status = m.group(1)
                remainder = remainder[m.end():]
            if remainder.startswith(' => '):
                item.rest = remainder[4:]
            elif remainder.startswith((', ', '; ')):
                item.rest = remainder[2:]
            return item
    head, sep, rest = text.partition(' => ')
    item.rest = rest if sep else ''
    m = STATUS_RE.search(head)
    if m and not head[m.end():].strip():
        item.status = m.group(1)
        head = head[:m.start()]
    else:
        m = STATUS_RE.search(item.rest)
        if m:
            item.status = m.group(1)
    item.item = head.strip()
    return item


def _body(raw):
    return raw[:-1] if raw.endswith('\r') else raw


def _is_item_line(body):
    stripped = body.strip()
    return bool(stripped) and not body[:1].isspace() and not stripped.startswith(('(', '---', '='))


def _sub_line(body):
    """(key, value) of an indented "key: value" line, else None."""
    m = _SUB_LINE_RE.match(body)
    return (m.group(2), m.group(3) or '') if m else None


def _subsection_title(stripped):
    return stripped.strip('-').strip()


# ---------------------------------------------------------------------------
# FILES and AMCACHE FILES
# ---------------------------------------------------------------------------

@dataclass
class FileLine:
    line_no: int
    path: str
    hash: str = ''          # as written (SHA256 by default; MD5 or SHA1 with -algo), '' when not hashed
    status: str = ''        # "no access", "> 600 MB, not hashed", ...
    details: dict = field(default_factory=dict)  # FILES_DETAIL_NAMES -> value

    @property
    def signature(self):
        """valid / invalid / revoked / expired / unsigned, or ''."""
        return (self.details.get('signature') or '').split(' ', 1)[0]


def parse_labelled(rest, names):
    """({name: value}, [unlabelled parts]) of "; "-separated details, where a
    labelled part is "<name> <value>" (`names` longest first, so "file
    version" wins over "version")."""
    details = {}
    unlabelled = []
    for part in rest.split('; '):
        part = part.strip().lstrip(',').strip()
        if not part:
            continue
        for name in names:
            if part == name or part.startswith(name + ' '):
                details.setdefault(name, part[len(name) + 1:].strip()[:300])
                break
        else:
            unlabelled.append(part[:300])
    return details, unlabelled


def _parse_files_details(rest):
    return parse_labelled(rest, FILES_DETAIL_NAMES)[0]


def _parse_files_line(index, body):
    cut = body.find(FLAGS_MARK)
    if cut != -1:
        body = body[:cut]
    last = None
    for last in _FILES_VALUE_RE.finditer(body):
        pass
    if last is not None:
        head, value, rest = body[:last.start()], last.group(1), body[last.end():]
        if value == 'not hashed':
            value = ''
    else:
        head, _sep, rest = body.partition(' => ')
        value = ''
    status = ''
    m = STATUS_RE.search(head)
    if m and not head[m.end():].strip():
        status = m.group(1)
        head = head[:m.start()]
    path = head.strip()
    if not is_path(path):
        return None
    return FileLine(index + 1, path, value, status, _parse_files_details(rest))


def iter_file_lines(lines):
    """A FileLine per line of the FILES section."""
    ranges = section_ranges(lines)
    if SECTION_FILES not in ranges:
        return
    start, end = ranges[SECTION_FILES]
    for index in range(start + 1, end):
        body = _body(lines[index])
        if _is_item_line(body):
            parsed = _parse_files_line(index, body)
            if parsed is not None:
                yield parsed


def iter_files(lines):
    """(line_no, path, hash, signature) of the FILES section's lines. `hash`
    is as the log writes it (SHA256 by default; MD5 or SHA1 with -algo), ''
    for a file that was not hashed; `signature` is valid / invalid / revoked
    / expired / unsigned, or ''."""
    for parsed in iter_file_lines(lines):
        yield parsed.line_no, parsed.path, parsed.hash if _HASH_VALUE_RE.match(parsed.hash) else '', parsed.signature


def iter_amcache_files(lines):
    """(line_no, path, sha1) of the AMCACHE FILES section: the file when
    Windows recorded it."""
    ranges = section_ranges(lines)
    if SECTION_AMCACHE_FILES not in ranges:
        return
    start, end = ranges[SECTION_AMCACHE_FILES]
    for index in range(start + 1, end):
        body = _body(lines[index])
        if not _is_item_line(body):
            continue
        head, sep, value = body.rpartition(' => ')
        value = value.strip()
        if sep and is_path(head.strip()) and re.match(r'^[0-9A-Fa-f]{40}$', value):
            yield index + 1, head.strip(), value


def known_paths(lines):
    """{lowercased path: path} of the files FILES lists: the paths a
    !log-syntax-in-name line can be resolved against."""
    return {parsed.path.lower(): parsed.path for parsed in iter_file_lines(lines)}


# ---------------------------------------------------------------------------
# Defender
# ---------------------------------------------------------------------------

def _defender_path(entry):
    entry = _DEFENDER_FILE_PREFIX_RE.sub('', entry.strip(), count=1)
    path = entry.split('|', 1)[0].split('->', 1)[0].strip().strip('"')
    return path if is_path(path) else ''


def iter_defender_detections(lines):
    """(line_no, threat, action, path) for every file the DEFENDER section's
    "Defender detected:" / "Defender action taken:" lines name, one per
    (path, threat): a line with a real action wins over the detection."""
    ranges = section_ranges(lines)
    if SECTION_DEFENDER not in ranges:
        return []
    start, end = ranges[SECTION_DEFENDER]
    found = {}
    for index in range(start + 1, end):
        body = _body(lines[index])
        if 'Defender ' not in body or not _is_item_line(body):
            continue
        item = split_item(body)
        m = _DEFENDER_RE.match(item.item)
        if not m:
            continue
        threat = m.group(2).strip()
        action = ''
        paths = []
        for part in item.rest.split('; '):
            part = part.strip()
            if part.startswith('action '):
                action = part[len('action '):].strip()
            elif part.startswith('process '):
                continue
            else:
                path = _defender_path(part)
                if path:
                    paths.append(path)
        for path in paths:
            slot = (path.lower(), threat.lower())
            known = found.get(slot)
            if known is not None and (not action or known[2]):
                continue
            found[slot] = (index + 1, threat, action, path)
    return list(found.values())


# ---------------------------------------------------------------------------
# TIMELINE
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    line_no: int
    path: str
    time: str
    sources: str
    file_status: str
    details: str
    flags: list


def iter_timeline_evidence(lines, known=None):
    """Evidence per file of the TIMELINE section: what was seen (runs,
    creation, download, ...) by which sources, and when. A merged line
    ("path:" sub-lines, one per real path) gives each path its own entry,
    with its own time and status. One entry per path (case-insensitive).
    A !log-syntax-in-name line counts only when its path is in FILES."""
    ranges = section_ranges(lines)
    if SECTION_TIMELINE not in ranges:
        return []
    if known is None:
        known = known_paths(lines)
    start, end = ranges[SECTION_TIMELINE]
    out = []
    seen = set()
    parent = None

    def add(line_no, path, time, file_status, details, flags):
        key = path.lower()
        if key in seen:
            return
        seen.add(key)
        out.append(Evidence(line_no, path, time, parent.tags, file_status, details.strip()[:300], flags))

    for index in range(start + 1, end):
        body = _body(lines[index])
        sub = _sub_line(body)
        if sub is not None:
            key, value = sub
            if key != 'path' or parent is None:
                continue
            item = split_item(value, known)
            if not item.trusted or not is_path(item.item):
                continue
            time = item.rest[:19] if _TIME_RE.match(item.rest) else parent.time
            add(index + 1, item.item, time, item.status, parent.rest, item.flags or parent.flags)
            continue
        if not _is_item_line(body):
            parent = None
            continue
        parent = split_item(body, known)
        if parent.tags and parent.trusted and is_path(parent.item):
            add(index + 1, parent.item, parent.time, parent.status, parent.rest, parent.flags)
    return out


# ---------------------------------------------------------------------------
# Mentions: every other place a module section names a file or folder
# ---------------------------------------------------------------------------

@dataclass
class Mention:
    line_no: int
    path: str
    section: str
    subsection: str = ''
    time: str = ''
    tags: str = ''
    text: str = ''          # the whole line (stripped, at most 300 characters)
    role: str = 'item'      # item / target / loaded / path / entry / files / ...
    parent: str = ''        # the item a sub-line belongs to ("loaded by" this program)
    status: str = ''
    flags: list = field(default_factory=list)
    extra: list = field(default_factory=list)   # [[key, value]] of the item's other sub-lines
    folder: bool = False    # speaks for everything inside (a Defender path exclusion)
    # (kind, name) of a PERSISTENCE entry (persistence_identity), on the first
    # mention of its line only.
    identity: tuple = ()


def _path_at(text):
    """The path `text` starts with, up to its status, " => " or the next part."""
    if not is_path(text):
        return ''
    return text[:_PATH_END_RE.search(text).start()].strip()


def _status_after(text, path):
    if not text.startswith(path):
        return ''
    position = len(path)
    if text.startswith(SVCHOST_DLL_NOTE, position):
        position += len(SVCHOST_DLL_NOTE)
    m = STATUS_RE.match(text, position)
    return m.group(1) if m else ''


# PERSISTENCE: the entry's kind is its first tag ("[run]", "[service]", ...),
# never the sub-section title. Run values are named by their "value" detail
# (a value name can hold backslashes: it is not cut from the key), services,
# drivers and tasks by the item.
PERSISTENCE_KINDS = {
    'run': 'run', 'runonce': 'run', 'policy-run': 'run', 'service': 'svc', 'driver': 'svc', 'task': 'task',
}
# Further tags after the kind ("[task] [106] \Path" of a Task Scheduler event).
_MORE_TAGS_RE = re.compile(r'^(?:\[[^\[\]\r\n]{1,80}\] ){1,5}')
_VALUE_MARKS = ('; value ', ', value ')


def persistence_identity(item):
    """(kind, name) of a PERSISTENCE item line (a SporItem): kind `run`,
    `svc` or `task`; None for other kinds (startup, wmi) or without a name."""
    tags = item.tags.split()
    kind = PERSISTENCE_KINDS.get(tags[0].lower()) if tags else None
    if not kind or not item.trusted:
        return None
    if kind == 'run':
        # "value" is the last detail; the program's arguments come before it.
        rest = item.rest
        if rest.startswith('value '):
            name = rest[len('value '):]
        else:
            cut = max(rest.rfind(mark) for mark in _VALUE_MARKS)
            name = rest[cut + len('; value '):] if cut != -1 else ''
    else:
        name = _MORE_TAGS_RE.sub('', item.item, count=1)
    name = name.strip()
    if not name or name == '-':
        return None
    return kind, name[:300]


def _outside_folder(program, rest):
    """SOFTWARE: the program an Uninstall entry shows lies outside its install
    folder (a Steam game pointing at steam.exe, a shared uninstaller)."""
    m = _SOFTWARE_FOLDER_RE.search(rest)
    if not m:
        return False
    folder = m.group(1).strip().rstrip('\\').lower()
    return bool(folder) and not program.lower().startswith(folder + '\\')


def iter_mentions(lines, known=None):
    """A Mention per file or folder a module section names (PREFETCH,
    PERSISTENCE, SOFTWARE, NETWORK, DOWNLOADS, DEFENDER exclusions, ...):
    the item, the target it points at, and paths of its sub-lines ("loaded:",
    "path:", "target:"). The item's other sub-lines ("from:", "page:",
    "info:") are its `extra`. New modules need no code."""
    if known is None:
        known = known_paths(lines)
    out = []
    for title, start, end in iter_sections(lines):
        if title in _NOT_MENTION_SECTIONS or title.startswith(('Spor', 'End of log')):
            continue
        subsection = ''
        current = []   # the mentions of the item line above (its sub-lines add to them)
        parent = None  # the item line above
        for index in range(start + 1, end):
            body = _body(lines[index])
            stripped = body.strip()
            if not stripped:
                current, parent = [], None
                continue
            if stripped.startswith('---') and stripped.endswith('---'):
                subsection = _subsection_title(stripped)
                current, parent = [], None
                continue
            if stripped.startswith('('):
                continue
            sub = _sub_line(body)
            if sub is not None:
                key, value = sub
                item = split_item(value, known) if key in _PATH_SUB_KEYS else None
                if (key == 'dll' and item is not None
                        and any(mention.path.lower() == item.item.lower() for mention in current)):
                    continue   # a registry line's target already is the DLL
                if item is not None and item.trusted and is_path(item.item):
                    out.append(Mention(
                        index + 1, item.item, title, subsection, item.time or (parent.time if parent else ''),
                        parent.tags if parent else '', stripped[:300], key,
                        parent.item[:200] if parent else '', item.status, item.flags,
                    ))
                elif current and value:
                    for mention in current:
                        if len(mention.extra) < MAX_EXTRA:
                            mention.extra.append([key, value.strip()[:200]])
                continue
            if body[:1].isspace() or not _is_item_line(body):
                continue
            item = split_item(body, known)
            current = []
            parent = item
            if not item.trusted or _DEFENDER_RE.match(item.item):
                continue   # Defender detections are read by iter_defender_detections
            common = dict(section=title, subsection=subsection, time=item.time, tags=item.tags,
                          text=stripped[:300], flags=item.flags)
            if is_path(item.item):
                folder = title == SECTION_DEFENDER and item.tags == 'Paths' and 'exclusion' in subsection.lower()
                current.append(Mention(index + 1, item.item, role='item', status=item.status, folder=folder,
                                       **common))
            target = _path_at(item.rest)
            if target and not (title == SECTION_SOFTWARE and _outside_folder(target, item.rest)):
                current.append(Mention(index + 1, target, role='target', status=_status_after(item.rest, target),
                                       **common))
            identity = persistence_identity(item) if title == SECTION_PERSISTENCE else None
            if identity:
                # The entry stands for its line under its name too (a Run
                # value whose program differs or is gone, a service, a task).
                if current:
                    current[0].identity = identity
                else:
                    current.append(Mention(index + 1, '', role='entry', status=item.status, identity=identity,
                                           **common))
            out.extend(current)
    return out


# ---------------------------------------------------------------------------
# SOFTWARE: installed programs, Windows Installer events, Store / MSIX apps
# ---------------------------------------------------------------------------

# Labelled details of the SOFTWARE lines, longest first.
SOFTWARE_LABELS = (
    'install date', 'product code', 'full trust', 'publisher', 'version', 'folder', 'hidden', 'source',
    'signer', 'times', 'first', 'from', 'name', 'key',
)
SOFTWARE_EVENTS = {'1033': 'installed', '1034': 'removed', '11708': 'install failed'}


@dataclass
class SoftwareFact:
    line_no: int
    kind: str               # uninstall / installer / package
    name: str               # display name (or the package full name)
    subsection: str = ''
    time: str = ''
    tags: str = ''
    status: str = ''
    flags: list = field(default_factory=list)
    text: str = ''
    details: dict = field(default_factory=dict)   # SOFTWARE_LABELS, plus program / user / event / display name


def _software_kind(subsection):
    lower = subsection.lower()
    if lower.startswith('installed programs'):
        return 'uninstall'
    if lower.startswith('windows installer'):
        return 'installer'
    if lower.startswith('store and msix'):
        return 'package'
    return ''


def _split_program(rest):
    """An Uninstall line's rest: (program, its status, details). The program
    (a path, or "Windows Installer (msiexec)") ends at the ", " in front of
    the first labelled detail; an entry without one starts with a detail."""
    if rest.startswith(tuple(label + ' ' for label in SOFTWARE_LABELS)):
        return '', '', rest
    cut = -1
    for label in SOFTWARE_LABELS:
        position = rest.find(', ' + label + ' ')
        if position != -1 and (cut == -1 or position < cut):
            cut = position
    program, details = (rest[:cut], rest[cut + 2:]) if cut != -1 else (rest, '')
    status = ''
    m = STATUS_RE.search(program)
    if m and not program[m.end():].strip():
        status = m.group(1)
        program = program[:m.start()]
    return program.strip(), status, details


def iter_software(lines):
    """A SoftwareFact per line of the SOFTWARE section's sub-sections:
    installed programs (Uninstall keys, with "key HKLM\\...\\X" in FRST's
    form), Windows Installer events (1033 / 1034 / 11708, with "product
    code {GUID}") and Store / MSIX operations (with the package "folder").
    The "key:" sub-lines of a collapsed group ("27 entries from ...") are
    facts too. TIMELINE's [INS] lines repeat these and are not read."""
    ranges = section_ranges(lines)
    if SECTION_SOFTWARE not in ranges:
        return []
    start, end = ranges[SECTION_SOFTWARE]
    out = []
    subsection = ''
    parent = None
    for index in range(start + 1, end):
        body = _body(lines[index])
        stripped = body.strip()
        if not stripped:
            parent = None
            continue
        if stripped.startswith('---') and stripped.endswith('---'):
            subsection = _subsection_title(stripped)
            parent = None
            continue
        kind = _software_kind(subsection)
        if stripped.startswith('(') or not kind:
            continue
        sub = _sub_line(body)
        if sub is not None:
            key, value = sub
            if key == 'key' and parent is not None and kind == 'uninstall' and value.strip():
                # "key: HKLM\...\{GUID}; name <DisplayName>; version <DisplayVersion>"
                # (older logs: the key alone). Named by its own entry, else the group.
                details, unlabelled = parse_labelled(value, SOFTWARE_LABELS)
                key_value = unlabelled[0] if unlabelled else details.get('key', '')
                if not key_value:
                    continue
                details['key'] = key_value[:300]
                name = details.get('name') or parent.item
                out.append(SoftwareFact(
                    index + 1, kind, name[:200], subsection, parent.time, parent.tags, '', parent.flags,
                    stripped[:300], details,
                ))
            continue
        if not _is_item_line(body):
            continue
        item = split_item(body)
        parent = item
        details, unlabelled = {}, []
        if kind == 'uninstall':
            program, status, rest = _split_program(item.rest)
            details, unlabelled = parse_labelled(rest, SOFTWARE_LABELS)
            if program:
                details['program'] = program[:300]
            # The item's own status is the program's ("=> program [unsigned]").
            item.status = status
        elif kind == 'installer':
            details, unlabelled = parse_labelled(item.rest, SOFTWARE_LABELS)
            details['event'] = SOFTWARE_EVENTS.get(item.tags, item.tags)
        else:
            details, unlabelled = parse_labelled(item.rest, SOFTWARE_LABELS)
            details['package'] = item.item[:300]
            if unlabelled and not item.rest.startswith(tuple(label + ' ' for label in SOFTWARE_LABELS)):
                details['display name'] = unlabelled[0]
        if kind == 'installer' and unlabelled:
            details['user'] = unlabelled[0]
        name = details.get('display name') or details.get('name') or item.item
        if not item.rest and kind == 'uninstall':
            continue   # a collapsed group's own line: its "key:" sub-lines are the facts
        out.append(SoftwareFact(index + 1, kind, name[:200], subsection, item.time, item.tags, item.status,
                                item.flags, stripped[:300], details))
    return out


# ---------------------------------------------------------------------------
# Times: the TIMELINE's items, and how to read their times as local time
# ---------------------------------------------------------------------------

# "Created:   2026-11-18 12:45:48 UTC (local time 13:45, UTC+01:00)"
_LOCAL_OFFSET_RE = re.compile(r'\(local time \d\d:\d\d, UTC([+-])(\d\d):(\d\d)\)')
_HEADER_LINES = 30


def local_offset_minutes(lines):
    """Minutes to add to the log's times for the PC's local time: the
    "Created:" line's UTC offset when the header says "Times: UTC", 0 when it
    names another time base (local); None when the header does not tell."""
    times = None
    offset = None
    for raw in lines[:_HEADER_LINES]:
        body = _body(raw)
        if body.startswith('Times:'):
            times = body.split(':', 1)[1].strip().upper()
        elif body.startswith('Created:'):
            m = _LOCAL_OFFSET_RE.search(body)
            if m:
                minutes = int(m.group(2)) * 60 + int(m.group(3))
                offset = -minutes if m.group(1) == '-' else minutes
    if times is None:
        return None
    if not times.startswith('UTC'):
        return 0
    return offset


def iter_timeline_items(lines, known=None):
    """(line_no, SporItem) of the TIMELINE section's item lines that have a
    time. `known` (known_paths) resolves !log-syntax-in-name lines; one that
    stays unresolved is left out, as in iter_timeline_evidence."""
    ranges = section_ranges(lines)
    if SECTION_TIMELINE not in ranges:
        return
    if known is None:
        known = known_paths(lines)
    start, end = ranges[SECTION_TIMELINE]
    for index in range(start + 1, end):
        body = _body(lines[index])
        if not _is_item_line(body) or not _TIME_RE.match(body):
            continue
        item = split_item(body, known)
        if item.trusted:
            yield index + 1, item
