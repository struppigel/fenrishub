"""Parsing of Spor logs (forensic triage: execution evidence, persistence,
Defender, file hashes). Pure functions, no app imports.

The format, from Spor's README ("Log format (for parsers)"):

- "==================== TITLE - description ====...": a section;
  "--- title ---": a sub-section; "(...)": a comment.
- an item line: "[time] [tags] item [=> target] [ [status]] [=> | , details; ...]
  [<==== !flag !flag]", each part left out when empty. The time is the first
  19 characters when they are a time ("2026-11-20 12:00:00"; CLICKFIX lines
  start with a number instead: "1 [suspicious] ..."); "<==== " splits off the
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

import ntpath
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
# Spor 0.6.0+ (USB worm profile): drive contents, autorun.inf, shortcuts.
SECTION_USB = 'USB DRIVES'
# Spor 0.8.0: loader project folders found by a sweep of Windows cache folders
# (PavinLoader), each folder a line ending in "\" with "entry:" (its programs,
# scripts, .resx), "others:" (other names) and "group:" sub-lines.
SECTION_DROPS = 'DROP FOLDERS'
SECTION_REMOTE = 'REMOTE ACCESS'
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
# Hints (Spor 0.3.0+): weak flags that Spor puts in its SUMMARY only together
# with a strong flag nearby. On their own they are shown in the info colour and
# rate a line I, not !; they still get their files looked up.
# Spor 0.8.1: !abused-tld, a download from a cheap TLD campaigns favour.
HINT_FLAGS = frozenset({'!renamed-program', '!abused-tld'})
# Spor 0.4.0+ Autodetect: the item matches a known malware family (Spor's
# curated pattern database). Stronger than any heuristic flag: malware (B).
MALWARE_FLAGS = frozenset({'!known-malware'})
# Spor 0.8.1 context flags: not evidence of malware, but part of the case (a
# remote access tool used, an account created, Defender's history wiped). They
# put a finding in the SUMMARY; shown in the info colour, never a status.
INFO_FLAGS = frozenset({
    '!remote-access', '!account-change', '!history-deleted', '!disk-image', '!upload', '!new-service',
    '!task-deleted', '!startup-item', '!drop-group',
    # Spor 0.9.0: a PC maker's reset hook, a proxy, extension developer mode,
    # an older custom root certificate, Settings pages hidden by policy
    '!reset-config', '!proxy', '!dev-mode', '!custom-root', '!settings-changed',
})


FLAG_TIERS = ('malware', 'strong', 'info', 'hint', 'quiet')   # worst first


def flag_tier(flag):
    """'quiet' (normal on many PCs), 'hint' (weak), 'info' (context),
    'malware' (a known family) or 'strong'."""
    if flag in QUIET_FLAGS:
        return 'quiet'
    if flag in HINT_FLAGS:
        return 'hint'
    if flag in INFO_FLAGS:
        return 'info'
    if flag in MALWARE_FLAGS:
        return 'malware'
    return 'strong'


def worst_tier(flags):
    """The worst tier of some flags (FLAG_TIERS order); '' for none."""
    tiers = {flag_tier(flag) for flag in flags or ()}
    return next((tier for tier in FLAG_TIERS if tier in tiers), '')
# A path made to look like log text (" => ", "[gone]"): its line cannot be split as usual.
SYNTAX_FLAG = '!log-syntax-in-name'
# SUMMARY lines that write their flags after a double blank, without "<====":
# "[Prefetch] C:\...\x.pdf.lnk  !double-extension  (loaded by C:\...\host.exe)",
# also followed by a comma or a single blank and more text (Spor 0.6.x:
# "(user)  !hidden-account, password set ...", "x.exe  !kept-despite-warning from https://...").
INLINE_FLAG_RE = re.compile(r'(?<=  )(![a-zA-Z][a-zA-Z0-9-]{1,40})(?=[ ,]|\s*$)')

# One status word (also "> 600 MB, not hashed").
STATUS_WORD = r'(?:' + '|'.join(re.escape(word) for word in STATUS_WORDS) + r'|> \d{1,9} MB, not hashed)'
_STATUS_WORD_RE = re.compile(STATUS_WORD)
# " [status]", anywhere in a line. Spor joins several with ", " in one bracket:
# "[> 600 MB, not hashed, unsigned]".
STATUS_RE = re.compile(r' \[(' + STATUS_WORD + r'(?:, ' + STATUS_WORD + r'){0,5})\]')
_TIME_RE = re.compile(r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?= |$)')
# The own time of a timeline sub-line's file, after its " => ": "<time>",
# "<time>, first <time>, N times" (path:), "<time>; N bytes" (script:).
_SUB_TIME_RE = re.compile(r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?=[ ,;]|$)')
# One tag group, a "[user] " inside it allowed (multi-user logs of Spor 0.1.1
# and older: "[[anna] Brave]").
TAG_GROUP = r'\[(?:[^\[\]\r\n]|\[[^\[\]\r\n]{1,40}\]){1,80}\]'
# The leading tag groups of an item: "[task] [106] ", "[anna] [Brave] ".
_TAGS_RE = re.compile(r'^((?:' + TAG_GROUP + r' ){0,4}' + TAG_GROUP + r')(?: |$)')
_TAG_GROUP_RE = re.compile(TAG_GROUP)
FLAGS_MARK = ' <==== '
# Normal Spor logs (0.10.0+) end the lines of the records its aggressive
# whitelist (-aggressive, a command line trial) would hide with " ~". Parsers
# and rules read the line without it; the log view shows it.
AGGR_MARK = ' ~'
_PATH_START_RE = re.compile(r'^(?:[A-Za-z]:\\|\\\\)')
# Spor writes some service / task targets with forward slashes as the registry
# holds them ("D:/Program Files (x86)/PlanetVPN/x.exe"): normalize_path makes
# them paths where items and targets are split.
_FORWARD_SLASH_PATH_RE = re.compile(r'^[A-Za-z]:/')
_SUB_LINE_RE = re.compile(r'^( {2,}|\t+)([a-z][a-z0-9 ]{0,30}):(?: (.*)|)$')
# FILES: " => <hash>" or " => not hashed", the last one on the line (a path may contain " => ").
_FILES_VALUE_RE = re.compile(r' => ([0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32}|not hashed)(?=,|;|$)')
_HASH_VALUE_RE = re.compile(r'^(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})$')
# The labelled parts of a FILES line, longest first ("file version" before "version").
FILES_DETAIL_NAMES = (
    'original name', 'amcache sha1', 'file version', 'description', 'thumbprint', 'signature', 'modified',
    'product', 'company', 'created', 'signer', 'note', 'size', 'md5',
)
# "Defender action FAILED:" (events 1008, 1118, 1119) comes with !not-removed.
_DEFENDER_RE = re.compile(r'^Defender (detected|action taken|action FAILED): (.{1,300})$')
# Defender path entries that name a file ("file:_<path>", "webfile:_<path>|<url>|...").
_DEFENDER_FILE_PREFIX_RE = re.compile(r'^(?:file|containerfile|webfile):_', re.IGNORECASE)
# Where a path ends inside the rest of a line: its status (a bracket that is
# no status stays part of the path: "C:\Games [x]\a.exe"), a detail, the next
# part, the " (svchost DLL)" note of a service hosted by svchost.exe or the
# " (COM handler, HKLM)" note of a task's COM handler.
SVCHOST_DLL_NOTE = ' (svchost DLL)'
COM_HANDLER_NOTE = ' (COM handler, '
_PATH_END_RE = re.compile(r'(?= \[' + STATUS_WORD + r'[,\]])| => |, |; | \(svchost DLL\)| \(COM handler, |$')
# Device prefixes Windows APIs give paths ("\\?\C:\...", "\??\C:\..."; Spor's MPLog
# lines up to 0.1.1): without them the path matches the same file elsewhere.
_DEVICE_PREFIX_RE = re.compile(r'^(?:\\\\\?\\|\\\?\?\\)(?=[A-Za-z]:\\)')
# SOFTWARE Uninstall entries: "...; folder C:\...\" (the install folder).
_SOFTWARE_FOLDER_RE = re.compile(r'(?:^|; )folder ([^;]{1,400})')
# Sub-lines whose value is a file or folder of its own ("module:" an unsigned
# DLL a program loads or side-loads, "script:" a script file of a runtime
# launcher: Spor 0.3.0; USB DRIVES, Spor 0.6.0: "target:" a file autorun.inf
# starts, "icon file:" its icon, "argument file:" a file a shortcut's
# arguments name (a worm's hidden copy), "item list target:" a shortcut's
# target from its shell items when it differs; Spor 0.8.0: "group:" the first
# folder of a drop folder's group, so the members link to it; a task's further
# actions, "action: C:\x.exe [unsigned] => arguments ...").
_PATH_SUB_KEYS = frozenset({
    'loaded', 'path', 'target', 'entry', 'files', 'dll', 'module', 'script',
    'argument file', 'icon file', 'item list target', 'group', 'action',
})
# REMOTE ACCESS "[RMM folder]" lines (Spor 0.6.0): "exe: <path>", "file: <time> <path>".
_REMOTE_PATH_SUB_KEYS = frozenset({'exe', 'file'})
# TIMELINE sub-lines that are files with their own time ("path: X [status] =>
# <time>, ...", "script: X => <created>; N bytes").
_TIMELINE_SUB_KEYS = frozenset({'path', 'script'})
MAX_EXTRA = 6


@dataclass
class SporItem:
    time: str = ''
    tags: str = ''
    # The tag groups one by one ("[machine 32-bit]" stays one tag; `tags` joins them with blanks).
    tag_list: list = field(default_factory=list)
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
        """Flags other than the quiet ones: strong flags and hints."""
        return [flag for flag in self.flags if flag not in QUIET_FLAGS]

    @property
    def strong_flags(self):
        """Strong flags, the known-malware flag included."""
        return [flag for flag in self.flags if flag_tier(flag) in ('malware', 'strong')]

    @property
    def malware_flags(self):
        return [flag for flag in self.flags if flag_tier(flag) == 'malware']

    @property
    def trusted(self):
        return not self.untrusted or self.resolved


def is_path(text):
    return bool(_PATH_START_RE.match(text or ''))


def strip_device_prefix(path):
    r"""`path` without a leading device prefix ("\\?\C:\x" -> "C:\x")."""
    return _DEVICE_PREFIX_RE.sub('', path, count=1)


def normalize_path(text):
    r"""`text` without a device prefix and, when it starts with a drive and a
    forward slash, with backslashes ("D:/a/b.exe" -> "D:\a\b.exe"; one
    character for one, so positions in the text stay the same), up to a URL
    further on ("D:/a.exe sent to http://x/y" keeps its URL)."""
    text = strip_device_prefix(text)
    if not _FORWARD_SLASH_PATH_RE.match(text):
        return text
    url = text.find('://')
    end = text.rfind(' ', 0, url) + 1 if url != -1 else len(text)
    return text[:end].replace('/', '\\') + text[end:]


# "%USERPROFILE%\AppData\..." (Spor's PCA lines up to 0.6.1 at least).
_PROFILE_VAR_RE = re.compile(r'^%USERPROFILE%(?=\\)', re.IGNORECASE)
# Accounts of Windows itself that the header's "Users:" can list.
_SYSTEM_ACCOUNTS = frozenset({'wsiaccount', 'wdagutilityaccount', 'defaultaccount', 'guest'})
_DEFAULT_USER_RE = re.compile(r'^defaultuser\d{1,9}$')


def _is_system_account(name):
    lower = name.lower()
    return lower in _SYSTEM_ACCOUNTS or bool(_DEFAULT_USER_RE.match(lower))


def user_profile(lines, known=None):
    r"""The profile folder "%USERPROFILE%" stands for: that of the only user
    the header's "Users:" lists (accounts of Windows itself left out), as a
    FILES path (`known`, known_paths; read when None) spells it. '' when the
    header lists none or several users, or FILES has no file in such a
    folder (an account's folder can be named otherwise: no guessing)."""
    names = []
    for raw in lines[:_HEADER_LINES]:
        body = _body(raw)
        if body.startswith('Users:'):
            names = [name.strip() for name in body.split(':', 1)[1].split(',')]
            break
    names = [name for name in names if name and not _is_system_account(name)]
    if len(names) != 1:
        return ''
    if known is None:
        known = known_paths(lines)
    tail = ':\\users\\' + names[0] + '\\'
    found = [path for path in known.values() if path[1:len(tail) + 1].lower() == tail.lower()]
    # The system drive's profile before one on another disk (an old install, a USB drive).
    path = next((path for path in found if path[:1] in 'cC'), found[0] if found else '')
    return path[:len(tail)]


def _expand_profile(item, profile):
    if profile and item.item[:1] == '%':
        item.item = _PROFILE_VAR_RE.sub(lambda _m: profile, item.item, count=1)
    return item


def folder_path(path):
    r"""A folder as Spor lists it ("E:\<U+00A0>\") without the trailing
    backslash, so it keys like a file path and like FRST's folders; a drive
    root ("E:\") keeps it."""
    trimmed = (path or '').rstrip('\\')
    return trimmed if len(trimmed) > 2 else path


# USB DRIVES: a folder's attributes ("attributes hidden, system, folder; ...").
_HIDDEN_ATTRIBUTES_RE = re.compile(r'(?:^|; )attributes [^;]*\b(?:hidden|system)\b')


def is_hidden_folder(item):
    r"""A USB DRIVES or DROP FOLDERS folder line (path ending in "\") that is hidden, system or
    flagged: it speaks for the files inside it (a worm's hidden folder)."""
    return (item.item.endswith('\\') and len(item.item.rstrip('\\')) > 2
            and (bool(_HIDDEN_ATTRIBUTES_RE.search(item.rest)) or bool(item.loud_flags)))


def status_words(status):
    """The status words of a bracket ("> 600 MB, not hashed, unsigned" ->
    ['> 600 MB, not hashed', 'unsigned'])."""
    return _STATUS_WORD_RE.findall(status or '')


def is_bad_signature(status):
    """True when a status bracket says the signature does not hold."""
    return any(word in BAD_SIGNATURE_STATUSES for word in status_words(status))


def section_title(body):
    """'TIMELINE' for "==== TIMELINE - last 30 days ... ====", '' for other lines.
    The log's own title banner gives "Spor 0.1.0", the last one "End of log. ..."."""
    body = body.lstrip('﻿')
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


def split_item(body, known=None, profile=''):
    """The parts of an item line (see the module docstring). `known`
    ({lowercased path: path}, known_paths) resolves !log-syntax-in-name lines;
    `profile` (user_profile) stands in for a leading "%USERPROFILE%"."""
    return _expand_profile(_split_item(body, known), profile)


def _split_item(body, known):
    item = SporItem()
    text = strip_aggr_mark(body.rstrip())
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
        item.tag_list = [group[1:-1] for group in _TAG_GROUP_RE.findall(m.group(1))]
        item.tags = ' '.join(item.tag_list)
        text = text[m.end():]
    item.text = text
    if SYNTAX_FLAG in item.flags:
        item.untrusted = True
        path = resolve_item_path(text, known) if known else ''
        if path:
            item.resolved = True
            item.item = normalize_path(path)
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
    note = _NOTE_BRACKET_RE.search(head) if not m else None
    if m and not head[m.end():].strip():
        item.status = m.group(1)
        head = head[:m.start()]
    elif note and is_path(normalize_path(head[:note.start()])) and not status_words(note.group(1)):
        # A note in brackets after a path, no status word (Spor 0.8.0 USB DRIVES:
        # "N:\x\<U+0020>a.mp4 [name ends with a space or dot: ...] => ..."): not
        # part of the path; it goes in front of the details.
        item.rest = '; '.join(part for part in (note.group(1), item.rest) if part)
        head = head[:note.start()]
    elif m and not sep and _is_lone_path(head[:m.start()]) and not INLINE_FLAG_RE.search(head):
        # A path's status followed by text without " => " (SUMMARY of Spor
        # 0.6.x: "C:\...\robloxplayerbeta.exe [gone] sent N bytes (...)"); not
        # "path [gone]  !flag  (...)", whose flags iter_summary_items reads.
        item.status = m.group(1)
        item.rest = head[m.end():].strip().lstrip(',;').strip()
        head = head[:m.start()]
    else:
        # Without a status of its own, the item takes its target's ("[run] X =>
        # C:\a.exe [unsigned], ...", also "C:\Foo, Inc\a.exe" or a quoted
        # path), never a status further on in the details ("side-loads x.dll",
        # a parent chain, a command line).
        m = STATUS_RE.search(item.rest)
        if m and _is_target_prefix(item.rest[:m.start()]):
            item.status = m.group(1)
    item.item = normalize_path(head.strip())
    return item


# A bracket at the end of an item that is a note, not a status: it holds a
# blank and a colon ("[name ends with a space or dot: Windows programs cannot
# open it]"). A folder or file name never ends like that ("C:\Games [x]\a.exe"
# has its bracket inside the path).
_NOTE_BRACKET_RE = re.compile(r' \[([^\[\]\r\n]{1,40}: [^\[\]\r\n]{1,200})\]$')


# Where a second path starts inside a text: " C:\", "(C:\", " \\server".
_INNER_PATH_RE = re.compile(r'[ (](?:[A-Za-z]:[\\/]|\\\\)')


# A path's end: a file's extension or a folder's backslash.
_FILE_END_RE = re.compile(r'(?:\.[A-Za-z0-9]{1,10}|\\)$')


def _is_lone_path(text):
    """`text` is one path and nothing else: no double blank, no second path,
    ending in an extension or a backslash ("C:\\a.exe sent 5 bytes (by
    C:\\b.exe" and "C:\\a.exe sent 5 bytes" are not)."""
    text = normalize_path(text)
    return (is_path(text) and '  ' not in text and not _INNER_PATH_RE.search(text)
            and bool(_FILE_END_RE.search(text)))


def _is_target_prefix(text):
    """The text before a status bracket is the line's target: a path from the
    start of the rest (maybe quoted), not yet in the details ("; ", " => ")."""
    return is_path(normalize_path(text.lstrip('"'))) and '; ' not in text and ' => ' not in text


def strip_aggr_mark(text):
    """`text` without the aggressive-whitelist mark (AGGR_MARK) at its end;
    a block's text ("\\n"-joined lines): each line without it."""
    if not text or '~' not in text:
        return text
    if '\n' in text:
        return '\n'.join(strip_aggr_mark(line) for line in text.split('\n'))
    body = text.rstrip('\r')
    if not body.endswith(AGGR_MARK):
        return text
    return body[:-len(AGGR_MARK)] + text[len(body):]


def _body(raw):
    return strip_aggr_mark(raw[:-1] if raw.endswith('\r') else raw)


def _is_item_line(body):
    stripped = body.strip()
    return bool(stripped) and not body[:1].isspace() and not stripped.startswith(('(', '---', '='))


def _sub_line(body):
    """(key, value) of an indented "key: value" line, else None."""
    m = _SUB_LINE_RE.match(body)
    return (m.group(2), m.group(3) or '') if m else None


def _subsection_title(stripped):
    return stripped.strip('-').strip()


def is_sub_line(body):
    """`body` is an indented "key: value" line (it belongs to the item above)."""
    return _sub_line(body) is not None


# ---------------------------------------------------------------------------
# Spor 0.7.0+: details on sub-lines of their own, folded back for the readers
# ---------------------------------------------------------------------------
# Spor 0.7.0 writes long details on indented sub-lines instead of the line: a
# Run value's or task's program and arguments ("program:", "arguments:",
# "value:"), a Defender detection's items ("file:", "process:",
# "resource:"), a download's addresses under TIMELINE and SUMMARY lines
# ("from:", "page:", "referrer:") and a SOFTWARE entry's "folder:", "key:"
# and "signer:". unfold() writes them back into their line as Spor 0.6 did,
# so the readers below read logs of every version the same way.

_RUN_TASK_KINDS = frozenset({'run', 'runonce', 'policy-run', 'task'})
_DEFENDER_ITEM_KEYS = ('file', 'process', 'resource')
# A download's addresses: whole URLs (DOWNLOADS), "blob:https://..." or
# "host/path" without scheme and query (TIMELINE, SUMMARY: Spor's Host()).
# log_highlighting marks each value as one URL.
DOWNLOAD_KEYS = ('from', 'page', 'referrer')
_FOLD_KEYS = frozenset({'program', 'arguments', 'value', 'folder', 'key', 'signer', 'version', *_DEFENDER_ITEM_KEYS, *DOWNLOAD_KEYS})
# FILES: "    file: md5 M; size N; created T; modified T; amcache sha1 S" and
# "    version: file version X; ...; thumbprint T" under the hash line.
_FILES_SUB_KEYS = ('file', 'version')


def _folded_rest(title, item, subs):
    """The rest of `item` (an item line of section `title`) with its sub-lines
    `subs` ([(key, value)]) folded in as Spor 0.6 wrote it on the line; None
    when none of them belongs there."""
    keys = [key for key, _value in subs]
    kind = (item.tags.split() or [''])[0].lower()
    if title == SECTION_FILES:
        # "=> <hash>, signature valid; signer X; md5 M; size N; ...; file version V; ...; thumbprint T"
        added = [value for key, value in subs if key in _FILES_SUB_KEYS and value]
        return '; '.join(([item.rest] if item.rest else []) + added) if added else None
    if title == SECTION_PERSISTENCE and kind in _RUN_TASK_KINDS and 'program' in keys:
        # "=> C:\x.exe [unsigned], changed <time>; arguments -a; value Name"
        program = next(value for key, value in subs if key == 'program')
        details = [item.rest] if item.rest else []
        details += [f'arguments {value}' for key, value in subs if key == 'arguments'][:1]
        if kind != 'task':
            # Without a "value:" line the value name is the entry's last part.
            value = next((value for key, value in subs if key == 'value'), '') or item.item.rsplit('\\', 1)[-1]
            details.append(f'value {value}')
        return program + (', ' + '; '.join(details) if details else '')
    if _DEFENDER_RE.match(item.item) and any(key in _DEFENDER_ITEM_KEYS for key in keys):
        # "=> C:\a.zip; C:\a.zip->b.exe; process: C:\c.exe, pid:5:1; action Remove"
        parts = [f'process: {value}' if key == 'process' else value for key, value in subs if key in _DEFENDER_ITEM_KEYS]
        return '; '.join(parts + ([item.rest] if item.rest else []))
    added = []
    if title in (SECTION_TIMELINE, SECTION_SUMMARY):
        added += [f'{key} {value}' for key, value in subs if key in DOWNLOAD_KEYS]
    if title == SECTION_SOFTWARE or (title == SECTION_TIMELINE and 'INS' in item.tags.split()):
        # Several "key:" lines are the entries of a collapsed group: facts of their own.
        single_key = keys.count('key') == 1
        added += [f'{key} {value}' for key, value in subs if key in ('folder', 'signer') or (key == 'key' and single_key)]
    if not added:
        return None
    return '; '.join(([item.rest] if item.rest else []) + added)


def _with_rest(raw, rest):
    """Item line `raw` with `rest` after its first " => " (its flags kept at the end)."""
    cr = '\r' if raw.endswith('\r') else ''
    body = _body(raw).rstrip()
    cut = body.find(FLAGS_MARK)
    head, tail = (body[:cut], body[cut:]) if cut != -1 else (body, '')
    return f"{head.partition(' => ')[0]} => {rest}{tail}{cr}"


class _Unfolded(list):
    """Lines unfold() has folded already: folding them again would put their
    sub-lines on the line a second time (and cost a pass over the log)."""


def unfold(lines):
    """`lines` with the sub-lines of Spor 0.7.0+ folded back into their item
    line (_folded_rest), line numbers unchanged: the sub-lines stay where they
    are (the readers skip them or keep them as extra). `lines` itself when
    there is nothing to fold (logs of Spor 0.6 and older) or when they are
    unfold()'s own result already. The readers of one log (spor_source.build)
    each ask for it: the last result is kept for the same list (never changed
    in place by the readers)."""
    global _last_unfold
    if isinstance(lines, _Unfolded):
        return lines
    last = _last_unfold
    if last[0] is lines and last[1] == len(lines):
        return last[2]
    out = _unfold(lines)
    _last_unfold = (lines, len(lines), out)
    return out


# (lines, their count, unfold's result) of the last log unfolded.
_last_unfold = (None, 0, None)


def _unfold(lines):
    out = None
    title = ''
    count = len(lines)
    index = 0
    while index < count:
        body = _body(lines[index])
        found = section_title(body)
        if found:
            title = found
            index += 1
            continue
        if not _is_item_line(body):
            index += 1
            continue
        subs = []
        following = index + 1
        while following < count:
            sub = _sub_line(_body(lines[following]))
            if sub is None:
                break
            subs.append((sub[0], sub[1].strip()))
            following += 1
        if any(key in _FOLD_KEYS for key, _value in subs):
            item = split_item(body)
            # A FILES line's sub-lines only add to the end of its rest, so a
            # !log-syntax-in-name line (its path not resolved here) gets them too.
            rest = _folded_rest(title, item, subs) if item.trusted or title == SECTION_FILES else None
            if rest is not None:
                if out is None:
                    out = _Unfolded(lines)
                out[index] = _with_rest(lines[index], rest)
        index = following
    return out if out is not None else lines


def sub_details(lines, index):
    """[[key, value]] of the sub-lines right under item line `index` (0-based)
    that are details of it, not files of their own (_PATH_SUB_KEYS,
    _TIMELINE_SUB_KEYS): Spor 0.7.0's "program:", "arguments:", "file:",
    "from:", "folder:", ... and "info:" (at most MAX_EXTRA, values cut at 200)."""
    out = []
    for following in range(index + 1, len(lines)):
        sub = _sub_line(_body(lines[following]))
        if sub is None:
            break
        key, value = sub[0], sub[1].strip()
        if key in _PATH_SUB_KEYS or key in _TIMELINE_SUB_KEYS or not value:
            continue
        if len(out) < MAX_EXTRA:
            out.append([key, value[:200]])
    return out


def as_written(lines, line_no):
    """(text, extra) of item line `line_no` (from 1) as the log shows it: the
    line itself (stripped, at most 300 characters) and its detail sub-lines
    (sub_details), not the line unfold() makes of them."""
    index = line_no - 1
    if not 0 <= index < len(lines):
        return '', []
    return _body(lines[index]).strip()[:300], sub_details(lines, index)


def rest_as_written(lines, line_no, known=None, profile=''):
    """The part after " => " of item line `line_no` as the log writes it."""
    index = line_no - 1
    if not 0 <= index < len(lines):
        return ''
    return split_item(_body(lines[index]), known, profile).rest


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
    body = strip_aggr_mark(body)
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
    lines = unfold(lines)   # Spor 0.7.0+: md5, size, times and version on sub-lines
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

# Defender's "resource:" items up to Spor 0.8.0 name a file by its volume
# device ("\Device\HarddiskVolume3\Users\x\a.exe"): device_volumes maps it to
# its drive.
_DEVICE_PATH_RE = re.compile(r'^\\Device\\(HarddiskVolume\d{1,3})(\\.*)$', re.IGNORECASE)
# Folders only the system drive has: a device path under one is on it when
# the log pairs the volume with no drive.
_SYSTEM_DRIVE_FOLDERS = ('\\users\\', '\\windows\\', '\\programdata\\', '\\program files')
_DRIVE_PATH_RE = re.compile(r'(?<![\w\\])([A-Za-z]:)(\\[^;"|<>\r\n]{1,400})')


def device_volumes(lines):
    r"""{volume device (lowercased, "harddiskvolume3"): drive ("C:")} of the
    devices a log names, learned from the log itself: a device path and a
    drive path with the same rest ("process C:\x\a.exe" and "resource:
    \Device\HarddiskVolume3\x\a.exe" of one Defender detection; a FILES path).
    A volume paired with several drives is left out. The readers of one log
    each ask for it: the last result is kept for the same list."""
    global _last_volumes
    if _last_volumes[0] is lines and _last_volumes[1] == len(lines):
        return _last_volumes[2]
    found = _device_volumes(lines)
    _last_volumes = (lines, len(lines), found)
    return found


# (lines, their count, device_volumes' result) of the last log read.
_last_volumes = (None, 0, None)


def _device_volumes(lines):
    rests = {}
    devices = []
    for raw in lines:
        if '\\Device\\' in raw or '\\device\\' in raw:
            for part in re.split(r'[;,]\s*|:\s+', raw.strip()):
                m = _DEVICE_PATH_RE.match(part.strip())
                if m:
                    devices.append((m.group(1).lower(), m.group(2).rstrip().lower()))
        if ':\\' in raw:
            for drive, rest in _DRIVE_PATH_RE.findall(raw):
                rests.setdefault(rest.rstrip().lower(), set()).add(drive.upper())
    if not devices:
        return {}
    votes = {}
    for volume, rest in devices:
        drives = rests.get(rest)
        if drives and len(drives) == 1:
            votes.setdefault(volume, set()).update(drives)
    return {volume: next(iter(drives)) for volume, drives in votes.items() if len(drives) == 1}


def device_path(path, volumes=None):
    r"""A "\Device\HarddiskVolumeN\x" path as a drive path ("C:\x") through
    `volumes` (device_volumes); a volume the log does not pair is the system
    drive when the path is under a folder only it has (Users, Windows, ...).
    Any other text unchanged; '' for a device path it cannot place."""
    m = _DEVICE_PATH_RE.match(path or '')
    if not m:
        return path
    drive = (volumes or {}).get(m.group(1).lower())
    if not drive and m.group(2).lower().startswith(_SYSTEM_DRIVE_FOLDERS):
        drive = 'C:'
    return drive + m.group(2) if drive else ''


def _defender_path(entry, volumes=None):
    entry = _DEFENDER_FILE_PREFIX_RE.sub('', entry.strip(), count=1)
    path = entry.split('|', 1)[0].split('->', 1)[0].strip().strip('"')
    path = device_path(path, volumes)
    return path if is_path(path) else ''


def defender_threat(item_text):
    """The threat of a "Defender detected: / action taken: / action FAILED:"
    item, '' for any other item."""
    m = _DEFENDER_RE.match(item_text or '')
    return m.group(2).strip() if m else ''


def defender_paths(rest, volumes=None):
    r"""The files a Defender line's details name ("<path>; action ...; process
    ..."). `volumes` (device_volumes) places "\Device\HarddiskVolumeN\..."
    resources on their drive."""
    return [path for path in (_defender_path(part, volumes) for part in (rest or '').split('; ')
                              if not part.strip().startswith(('action ', 'process '))) if path]


def iter_defender_detections(lines):
    """(line_no, threat, action, path) for every file the DEFENDER section's
    "Defender detected:" / "Defender action taken:" lines name, one per
    (path, threat): a line with a real action wins over the detection."""
    lines = unfold(lines)   # Spor 0.7.0+ sub-lines, back on their line
    ranges = section_ranges(lines)
    if SECTION_DEFENDER not in ranges:
        return []
    start, end = ranges[SECTION_DEFENDER]
    volumes = device_volumes(lines)   # from the whole log, as its other readers learn them
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
                path = _defender_path(part, volumes)
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
    # The line's detail sub-lines (Spor 0.7.0+: "from:", "page:", ...), as
    # written; `details` is its rest as written.
    extra: list = field(default_factory=list)


def iter_timeline_evidence(lines, known=None):
    """Evidence per file of the TIMELINE section: what was seen (runs,
    creation, download, ...) by which sources, and when. A merged line
    ("path:" sub-lines, one per real path) gives each path its own entry,
    with its own time and status. One entry per path (case-insensitive).
    A !log-syntax-in-name line counts only when its path is in FILES."""
    written = lines         # as the log shows them (the entries' details)
    lines = unfold(lines)   # Spor 0.7.0+ sub-lines, back on their line
    ranges = section_ranges(lines)
    if SECTION_TIMELINE not in ranges:
        return []
    if known is None:
        known = known_paths(lines)
    profile = user_profile(lines, known)
    start, end = ranges[SECTION_TIMELINE]
    out = []
    seen = {}   # lowercased path: its Evidence
    parent = None
    parent_details, parent_extra = '', []   # the item line's rest and detail sub-lines, as written

    def add(line_no, path, time, file_status, details, flags, extra=()):
        key = path.lower()
        if key in seen:
            # The first line wins; a later one can still tell the file's status
            # (a PCA line names "%USERPROFILE%\..." files without one).
            if file_status and not seen[key].file_status:
                seen[key].file_status = file_status
            return
        seen[key] = Evidence(line_no, path, time, parent.tags, file_status, details.strip()[:300], flags, list(extra))
        out.append(seen[key])

    for index in range(start + 1, end):
        body = _body(lines[index])
        sub = _sub_line(body)
        if sub is not None:
            key, value = sub
            if key not in _TIMELINE_SUB_KEYS or parent is None:
                continue
            item = split_item(value, known, profile)
            if not item.trusted or not is_path(item.item):
                continue
            own_time = _SUB_TIME_RE.match(item.rest)
            time = item.rest[:19] if own_time else parent.time
            if key == 'script':
                # A script file of a runtime launcher: its own details, and only
                # its own flags (Spor flags the launcher, not its data files).
                rest = item.rest[19:].lstrip(';, ') if own_time else item.rest
                details = '; '.join(part for part in (rest, 'script of ' + ntpath.basename(parent.item)) if part)
                add(index + 1, item.item, time, item.status, details, item.flags)
            else:
                # A merged line's path: the details of its line, as written.
                add(index + 1, item.item, time, item.status, parent_details, item.flags or parent.flags, parent_extra)
            continue
        if not _is_item_line(body):
            parent = None
            continue
        parent = split_item(body, known, profile)
        parent_details = parent.rest if written is lines else rest_as_written(written, index + 1, known, profile)
        parent_extra = sub_details(written, index)
        if parent.tags and parent.trusted and is_path(parent.item):
            add(index + 1, parent.item, parent.time, parent.status, parent_details, parent.flags, parent_extra)
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
    parent_line: int = 0    # a sub-line's item line (its line number), 0 for an item line


def _path_at(text):
    """The path `text` starts with, up to its status, " => " or the next part."""
    text = normalize_path(text)
    if not is_path(text):
        return ''
    return text[:_PATH_END_RE.search(text).start()].strip()


def _status_after(text, path):
    text = normalize_path(text)
    if not text.startswith(path):
        return ''
    position = len(path)
    if text.startswith(SVCHOST_DLL_NOTE, position):
        position += len(SVCHOST_DLL_NOTE)
    elif text.startswith(COM_HANDLER_NOTE, position):
        end = text.find(')', position)
        if end != -1:
            position = end + 1
    m = STATUS_RE.match(text, position)
    return m.group(1) if m else ''


# For the parsers of Spor blocks (spor_extractors): the path a text starts
# with, and the status written right after it.
path_at = _path_at
status_after = _status_after


# PERSISTENCE: the entry's kind is its first tag ("[run]", "[service]", ...),
# never the sub-section title. Run values are named by their "value" detail
# (a value name can hold backslashes: it is not cut from the key), services,
# drivers and tasks by the item.
PERSISTENCE_KINDS = {
    'run': 'run', 'runonce': 'run', 'policy-run': 'run', 'service': 'svc', 'driver': 'svc', 'task': 'task',
}
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
        # Further tags ("[task] [106] \Path" of a Task Scheduler event) are in item.tags.
        name = item.item
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
    "info:") are its `extra`. New modules need no code. A mention's `text`
    is its line as the log writes it (Spor 0.7.0+: without the sub-lines
    unfold() puts on it; they are its `extra`)."""
    written = lines
    lines = unfold(lines)   # Spor 0.7.0+ sub-lines, back on their line
    if known is None:
        known = known_paths(lines)
    profile = user_profile(lines, known)
    out = []
    for title, start, end in iter_sections(lines):
        if title in _NOT_MENTION_SECTIONS or title.startswith(('Spor', 'End of log')):
            continue
        subsection = ''
        current = []   # the mentions of the item line above (its sub-lines add to them)
        parent = None  # the item line above
        parent_no = 0  # its line number
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
                path_key = key in _PATH_SUB_KEYS or (title == SECTION_REMOTE and key in _REMOTE_PATH_SUB_KEYS)
                item = split_item(value, known, profile) if path_key else None
                if (key == 'dll' and item is not None
                        and any(mention.path.lower() == item.item.lower() for mention in current)):
                    continue   # a registry line's target already is the DLL
                if (key == 'files' and item is not None and parent is not None
                        and any(mention.parent_line == parent_no and mention.role == 'files'
                                and mention.path.lower() == item.item.lower() for mention in out[-MAX_EXTRA:])):
                    continue   # Spor 0.7.0+: a long list of one folder on several "files:" lines
                if item is not None and item.trusted and is_path(item.item):
                    owner = parent.item if parent else ''
                    if key == 'module':
                        # loaded by the program of the line (a Run value's or task's target), not the registry entry
                        owner = next((mention.path for mention in current if mention.role == 'target'), owner)
                    # a group's first folder keys like that folder's own line (without the "\")
                    path = folder_path(item.item) if key == 'group' else item.item
                    out.append(Mention(
                        index + 1, path, title, subsection, item.time or (parent.time if parent else ''),
                        parent.tags if parent else '', stripped[:300], key,
                        owner[:200], item.status, item.flags, parent_line=parent_no if parent else 0,
                    ))
                elif current and value:
                    for mention in current:
                        if len(mention.extra) < MAX_EXTRA:
                            mention.extra.append([key, value.strip()[:200]])
                continue
            if body[:1].isspace() or not _is_item_line(body):
                continue
            item = split_item(body, known, profile)
            current = []
            parent, parent_no = item, index + 1
            if not item.trusted or _DEFENDER_RE.match(item.item):
                continue   # Defender detections are read by iter_defender_detections
            common = dict(section=title, subsection=subsection, time=item.time, tags=item.tags,
                          text=_body(written[index]).strip()[:300], flags=item.flags)
            if is_path(item.item):
                # "[Paths]", and Spor 0.8.1's "[Paths (policy)]" (the Policies key, where malware writes them)
                folder = (title == SECTION_DEFENDER and item.tags in ('Paths', 'Paths (policy)')
                          and 'exclusion' in subsection.lower())
                path = item.item
                if title in (SECTION_USB, SECTION_DROPS):
                    # Folders end in "\"; a hidden or flagged one speaks for its files.
                    folder = is_hidden_folder(item)
                    path = folder_path(path)
                current.append(Mention(index + 1, path, role='item', status=item.status, folder=folder,
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
    kind: str               # uninstall / installer / cached / package
    name: str               # display name (or the package full name)
    subsection: str = ''
    time: str = ''
    tags: str = ''
    status: str = ''
    flags: list = field(default_factory=list)
    text: str = ''
    details: dict = field(default_factory=dict)   # SOFTWARE_LABELS, plus program / user / event / display name
    # `text` is the line as written; Spor 0.7.0+ puts "folder:", "key:" and
    # "signer:" on sub-lines of their own: [[key, value]] (sub_details).
    extra: list = field(default_factory=list)


def _software_kind(subsection):
    lower = subsection.lower()
    if lower.startswith('installed programs'):
        return 'uninstall'
    if lower.startswith('windows installer'):
        return 'installer'
    if lower.startswith('cached windows installer'):
        return 'cached'
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
    code {GUID}"), cached Windows Installer packages (Spor 0.8.0: "name N;
    version V; publisher P; product code {GUID}", the packages Spor flags)
    and Store / MSIX operations (with the package "folder").
    The "key:" sub-lines of a collapsed group ("27 entries from ...") are
    facts too. TIMELINE's [INS] lines repeat these and are not read."""
    written = lines
    lines = unfold(lines)   # Spor 0.7.0+ sub-lines, back on their line
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
            # Only under a collapsed group's line (no details of its own): the
            # "key:" line of a single entry (Spor 0.7.0+) is on its unfolded line.
            if key == 'key' and parent is not None and kind == 'uninstall' and not parent.rest and value.strip():
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
        elif kind == 'cached':
            details, unlabelled = parse_labelled(item.rest, SOFTWARE_LABELS)
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
        # a cached package's file name is random: its product code, not the file, when it has no name
        fallback = details.get('product code', '') if kind == 'cached' else item.item
        name = details.get('display name') or details.get('name') or fallback
        if not item.rest and kind == 'uninstall':
            continue   # a collapsed group's own line: its "key:" sub-lines are the facts
        text, extra = as_written(written, index + 1)
        out.append(SoftwareFact(index + 1, kind, name[:200], subsection, item.time, item.tags, item.status,
                                item.flags, text, details, extra))
    return out


# ---------------------------------------------------------------------------
# SUMMARY, and item lines by section
# ---------------------------------------------------------------------------

def iter_summary_items(lines, known=None):
    """(line_no, SporItem) of the SUMMARY section's item lines. Flags written
    inline ("[Prefetch] C:\\...\\x.pdf.lnk  !double-extension  (loaded by ...)")
    are moved from the item to its flags."""
    lines = unfold(lines)   # Spor 0.7.0+ sub-lines, back on their line
    ranges = section_ranges(lines)
    if SECTION_SUMMARY not in ranges:
        return
    start, end = ranges[SECTION_SUMMARY]
    if known is None:
        known = known_paths(lines)
    profile = user_profile(lines, known)
    for index in range(start + 1, end):
        body = _body(lines[index])
        if not _is_item_line(body):
            continue
        yield index + 1, summary_item(body, known, profile)


def summary_item(body, known=None, profile=''):
    r"""A SUMMARY line's SporItem (split_item), with flags written inline
    ("[Prefetch] C:\...\x.pdf.lnk  !double-extension  (loaded by ...)") moved
    from the item to its flags, and a status in front of them ("download
    C:\...\x.exe [gone]  !kept-despite-warning from ...") to its status."""
    item = split_item(body, known, profile)
    if item.flags:
        return item
    m = INLINE_FLAG_RE.search(item.item)
    if m:
        item.flags = INLINE_FLAG_RE.findall(item.item)
        # What follows the flags ("password set ...", "from https://...", "(loaded by ...)").
        # (From the double blank in front: the flags' pattern looks back at it.)
        details = INLINE_FLAG_RE.sub('', item.item[m.start() - 2:]).strip().lstrip(',;').strip()
        if details and not item.rest:
            item.rest = details
        item.item = item.item[:m.start()].rstrip()
        status = STATUS_RE.search(item.item)
        if status and not item.status and not item.item[status.end():].strip():
            item.status = status.group(1)
            item.item = item.item[:status.start()]
    return item


def iter_section_items(lines, known=None, skip=frozenset({SECTION_SUMMARY, SECTION_LEGEND})):
    """(line_no, section title, SporItem) of the item lines of every section
    but `skip` (sub-lines left out)."""
    lines = unfold(lines)   # Spor 0.7.0+ sub-lines, back on their line
    if known is None:
        known = known_paths(lines)
    profile = user_profile(lines, known)
    for title, start, end in iter_sections(lines):
        if title in skip or title.startswith(('Spor', 'End of log')):
            continue
        for index in range(start + 1, end):
            body = _body(lines[index])
            if _is_item_line(body):
                yield index + 1, title, split_item(body, known, profile)


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
    time, and of the "path:" sub-lines of a merged line at their own time
    (tags of their line). `known` (known_paths) resolves !log-syntax-in-name
    lines; one that stays unresolved is left out, as in iter_timeline_evidence."""
    lines = unfold(lines)   # Spor 0.7.0+ sub-lines, back on their line
    ranges = section_ranges(lines)
    if SECTION_TIMELINE not in ranges:
        return
    if known is None:
        known = known_paths(lines)
    profile = user_profile(lines, known)
    start, end = ranges[SECTION_TIMELINE]
    parent = None
    for index in range(start + 1, end):
        body = _body(lines[index])
        sub = _sub_line(body)
        if sub is not None:
            # A merged line's "path: X [status] => <time>[, first <time>, N times]"
            # (and a launcher's "script: X => <created>; ..."): each path at its
            # own time, with the sources of its line.
            key, value = sub
            if key not in _TIMELINE_SUB_KEYS or parent is None:
                continue
            item = split_item(value, known, profile)
            m = _SUB_TIME_RE.match(item.rest)
            if not m or not item.trusted or not is_path(item.item):
                continue
            item.time, item.tags = m.group(0), parent.tags
            if item.time == parent.time and item.item.lower() == parent.item.lower():
                continue   # the merged line itself
            yield index + 1, item
            continue
        if not _is_item_line(body) or not _TIME_RE.match(body):
            parent = None
            continue
        item = split_item(body, known, profile)
        parent = item if item.trusted else None
        if item.trusted:
            yield index + 1, item
