"""Which machine a log comes from: signals compared between logs.

Kinds, strongest first (see compare):

- `sid`: the machine SID (S-1-5-21-a-b-c) of the local accounts an Addition
  log lists. Random per Windows install.
- `computer`: the computer name in an FRST header ("Ran by U (admin) on PC
  (model) (date)", in every language FRST writes) or a scanner's "Computer
  name".
- `usersid`: the SID prefixes of FRST's HKU\\S-1-5-21-... lines: the machine
  SID on a home PC, the domain's on a domain-joined one, so weaker.
- `profile`: Windows profile names (C:\\Users\\<name>\\, the "Ran by" user).
- `disk`: Disk IDs from an Addition log's partition table. Survive a
  reinstall; change with the disk.
- `hw`: the make/model of the FRST header, and motherboard + processor of
  an Addition log. Many machines share them: a match only says "likely".

Values are stored and compared as sha1 hashes (UploadedLogMachineSignal):
SIDs and Disk IDs identify a machine and are never shown. Pure functions.
"""

import hashlib
import re

KIND_SID = 'sid'
KIND_COMPUTER = 'computer'
KIND_USERSID = 'usersid'
KIND_PROFILE = 'profile'
KIND_DISK = 'disk'
KIND_HW = 'hw'
KINDS = (KIND_SID, KIND_COMPUTER, KIND_USERSID, KIND_PROFILE, KIND_DISK, KIND_HW)
# Kinds strong enough to point at the same machine across forum names.
STRONG_KINDS = (KIND_SID, KIND_DISK)

SYSTEM_SAME = 'same'
SYSTEM_LIKELY = 'likely'
SYSTEM_DIFFERENT = 'different'
SYSTEM_UNKNOWN = 'unknown'

# The legacy head-only reading (system_signals): headers and early paths.
SYSTEM_SIGNAL_CHARS = 200_000

# FRST's "Ran by" ($SCAN11) and "on" ($ON) in every language it writes (from
# FRST's own source; Polish has no "on").
RAN_BY_WORDS = (
    'Ran by', 'Gestart door', 'durchgeführt von', 'Uruchomiony przez', 'Exécuté par', 'Pokrenuo',
    'Executado por', 'Ejecutado por', 'Запущено с помощью', '通过...运行',
)
_ON_WORDS = ('on', 'op', 'auf', 'sur', 'na', 'em', 'sobre', 'на', '启动')
# Every quantifier is bounded and none crosses a line: the whole text of
# any upload is scanned (in the background), so a crafted huge line or a run
# of blank lines must not make these quadratic.
_RAN_BY_RE = re.compile(
    r'^(?:' + '|'.join(re.escape(word) for word in RAN_BY_WORDS) + r') ([^\r\n]{1,100}?) \([^()\r\n]{0,60}\) {1,3}'
    r'(?:(?:' + '|'.join(re.escape(word) for word in _ON_WORDS) + r') {1,3})?(\S{1,64}) (\([^\r\n]{0,300})',
    re.MULTILINE,
)
# What follows the computer name: "(<make model>) (<date>)" or just "(<date>)"
# (at most 300 characters, see _RAN_BY_RE).
_MODEL_RE = re.compile(r'^\((.*)\) \([^()]*\)\s*$')
_COMPUTER_NAME_RE = re.compile(
    r'^[ \t]{0,20}Computer name(?: \.){0,40}[ \t]{0,20}:[ \t]{0,20}(\S{1,64})', re.MULTILINE | re.IGNORECASE,
)
_PROFILE_RE = re.compile(r'[A-Za-z]:\\Users\\([^\\"\r\n]{1,64})\\', re.IGNORECASE)
# Profile folders Windows creates itself (or placeholders): never a real user.
SYSTEM_PROFILE_NAMES = frozenset({
    'public', 'default', 'default user', 'all users', 'defaultuser0', 'username',
    'defaultaccount', 'wdagutilityaccount',
})
# Addition "Accounts:": "Administrator (S-1-5-21-a-b-c-500 - Administrators - Disabled)".
_ACCOUNT_SID_RE = re.compile(r'^.{1,100}? \((S-1-5-21-\d+-\d+-\d+)-\d+ - ', re.MULTILINE)
_HKU_SID_RE = re.compile(r'^HKU\\(S-1-5-21-\d+-\d+-\d+)-\d+', re.MULTILINE)
# "Disk: 1 (Size: 476.94 GB) (Disk ID: 3CB325E2)" and "Disk ID          : {GUID}".
_DISK_ID_RE = re.compile(
    r'\(Disk ID: ([0-9A-Fa-f]{8})\)|^Disk ID\s*:\s*\{([0-9A-Fa-f-]{36})\}', re.MULTILINE,
)
_BOARD_RE = re.compile(r'^Motherboard: ([^\r\n]{1,200})', re.MULTILINE)
_PROCESSOR_RE = re.compile(r'^Processor: ([^\r\n]{1,200})', re.MULTILINE)
_SPACES_RE = re.compile(r'\s+')
_BLANK_DISK_IDS = frozenset({'00000000', '00000000-0000-0000-0000-000000000000'})


def _norm(value):
    return _SPACES_RE.sub(' ', (value or '').strip()).lower()


def extract_signals(content, head_only=False):
    """{kind: set of raw lowercased values} of a log's text. `head_only`
    reads only the first SYSTEM_SIGNAL_CHARS characters (the old reading)."""
    content = content or ''
    if head_only:
        content = content[:SYSTEM_SIGNAL_CHARS]
    signals = {kind: set() for kind in KINDS}
    for match in _RAN_BY_RE.finditer(content):
        user_name, computer, rest = match.groups()
        signals[KIND_COMPUTER].add(computer.lower())
        signals[KIND_PROFILE].add(user_name.strip().lower())
        model = _MODEL_RE.match(rest.rstrip('\r'))
        if model and _norm(model.group(1)):
            signals[KIND_HW].add('model:' + _norm(model.group(1)))
    for computer in _COMPUTER_NAME_RE.findall(content):
        signals[KIND_COMPUTER].add(computer.lower())
    for profile in _PROFILE_RE.findall(content):
        profile = profile.strip().lower()
        if profile and profile not in SYSTEM_PROFILE_NAMES:
            signals[KIND_PROFILE].add(profile)
    signals[KIND_SID].update(sid.lower() for sid in _ACCOUNT_SID_RE.findall(content))
    signals[KIND_USERSID].update(sid.lower() for sid in _HKU_SID_RE.findall(content))
    for mbr, gpt in _DISK_ID_RE.findall(content):
        value = (mbr or gpt).lower()
        if value not in _BLANK_DISK_IDS:
            signals[KIND_DISK].add(value)
    board = _BOARD_RE.search(content)
    processor = _PROCESSOR_RE.search(content)
    if board and processor and _norm(board.group(1)):
        signals[KIND_HW].add(f'board:{_norm(board.group(1))}|{_norm(processor.group(1))}')
    return {kind: values for kind, values in signals.items() if values}


def hash_value(kind, value):
    return hashlib.sha1(f'{kind}:{value}'.encode('utf-8')).hexdigest()


def hashed(signals):
    """The same signals with every value replaced by its stored hash."""
    return {kind: {hash_value(kind, value) for value in values} for kind, values in (signals or {}).items()}


def log_signals(content, head_only=False):
    """extract_signals, hashed: what UploadedLogMachineSignal stores."""
    return hashed(extract_signals(content, head_only=head_only))


# compare: kinds that decide both ways when both logs have them, in order;
# then the ones that can only say "same" / "likely".
_DECIDING = (KIND_SID, KIND_COMPUTER, KIND_USERSID, KIND_PROFILE, KIND_DISK)


def compare_with_reason(a, b):
    """(verdict, kind that decided or ''): see compare."""
    a, b = a or {}, b or {}
    for kind in _DECIDING:
        if a.get(kind) and b.get(kind):
            return (SYSTEM_SAME if a[kind] & b[kind] else SYSTEM_DIFFERENT), kind
    if a.get(KIND_HW) and b.get(KIND_HW) and a[KIND_HW] & b[KIND_HW]:
        return SYSTEM_LIKELY, KIND_HW
    return SYSTEM_UNKNOWN, ''


def compare(a, b):
    """'same', 'likely', 'different' or 'unknown' for two {kind: values}:
    the first kind in _DECIDING both have decides (shared value or not);
    else matching hardware says 'likely'."""
    return compare_with_reason(a, b)[0]


# A verdict's reason in a few words, by the kind that decided it. Computer
# and profile names are shown (they are in the logs anyway); SIDs and Disk
# IDs never are.
_REASON_SAME = {
    KIND_SID: 'same machine SID', KIND_COMPUTER: 'same computer name', KIND_USERSID: 'same user SIDs',
    KIND_PROFILE: 'same Windows profile', KIND_DISK: 'same disk', KIND_HW: 'same hardware, nothing else to compare',
}
_REASON_DIFFERENT = {
    KIND_SID: 'other Windows install', KIND_COMPUTER: 'other computer', KIND_USERSID: 'other user SIDs',
    KIND_PROFILE: 'other Windows profile', KIND_DISK: 'other disks',
}


def system_reason(verdict, kind, their_raw=None):
    """Short reason for a verdict of compare_with_reason. `their_raw`
    (extract_signals of the other log) adds the names for computer and
    profile: "other computer: desktop-2"."""
    if verdict in (SYSTEM_SAME, SYSTEM_LIKELY):
        return _REASON_SAME.get(kind, '')
    if verdict != SYSTEM_DIFFERENT:
        return ''
    text = _REASON_DIFFERENT.get(kind, '')
    if kind in (KIND_COMPUTER, KIND_PROFILE) and their_raw and their_raw.get(kind):
        text += ': ' + ', '.join(sorted(their_raw[kind])[:2])
    return text
