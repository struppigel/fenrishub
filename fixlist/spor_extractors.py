"""Parsed entries of Spor log blocks, and the path of each Spor line.

A Spor entry spans a block: its item line and the indented "    key: value"
lines under it (log_layout). A Run value's program and arguments, for
instance, are on `program:` / `arguments:` lines below the entry. parse_block
reads such a block into one FrstEntry of a `spor_*` type, so a parsed rule
made from it matches the same entry on another PC (other user, other time).

Only what stays the same across PCs goes into an entry: no times, sources,
hashes, versions or counts. Lines of other files below an entry (`module:`,
`dll:`, `file:`, `folder:`) are not part of it; they keep their own path
(line_path), which file path rules match.

Spor 0.7.0 and later only (LOG-FORMAT.md in Spor's docs); entries are read
from the text alone, so rule creation, re-parsing and analysis agree. The
analyzer asks for them in Spor logs only. Pure functions, no app imports.
"""

import ntpath
import re
from typing import NamedTuple

from . import frst_extractors as ex
from . import log_layout
from . import spor_log as sl

# Every entry_type parse_block produces (a test checks the module's literals).
SPOR_ENTRY_TYPES = (
    "spor_run", "spor_service", "spor_task", "spor_startup", "spor_defender", "spor_defender_exclusion",
    "spor_software", "spor_installer", "spor_cached_msi", "spor_package", "spor_process", "spor_file",
)
# The parsed types a rule can be restricted to: FRST's, then Spor's.
ALL_ENTRY_TYPES = ex.ENTRY_TYPES + SPOR_ENTRY_TYPES

MIN_VERSION = (0, 7, 0)

# A sub-line once stripped: "program: C:\x.exe [unsigned]".
_SUB_RE = re.compile(r'^([a-z][a-z0-9 ]{0,30}):(?: (.*)|)$')
_VERSION_RE = re.compile(r'^=+ Spor (\d{1,4})\.(\d{1,4})\.(\d{1,4})\b')

_RUN_KINDS = frozenset({'run', 'runonce', 'policy-run'})
_SERVICE_KINDS = frozenset({'service', 'driver'})
_EXCLUSION_KINDS = frozenset({'Paths', 'Extensions', 'Processes', 'IpAddresses', 'TemporaryPaths'})
_INSTALLER_EVENTS = frozenset({'1033', '1034', '11708'})
_INSTALLER_PREFIXES = ('installed: ', 'removed: ', 'install failed: ', 'install FAILED: ')
_SOFTWARE_SCOPE_RE = re.compile(r'^(?:machine(?: 32-bit)?|user .{1,80})$')
# Store / MSIX operations ("Add", "Register", "ProvisionPackageOperation"); not
# all-capital timeline sources ("INS", "PF").
_PACKAGE_OPERATION_RE = re.compile(r'^[A-Z][a-z][A-Za-z]{0,40}$')
# A package full name: name_version_architecture_resourceid_publisherid.
_PACKAGE_RE = re.compile(r'^([^_\s]{1,200})_[^_\s]{0,40}_[^_\s]{0,20}_[^_\s]{0,40}_([a-z0-9]{13})$')
_SIGNER_NOTE_RE = re.compile(r'(?:\s\((?:package|catalog|newer version)\)){1,3}$')
# RUNNING PROCESSES parents: "Explorer.EXE (15464)", "pid 4200 (exited, was x.exe)".
_PARENT_PID_RE = re.compile(r'^(.{1,260}?) \(\d{1,10}\)$')
_PARENT_WAS_RE = re.compile(r'^pid \d{1,10} \(exited, was (.{1,260})\)$')
_PARENT_GONE_RE = re.compile(r'^pid \d{1,10} \(exited\)$')

# Lengths of the ClassificationRule columns the fields are stored in.
_MAX_NAME = 512
_MAX_ATTRIBUTES = 16
_MAX_CLSID = 128


def _path(value):
    """`value` in the form FRST entries hold paths: device prefix and forward
    slashes resolved, Spor's character markers decoded, drive, user and
    browser profile normalized."""
    if not value:
        return ''
    return ex.normalize_path(ex.decode_spor_chars(sl.normalize_path(value.strip())))


def _entry(entry_type, *, name='', filepath='', clsid='', company='', arguments='', file_not_signed=False,
           attributes='', is_hidden=False):
    filepath = _path(filepath)
    return ex.FrstEntry(
        clsid=clsid[:_MAX_CLSID],
        name=name.strip()[:_MAX_NAME],
        filepath=filepath,
        filename=ntpath.basename(filepath)[:260] if filepath else '',
        company=company.strip()[:_MAX_NAME],
        arguments=ex.normalize_path(arguments.strip()) if arguments else '',
        file_not_signed=file_not_signed,
        entry_type=entry_type,
        attributes=attributes[:_MAX_ATTRIBUTES],
        is_hidden=is_hidden,
    )


def _unsigned(status):
    return 'unsigned' in sl.status_words(status)


def _subs(texts):
    """[(key, value)] of the stripped sub-lines `texts`."""
    found = []
    for text in texts:
        m = _SUB_RE.match(text)
        if m:
            found.append((m.group(1), (m.group(2) or '').strip()))
    return found


def _sub(subs, key):
    return next((value for found, value in subs if found == key), '')


def _program(value):
    """(path, status) of a "program: path [status]" value; ('', '') without a path."""
    path = sl.path_at(value)
    return (path, sl.status_after(value, path)) if path else ('', '')


def split(text):
    """The SporItem of a stripped item line, flags written inline in SUMMARY
    lines moved to its flags (spor_log.summary_item)."""
    return sl.summary_item(text)


def _run(item, subs):
    item.rest = sl._folded_rest(sl.SECTION_PERSISTENCE, item, subs) or item.rest
    identity = sl.persistence_identity(item)
    name = identity[1] if identity else _sub(subs, 'value') or item.item.rsplit('\\', 1)[-1]
    program_value = _sub(subs, 'program')
    path, status = _program(program_value)
    arguments = _sub(subs, 'arguments')
    if program_value and not path:
        # A command, not a path: it all goes into the arguments.
        arguments = ' '.join(part for part in (program_value, arguments) if part)
    return _entry('spor_run', name=name, attributes=item.tag_list[0], filepath=path, arguments=arguments,
                  file_not_signed=_unsigned(status))


def _service(item, subs):
    target = sl.path_at(item.rest) or _program(_sub(subs, 'program'))[0]
    status = sl.status_after(item.rest, target) if target else ''
    dll_value = _sub(subs, 'dll')
    if dll_value and ntpath.basename(target).lower() == 'svchost.exe':
        # A 7045 line names svchost.exe and its ServiceDll on a dll: line, a
        # registry line the DLL itself: both give the same entry.
        target, status = _program(dll_value)
    return _entry('spor_service', name=item.item, attributes=item.tag_list[0], filepath=target,
                  file_not_signed=_unsigned(status))


def _task(item, subs):
    program_value = _sub(subs, 'program')
    path, status = _program(program_value)
    arguments = _sub(subs, 'arguments')
    if program_value and not path:
        arguments = ' '.join(part for part in (program_value, arguments) if part)
    return _entry('spor_task', name=item.item, filepath=path, arguments=arguments, file_not_signed=_unsigned(status))


def _startup(item, subs):
    if not sl.is_path(item.item):
        return None
    target = sl.path_at(_sub(subs, 'target'))
    return _entry('spor_startup', filepath=item.item, name=_path(target).lower(), file_not_signed=_unsigned(item.status))


def _parent_name(rest):
    """The nearest parent of a RUNNING PROCESSES line ("parent X (pid) < ..."),
    lowercased, without its pid; '' when it is gone, unknown or none."""
    first = rest[len('parent '):]
    for mark in (' < ', '; '):
        cut = first.find(mark)
        if cut != -1:
            first = first[:cut]
    first = first.strip()
    m = _PARENT_WAS_RE.match(first)
    if m:
        return m.group(1).strip().lower()
    if _PARENT_GONE_RE.match(first) or first in ('unknown', 'none'):
        return ''
    m = _PARENT_PID_RE.match(first)
    return (m.group(1) if m else first).strip().lower()


def _process(item, _subs_found):
    if not sl.is_path(item.item):
        return None
    return _entry('spor_process', filepath=item.item, name=_parent_name(item.rest),
                  file_not_signed=_unsigned(item.status))


def _installer(item, _subs_found):
    event = item.item.split(':', 1)[0].lower()
    details, _unlabelled = sl.parse_labelled(item.rest, sl.SOFTWARE_LABELS)
    name = details.get('name', '')
    product_code = details.get('product code', '').strip().strip('{}')
    if not name and not product_code:
        return None
    return _entry('spor_installer', name=name, clsid=product_code, attributes=event)


def _cached_msi(item, _subs_found):
    """A cached Windows Installer package Spor flags (Spor 0.8.0, SOFTWARE):
    "C:\\Windows\\Installer\\x.msi [status] => name N; version V; publisher P;
    product code {GUID}". The cached file's name is random, and so may be its
    signature state (Windows caches a changed copy): neither is part of it."""
    details, _unlabelled = sl.parse_labelled(item.rest, sl.SOFTWARE_LABELS)
    name = details.get('name', '')
    product_code = details.get('product code', '').strip().strip('{}')
    if not name and not product_code:
        return None
    return _entry('spor_cached_msi', name=name, company=details.get('publisher', ''), clsid=product_code)


def _software(item, _subs_found):
    program, status, rest = sl._split_program(item.rest)
    details, _unlabelled = sl.parse_labelled(rest, sl.SOFTWARE_LABELS)
    scope = item.tag_list[0]
    return _entry(
        'spor_software',
        name=item.item,
        company=details.get('publisher', ''),
        filepath=program if sl.is_path(program) else '',
        file_not_signed=_unsigned(status),
        is_hidden=details.get('hidden', '').lower() == 'yes',
        attributes='user' if scope.startswith('user ') else scope,
    )


def _package(item, subs):
    m = _PACKAGE_RE.match(item.item)
    if not m:
        return None
    signer = _SIGNER_NOTE_RE.sub('', _sub(subs, 'signer'))
    return _entry('spor_package', name=f'{m.group(1)}_{m.group(2)}', company='' if signer == '-' else signer)


def _file(text):
    parsed = sl._parse_files_line(0, text)
    if parsed is None or 'signature' not in parsed.details:
        return None
    signature = parsed.signature
    return _entry('spor_file', filepath=parsed.path, company=parsed.details.get('signer', ''),
                  attributes=signature, file_not_signed=signature == 'unsigned')


def _parse_item(item, texts):
    """The entry of a block whose item line is split into `item`."""
    if not item.trusted:
        return None
    subs = _subs(texts[1:])
    tags = item.tag_list
    if not tags:
        if not item.time and ' => ' in texts[0]:
            return _file(texts[0])
        return None
    if sl.defender_threat(item.item):
        return _entry('spor_defender', name=sl.defender_threat(item.item))
    # PERSISTENCE kinds are lower case; TIMELINE sources ("[RUN]" Run dialog) are not.
    kind = tags[0]
    if kind in _RUN_KINDS:
        return _run(item, subs)
    if kind in _SERVICE_KINDS:
        return _service(item, subs)
    if kind == 'task':
        if len(tags) > 1 and tags[1].isdigit():
            return None     # a Task Scheduler event, not the task
        return _task(item, subs)
    if kind == 'startup':
        return _startup(item, subs)
    if len(tags) != 1:
        return None
    tag = tags[0]
    if tag == 'cached msi':
        return _cached_msi(item, subs)
    if tag in _EXCLUSION_KINDS:
        value = item.item.strip()
        if not value:
            return None
        if sl.is_path(value):
            return _entry('spor_defender_exclusion', attributes=tag, filepath=sl.folder_path(value))
        return _entry('spor_defender_exclusion', attributes=tag, name=value)
    if tag.isdigit():
        if item.rest.startswith('parent '):
            return _process(item, subs)
        if tag in _INSTALLER_EVENTS and item.item.startswith(_INSTALLER_PREFIXES):
            return _installer(item, subs)
        return None
    if _SOFTWARE_SCOPE_RE.match(tag):
        return _software(item, subs) if item.rest else None
    if _PACKAGE_OPERATION_RE.match(tag):
        return _package(item, subs)
    return None


def _is_item_text(text):
    return bool(text) and not text.startswith(('(', '---', '='))


def parse_block(lines):
    """The FrstEntry of a Spor block, or None. `lines` are its stripped lines:
    the item line first, then its sub-lines ("program: C:\\x.exe")."""
    if not lines or not _is_item_text(lines[0]):
        return None
    return _parse_item(split(lines[0]), list(lines))


def _clean_path(path):
    path = path.split('->', 1)[0].strip()        # Defender: "x.zip->inner.exe" is the archive
    return sl.folder_path(path)


def _item_path(item):
    if not item.trusted:
        return ''
    if sl.is_path(item.item):
        return _clean_path(sl.path_at(item.item) or item.item)
    return _clean_path(sl.path_at(item.rest))


def line_path(text, *, sub_line=None):
    """The one path a stripped Spor line names, '' for none: an item line's
    item, else its target; a sub-line's value ("loaded: C:\\x.dll"). With
    `sub_line` None the "key: value" shape decides."""
    text = (text or '').strip()
    if sub_line is None:
        sub_line = bool(_SUB_RE.match(text))
    if sub_line:
        m = _SUB_RE.match(text)
        return _clean_path(sl.path_at(m.group(2) or '')) if m else ''
    if not _is_item_text(text):
        return ''
    return _item_path(split(text))


# Sub-lines that name another file than their entry's: items of their own.
# (A FILES line's "file: md5 ...; size ..." names no path, and is a detail.)
_OTHER_FILE_KEYS = frozenset({
    'file', 'process', 'resource', 'dll', 'module', 'loaded', 'path', 'script', 'files', 'folder',
    'action', 'exe', 'icon file', 'argument file', 'item list target', 'group',
})


def is_entry_line(text, *, sub_line):
    """Whether a stripped line of a Spor block is part of the block's entry:
    the item line, and sub-lines with its details (`program:`, `arguments:`,
    `value:`, `signer:`, `key:`, ...). A sub-line naming another file
    (`file:`, `dll:`, `module:`, `loaded:`, `folder:`) is not: it is an item
    of its own, with its own path."""
    if not sub_line:
        return True
    m = _SUB_RE.match((text or '').strip())
    if not m or m.group(1) not in _OTHER_FILE_KEYS:
        return True
    return not line_path(text, sub_line=True)


def log_version(texts):
    """(major, minor, patch) of the Spor banner among the first lines, or None."""
    for text in texts[:5]:
        m = _VERSION_RE.match(text.lstrip('\ufeff'))
        if m:
            return tuple(int(part) for part in m.groups())
    return None


class SporLines(NamedTuple):
    entries_by_block: dict      # block id -> (FrstEntry,)
    path_by_index: list         # analyzed-line index -> path or ''
    in_entry: list              # analyzed-line index -> part of its block's entry (is_entry_line)


def analyze_lines(walked, structure):
    """The Spor entry of every block and the path of every line of a log.
    `walked` is log_layout.analyzed_lines, `structure` its layout (Spor).
    A log of a Spor version before MIN_VERSION gets neither."""
    count = len(walked)
    paths = [''] * count
    in_entry = [True] * count
    entries = {}
    version = log_version([item.text for item in walked])
    if version is not None and version < MIN_VERSION:
        return SporLines(entries, paths, in_entry)
    for block, indexes in log_layout.block_members(structure).items():
        first = indexes[0]
        texts = [walked[index].text for index in indexes]
        if _is_item_text(texts[0]) and not walked[first].raw[:1].isspace():
            item = split(texts[0])
            paths[first] = _item_path(item)
            entry = _parse_item(item, texts)
            if entry is not None:
                entries[block] = (entry,)
        for index in indexes[1:]:
            text = walked[index].text
            paths[index] = line_path(text, sub_line=True)
            in_entry[index] = is_entry_line(text, sub_line=True)
    return SporLines(entries, paths, in_entry)
