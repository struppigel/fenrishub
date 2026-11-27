"""Links between the lines of one Spor log: every line that names a file (or
a persistence entry, an installed program) gets the other lines of the same
log about it, so the Run key line shows the file's FILES line, its timeline
entries and its Defender detection.

What the log says is read once (spor_source.build: the same SporFacts the
FRST lines of a case get through forward.py); the entries of each line are
collected like any line's (collector.LineEntries: each line once, under its
strongest match). Kinds of links (`match` of an entry, entries.MATCH_NOTES):
- none: the same file (path key) in another section;
- 'registry' / 'service' / 'task' / 'uninstall' / 'msi': the same Run value,
  service, task or installed program by name (a Task Scheduler event and the
  task, a 7045 install and the service, a Windows Installer event and the
  Uninstall entry, a TIMELINE [INS] line and its SOFTWARE line);
- 'summary': a SUMMARY line and the section line it sums up;
- 'detail' / 'named_by': a file named in a line's details (command line,
  parent, "padded file X", "side-loads x.dll") and the other way round;
- in_folder / 'inside': a Defender-excluded folder, an install folder or a
  package folder and the files inside it named in the log;
- 'sibling' / 'same_hash' / 'name': a detected file in the same folder, a
  copy with the same SHA256, a file of the same uncommon name;
- 'loads' / 'loaded_by': a program's PREFETCH line and the lines of the files
  its "loaded:" sub-lines name, and the other way round (a dropper and the
  Node.js it unpacked, an injected charmap.exe and its malware's library).
A program a prefetch entry knows by name only ("CHARMAP.EXE") links its
PREFETCH and TIMELINE lines as 'name' (spor_source.pfname_key; no status:
the name alone does not make two programs one file).
'host' marks a host program (cmd.exe, rundll32.exe, ...) named on many lines;
not one whose lines say malware was injected into it (!injection-host).

Only the same file, a copy and the summary / detail pair give a line a status
(self_status), and only a strong one: a Defender detection, !known-malware, a
strong flag or a signature that does not hold (B / P / !). Everything else
informs. Pure: the log's text only, nothing from the database.
"""

import logging
import threading
from collections import OrderedDict

from .. import spor_log
from ..correlation_keys import MATCH_HOST, is_host_of_line, is_host_program, is_path_key
from ..status_types import dominant_status
from .collector import MAX_INSIDE_ENTRIES, MAX_RELATED_PER_LINE, LineEntries
from .entries import (
    FLAGGED_STATUSES, MATCH_DETAIL, MATCH_INSIDE, MATCH_LOADED_BY, MATCH_LOADS, MATCH_NAME, MATCH_NAMED_BY,
    MATCH_NAMED_LIKE, MATCH_SAME_HASH, MATCH_SIBLING, MATCH_SUMMARY, finding_status,
)
from .folders import is_broad_folder
from .related import _EMPTY_SHA256, _RelatedIndex, _both_installed
from .spor_source import PFNAME_PREFIX, build

logger = logging.getLogger(__name__)


# A typed key's prefix -> the match of the entries found through it.
_TYPED_MATCHES = {'run': 'registry', 'svc': 'service', 'task': 'task', 'uninstall': 'uninstall', 'msi': 'msi'}
# The links whose entries may give a line its status, and the statuses they may give.
RATING_MATCHES = frozenset({None, MATCH_SAME_HASH, MATCH_SUMMARY})
SELF_STATUSES = frozenset({'B', 'P', '!'})


def _key_match(key, flagged=frozenset(), injected=frozenset()):
    """The match of entries found through `key`: none for a file, 'host' for
    a host program (see _is_host), 'name' for a program known by name only
    (informational: two programs named SETUP.EXE in different folders are not
    one file), the typed match for a typed key ('' for others)."""
    if is_path_key(key):
        return MATCH_HOST if _is_host(key, flagged, injected) else None
    if key.startswith(PFNAME_PREFIX):
        return MATCH_NAME
    return _TYPED_MATCHES.get(key.split(':', 1)[0], '')


def _is_host(key, flagged, injected=frozenset()):
    """A command-line host (cmd.exe, wscript.exe, ... in its Windows folder:
    its lines' flags are about what it runs) always, unless a line says
    malware was injected into it (dllhost.exe with !injection-host: that is
    about the process itself); another Windows binary only while no line of
    the log has a strong finding about it (a fake System32\\x.exe is a file
    like any other)."""
    if key in injected:
        return False
    return is_host_of_line(key) or (key not in flagged and is_host_program(key))


def _injected_keys(index):
    """The path keys of programs a line of the log flags !injection-host."""
    return {
        key for key, entries in index.items()
        if is_path_key(key) and any(spor_log.INJECTION_HOST_FLAG in (entry.get('flags') or ()) for entry in entries)
    }


def _rates(entry, extra):
    return (entry.get('kind') != 'reverse' and extra.get('match', entry.get('match')) in RATING_MATCHES
            and not extra.get('in_folder', entry.get('in_folder')))


def rates(entry):
    """True for an entry that may give its line a status (see the docstring)."""
    return isinstance(entry, dict) and _rates(entry, {})


def rating_status(entry):
    """The strong status (B / P / !) an entry gives its line, '' for none."""
    if not rates(entry):
        return ''
    status = finding_status(entry)
    return status if status in SELF_STATUSES else ''


def self_status(entries):
    """The worst strong status (B / P / !) of a line's self links, '' for none."""
    return dominant_status([rating_status(entry) for entry in entries or ()], default='')


def _status(collector):
    return dominant_status([
        status for status in (finding_status(entry) for entry, extra in collector.links if _rates(entry, extra))
        if status in SELF_STATUSES
    ], default='')


def notable(entry):
    """True for an entry of a line worth a marker: a finding or a flag (hints
    included), a signature that does not hold or is missing, a file gone."""
    if entry.get('severity') in ('b', 'p', 'w', 'g', 'i'):
        return True
    if any(flag not in spor_log.QUIET_FLAGS for flag in entry.get('flags') or ()):
        return True
    if entry.get('signature') in ('unsigned', 'invalid', 'revoked', 'expired'):
        return True
    words = spor_log.status_words(entry.get('file_status') or '')
    return any(word in ('gone', 'unsigned') or word in spor_log.BAD_SIGNATURE_STATUSES for word in words)


def _sort_key(entry):
    """Rating entries first, then in line order."""
    return (not rates(entry), entry['line_no'])


class SelfLinks:
    """The links of one Spor log. `codes` ({line no (str): code}) is what the
    log page needs up front: the line's status letter (B / P / !), 'm' for a
    neutral marker (the line or a linked line is notable), '' for a line whose
    links show from its hover icons only. `entries(no)` gives one line's
    entries (the info box asks for them when it opens): a big log links
    thousands of lines, too much to put into its page."""

    def __init__(self, links, notable_lines):
        self._links = {no: collector for no, collector in links.items() if collector.links}
        self.codes = {}
        for no, collector in self._links.items():
            marked = no in notable_lines or any(entry['line_no'] in notable_lines for entry, _extra in collector.links)
            self.codes[str(no)] = _status(collector) or ('m' if marked else '')

    def entries(self, no):
        """The entries of a line (str or int), [] for one without links."""
        no = str(no)
        collector = self._links.get(int(no)) if no.isdigit() else None
        return collector.finish(key=_sort_key) if collector is not None else []

    def linked_hashes(self):
        """{line no (str): {hash}}: the SHA-256 (else the MD5) of each FILES
        line a line links to, for its lookup icon (whether the info box can
        look one up on centralbox)."""
        found = {}
        for no, collector in self._links.items():
            hashes = {
                entry.get('sha256') or entry.get('md5') for entry, _extra in collector.links
                if entry.get('kind') == 'file_info'
            } - {'', None}
            if hashes:
                found[str(no)] = hashes
        return found

    def as_dict(self):
        """{line no (str): [entry]} of every linked line."""
        return {str(no): collector.finish(key=_sort_key) for no, collector in self._links.items()}


# The links of the logs looked at last, per worker process: the info box asks
# for one line at a time. Keyed by the log's content hash, so an edit of the
# log is never answered from an old copy.
_CACHE_SIZE = 3
_cache = OrderedDict()
_cache_lock = threading.Lock()


def _cache_key(uploaded_log):
    return (uploaded_log.pk, uploaded_log.content_hash or '')


def is_cached(uploaded_log):
    """True when this worker process has the log's SelfLinks already (for_upload
    answers at once, without reading the log)."""
    with _cache_lock:
        return _cache_key(uploaded_log) in _cache


def for_upload(uploaded_log):
    """The SelfLinks of a Spor log, from the cache when it has them. Never
    raises (None on an error)."""
    key = _cache_key(uploaded_log)
    with _cache_lock:
        found = _cache.get(key)
        if found is not None:
            _cache.move_to_end(key)
            return found
    try:
        found = compute(uploaded_log.upload_id, uploaded_log.content or '')
    except Exception:
        logger.exception('Spor self links failed for %s', getattr(uploaded_log, 'upload_id', '?'))
        return None
    with _cache_lock:
        _cache[key] = found
        _cache.move_to_end(key)
        while len(_cache) > _CACHE_SIZE:
            _cache.popitem(last=False)
    return found


def self_links(upload_id, content):
    """{line no (str): [entry]} of a Spor log: for each line, the entries of
    the other lines of the log about its files and entries (see the module
    docstring), rating entries first. Empty for a log without any."""
    return compute(upload_id, content).as_dict()


def compute(upload_id, content):
    """The SelfLinks of a Spor log's text."""
    facts = build(upload_id, (content or '').split('\n'))
    index = facts.index
    links = {}

    def at(no):
        if no not in links:
            links[no] = LineEntries(own=(upload_id, no))
        return links[no]

    for no, partners in facts.partners.items():
        for partner in partners:
            at(no).add(partner, MATCH_SUMMARY)
    flagged = _flagged_keys(index)
    injected = _injected_keys(index)
    # The same file / entry elsewhere in the log.
    for no, keys in facts.by_line.items():
        collector = at(no)
        for key in keys:
            match = _key_match(key, flagged, injected)
            if match == '':
                continue
            for entry in index[key]:
                collector.add(entry, match)
    related = _RelatedIndex(index)
    _add_folders(index, related, at)
    _add_details(facts, at)
    _add_loads(facts, at)
    _add_named_like(index, facts.by_line, at)
    for no, keys in facts.by_line.items():
        for key in keys:
            if is_path_key(key) and not _is_host(key, flagged, injected) and not _is_folder_key(index, key, no):
                _add_related(at(no), related, key, flagged)

    notable_lines = {
        entry['line_no'] for entries in index.values() for entry in entries
        if entry.get('line_no') and not entry.get('folder') and notable(entry)
    }
    return SelfLinks(links, notable_lines)


def _is_folder_key(index, key, no):
    """True when the line's entry under `key` is a folder entry."""
    return any(entry.get('folder') for entry in index[key] if entry.get('line_no') == no)


def _add_folders(index, related, at):
    """A Defender-excluded, install or package folder and the files inside
    it named in the log: the files get the folder's lines (in_folder), the
    folder's lines get the files' ones ('inside', at most MAX_INSIDE_ENTRIES)."""
    for key, entries in index.items():
        folders = [entry for entry in entries if entry.get('folder')]
        if not folders or not is_path_key(key) or is_broad_folder(key):
            continue
        listed = {}
        for path, inside in related.inside(key):
            for entry in inside:
                if entry.get('folder'):
                    continue
                for folder in folders:
                    at(entry['line_no']).add(folder, in_folder=True)
                    count = listed.get(folder['line_no'], 0)
                    if count < MAX_INSIDE_ENTRIES:
                        listed[folder['line_no']] = count + at(folder['line_no']).add(
                            entry, MATCH_INSIDE, other_path=path,
                        )


def _add_details(facts, at):
    """Files named in a line's details: the line gets their lines ('detail'),
    their lines get the naming line ('named_by')."""
    for no, keys in facts.names.items():
        for key in keys:
            for entry in facts.index[key]:
                if not entry.get('folder'):
                    at(no).add(entry, MATCH_DETAIL, other_path=entry.get('path') or key)
    for key, naming in facts.named_in.items():
        for entry in facts.index[key]:
            if entry.get('folder'):
                continue
            for mine in naming:
                at(entry['line_no']).add(mine, MATCH_NAMED_BY)


def _add_loads(facts, at):
    """A PREFETCH line and the files its program loaded: the line gets their
    other lines ('loads', at most MAX_INSIDE_ENTRIES: a fake Python loads a
    hundred library files), their lines get the program's line ('loaded_by').
    Not the "loaded:" sub-lines of the same block: they are under the line."""
    for no, keys in facts.loads.items():
        own_subs = facts.loaded_subs.get(no, set())
        added = 0
        for key in keys:
            for entry in facts.index[key]:
                if added >= MAX_INSIDE_ENTRIES:
                    break
                if entry.get('folder') or entry.get('line_no') in own_subs:
                    continue
                added += at(no).add(entry, MATCH_LOADS, other_path=entry.get('path') or key)
    for key, owners in facts.loaded_in.items():
        for entry in facts.index[key]:
            if entry.get('folder') or not entry.get('line_no'):
                continue
            for mine, subs, program in owners:
                if entry['line_no'] in subs or entry['line_no'] == mine.get('line_no'):
                    continue
                at(entry['line_no']).add(mine, MATCH_LOADED_BY, other_path=mine.get('path') or program)


# A persistence name that links to a folder of the same name: long enough not
# to be a word every PC has, and not a broad folder ("Microsoft", "Common Files").
_MIN_NAMED_LIKE = 6
_NOT_NAMED_LIKE = frozenset({
    'windows', 'system32', 'syswow64', 'program files', 'program files (x86)', 'programdata', 'appdata',
    'microsoft', 'common files', 'roaming', 'local', 'locallow', 'temp', 'users', 'public', 'default',
    'drivers', 'updater', 'update', 'service', 'services', 'launcher',
})


def _identity_name(key):
    """The name a typed persistence key stands for, as a folder would be
    named: a task's last part, a service's or Run value's name; '' else."""
    kind, _sep, value = key.partition(':')
    if kind == 'task':
        value = value.rsplit('\\', 1)[-1]
    elif kind not in ('svc', 'run'):
        return ''
    value = value.strip()
    return value if len(value) >= _MIN_NAMED_LIKE and value not in _NOT_NAMED_LIKE else ''


def _add_named_like(index, by_line, at):
    """A task, service or Run value that runs no file of its own (a bare
    "powershell", or only a host program: cmd, wscript, ...) and a file in a
    folder of its name ('named_like', both ways; informational): malware names
    its folder like its task ("\\Microsoft\\Windows\\Guard\\HealthCheck-x1"
    runs powershell, which starts "C:\\Windows\\System32\\HealthCheck-x1\\
    node.exe"). An entry that runs a program in its own folder (a Run value
    "Discord" and Discord's folder) says nothing new. One file per folder, at
    most MAX_RELATED_PER_LINE folders."""
    folders = {}
    for key, entries in index.items():
        # only a file with a line of its own (not a folder-only key) can stand for its folder
        if not is_path_key(key) or not any(not e.get('folder') and e.get('line_no') for e in entries):
            continue
        parts = key.split('\\')
        for depth in range(1, len(parts) - 1):
            part = parts[depth]
            if len(part) >= _MIN_NAMED_LIKE and part not in _NOT_NAMED_LIKE:
                # The folder itself, and the first file the log names in it.
                folders.setdefault(part, {}).setdefault('\\'.join(parts[:depth + 1]), key)
    if not folders:
        return
    for key, entries in index.items():
        name = '' if is_path_key(key) else _identity_name(key)
        found = folders.get(name) if name else None
        if not found:
            continue
        mine = [entry for entry in entries if entry.get('line_no')]
        if any(is_path_key(other) and not is_host_of_line(other)
               for entry in mine for other in by_line.get(entry['line_no'], ())):
            continue
        for path in list(found.values())[:MAX_RELATED_PER_LINE]:
            first = next((entry for entry in index[path] if not entry.get('folder') and entry.get('line_no')), None)
            if first is None:
                continue
            for entry in mine:
                at(entry['line_no']).add(first, MATCH_NAMED_LIKE, other_path=first.get('path') or path)
            # The file's line gets the entry's lines (a few: a service installed again and again).
            for entry in mine[:MAX_RELATED_PER_LINE]:
                at(first['line_no']).add(entry, MATCH_NAMED_LIKE)


def _flagged_keys(index):
    """The path keys of files with a strong finding somewhere in the log."""
    return {
        key for key, entries in index.items()
        if is_path_key(key) and any(
            not entry.get('folder') and finding_status(entry) in SELF_STATUSES for entry in entries
        )
    }


def _add_related(collector, related, key, flagged):
    """Detected files in the same folder, copies (same SHA256) and files of
    the same uncommon name, as related.add_related does across logs (FILES
    lines are this log's hash rows). A Spor log lists thousands of files
    (game and app folders with the same DLLs), so copies and names count only
    when one of the two files has a strong finding (`flagged`)."""
    added = 0
    for path, entry in related.siblings(key):
        if added >= MAX_RELATED_PER_LINE:
            break
        added += collector.add(entry, MATCH_SIBLING, other_path=path)
    mine = key in flagged
    for path in related.same_content(key)[:MAX_RELATED_PER_LINE]:
        if not mine and path not in flagged:
            continue
        for entry in related.index.get(path, ()):
            # The copy's FILES line and detections, and every other line about
            # it with a strong finding (its !known-malware timeline line).
            if entry.get('folder') or (entry['kind'] not in ('file_info', 'detection')
                                       and finding_status(entry) not in SELF_STATUSES):
                continue
            if entry['kind'] == 'file_info' and entry.get('sha256') == _EMPTY_SHA256:
                continue
            if _both_installed(key, path) and finding_status(entry) not in FLAGGED_STATUSES:
                continue
            collector.add(entry, MATCH_SAME_HASH, other_path=path)
    added = 0
    for path in related.same_name(key):
        if _both_installed(key, path) or (not mine and path not in flagged):
            continue
        for entry in related.index.get(path, ()):
            if added >= MAX_RELATED_PER_LINE:
                return
            if not entry.get('folder'):
                added += collector.add(entry, MATCH_NAME, other_path=path)
