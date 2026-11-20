"""Links between the lines of one Spor log: every line that names a file (or
a persistence entry, an installed program) gets the other lines of the same
log about it, so the Run key line shows the file's FILES line, its timeline
entries and its Defender detection.

Kinds of links (`match` of an entry, as in case_correlations):
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
  copy with the same SHA256, a file of the same uncommon name.
'host' marks a host program (cmd.exe, rundll32.exe, ...) named on many lines.

Only the same file, a copy and the summary / detail pair give a line a status
(self_status), and only a strong one: a Defender detection, !known-malware, a
strong flag or a signature that does not hold (B / P / !). Everything else
informs. Pure: the log's text only, nothing from the database.
"""

import logging
import ntpath
import re
import threading
from collections import OrderedDict

from . import spor_log
from .case_correlations import (
    FLAGGED_STATUSES, MATCH_INSIDE, MATCH_NAME, MATCH_SAME_HASH, MATCH_SIBLING, MAX_ENTRIES_PER_LINE,
    MAX_INSIDE_ENTRIES, MAX_RELATED_PER_LINE, _EMPTY_SHA256, _RelatedIndex, _both_installed, _plain_mention,
    defender_severity, evidence_severity, file_name, finding_status, is_broad_folder, spor_log_entries,
)
from .correlation_keys import MATCH_HOST, argument_paths, is_host_program, is_path_key, msi_key, software_keys
from .file_hashes import normalized_path
from .log_types import LOG_TYPE_SPOR
from .status_types import dominant_status

logger = logging.getLogger(__name__)

MATCH_SUMMARY = 'summary'
MATCH_DETAIL = 'detail'
MATCH_NAMED_BY = 'named_by'
# A typed key's prefix -> the match of the entries found through it.
_TYPED_MATCHES = {'run': 'registry', 'svc': 'service', 'task': 'task', 'uninstall': 'uninstall', 'msi': 'msi'}
# The links whose entries may give a line its status, and the statuses they may give.
RATING_MATCHES = frozenset({None, MATCH_SAME_HASH, MATCH_SUMMARY})
SELF_STATUSES = frozenset({'B', 'P', '!'})
# A file named by its bare name in a line's details: it is in the folder of
# the line's own file ("side-loads providers.dll", "loaded by host.exe").
_BARE_NAME_RE = re.compile(
    r'(?:side-loads|loaded by|forwards to|imported by) ([^\s;,()\\/:"<>|]{1,120}\.[A-Za-z0-9]{1,5})(?=[\s;,()]|$)'
)
# Sections whose lines name no other files in their details.
_NO_DETAIL_SECTIONS = frozenset({spor_log.SECTION_FILES, spor_log.SECTION_AMCACHE_FILES})


def _key_match(key):
    """The match of entries found through `key`: none for a file, 'host' for
    a host program, the typed match for a typed key ('' for others)."""
    if is_path_key(key):
        return MATCH_HOST if is_host_program(key) else None
    return _TYPED_MATCHES.get(key.split(':', 1)[0], '')


def _item_severity(item):
    """The severity of an item line: its Defender threat's, else its flags'
    and signature's (case_correlations.evidence_severity)."""
    threat = spor_log.defender_threat(item.item)
    if threat:
        return defender_severity(threat)
    return evidence_severity(item.flags, item.status)


def _main_key(item):
    """The key of the file an item line is about, '' for none: the Defender
    detection's file, the item, else the first file the item names."""
    if spor_log.defender_threat(item.item):
        paths = spor_log.defender_paths(item.rest)
        return normalized_path(paths[0]) if paths else ''
    if spor_log.is_path(item.item):
        return normalized_path(item.item)
    found = argument_paths(item.item)
    return found[0] if found else ''


def _file_of(index, key):
    """The file name of a key as the log spells it (lowercased if unknown)."""
    for entry in index.get(key, ()):
        if entry.get('file') and not entry.get('folder'):
            return entry['file']
    return ntpath.basename(key.rstrip('\\'))[:120]


class _Links:
    """The entries of one line: each other line once per kind (the first
    link wins: the same file before its folder), never the line itself;
    lines already linked as its summary / detail line only through that link."""

    def __init__(self, line_no):
        self.line_no = line_no
        # (shared index entry, {match, in_folder, other_path}): a big log
        # links thousands of lines to the same entries, so they are not copied
        # until a line's entries are asked for (expand).
        self.links = []
        self.seen = set()
        self.paired = set()

    def add(self, entry, match=None, other_path='', in_folder=False):
        no = entry.get('line_no')
        if not no or no == self.line_no or (no in self.paired and match != MATCH_SUMMARY):
            return False
        slot = (no, entry.get('kind'))
        if slot in self.seen:
            return False
        self.seen.add(slot)
        extra = {}
        if match:
            extra['match'] = match
        if in_folder:
            extra['in_folder'] = True
        if other_path:
            extra['other_path'] = other_path[:400]
        self.links.append((entry, extra))
        return True

    def expand(self):
        """The line's entries: rating ones first, then in line order, capped."""
        entries = [{**entry, **extra} if extra else dict(entry) for entry, extra in self.links]
        entries.sort(key=lambda entry: (not rates(entry), entry['line_no']))
        return entries[:MAX_ENTRIES_PER_LINE]

    def status(self):
        return dominant_status([
            status for status in (finding_status(entry) for entry, extra in self.links if _rates(entry, extra))
            if status in SELF_STATUSES
        ], default='')


def _rates(entry, extra):
    return (entry.get('kind') != 'reverse' and extra.get('match', entry.get('match')) in RATING_MATCHES
            and not extra.get('in_folder', entry.get('in_folder')))


def rates(entry):
    """True for an entry that may give its line a status (see the docstring)."""
    return isinstance(entry, dict) and _rates(entry, {})


def self_status(entries):
    """The worst strong status (B / P / !) of a line's self links, '' for none."""
    return dominant_status([
        status for status in (finding_status(entry) for entry in entries or () if rates(entry))
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


def _summary_pairs(upload_id, lines, known, index):
    """Index the SUMMARY lines under their file, and pair each with the
    section line it sums up: [(summary entry, detail entry)]."""
    by_time = {}
    for no, title, item in spor_log.iter_section_items(lines, known):
        if item.time and item.trusted:
            by_time.setdefault(item.time, []).append((no, title, item, _main_key(item)))
    pairs = []
    for no, item in spor_log.iter_summary_items(lines, known):
        if not item.trusted:
            continue
        main = _main_key(item)
        entry = _plain_mention(
            upload_id, LOG_TYPE_SPOR, no, lines[no - 1].strip(), 'item', _file_of(index, main) if main else '',
            section=spor_log.SECTION_SUMMARY, time=item.time, tags=item.tags, severity=_item_severity(item),
        )
        entry['flags'] = item.flags[:10]
        entry['file_status'] = item.status
        if main:
            index.setdefault(main, []).append(entry)
        detail = _detail_line(item, main, by_time.get(item.time, ()) if item.time else ())
        if detail is None:
            continue
        detail_no, title, detail_item, detail_key = detail
        detail_entry = _plain_mention(
            upload_id, LOG_TYPE_SPOR, detail_no, lines[detail_no - 1].strip(), 'details',
            _file_of(index, detail_key) if detail_key else '', section=title, time=detail_item.time,
            tags=detail_item.tags, severity=_item_severity(detail_item),
        )
        detail_entry['flags'] = detail_item.flags[:10]
        detail_entry['file_status'] = detail_item.status
        pairs.append(({**entry, 'role': 'in SUMMARY'}, detail_entry))
    return pairs


def _detail_line(item, main, candidates):
    """The line of a section with the SUMMARY item's time that it sums up:
    for "[timeline ...]" the TIMELINE line with the same text (or file);
    else a line of the section its first tag names, then of any section,
    with the same file, then with the same text. None if there is none."""
    word = item.tags.split()[0].lower() if item.tags else ''
    timeline = [c for c in candidates if c[1] == spor_log.SECTION_TIMELINE]
    if word == 'timeline':
        return (next((c for c in timeline if c[2].text == item.text), None)
                or next((c for c in timeline if main and c[3] == main), None))
    named = [c for c in candidates if word and c[1].lower().startswith(word)]
    for group in (named, candidates):
        found = next((c for c in group if main and c[3] == main), None) or next(
            (c for c in group if c[2].text == item.text), None)
        if found:
            return found
    return None


def _install_entries(upload_id, lines, known, index):
    """TIMELINE [INS] lines ("installed or updated: X => key HKLM\\...\\X")
    under their Uninstall key; Uninstall entries of an MSI product code under
    that code too, so a Windows Installer event finds them."""
    for no, item in spor_log.iter_timeline_items(lines, known):
        if 'INS' not in item.tags.split():
            continue
        details, _unlabelled = spor_log.parse_labelled(item.rest, spor_log.SOFTWARE_LABELS)
        keys = {key for key in software_keys(details.get('key', '')) if key.startswith(('uninstall:', 'msi:'))}
        if not keys:
            continue
        entry = _plain_mention(
            upload_id, LOG_TYPE_SPOR, no, lines[no - 1].strip(), 'item', item.item[:120],
            section=spor_log.SECTION_TIMELINE, time=item.time, tags=item.tags,
            severity=evidence_severity(item.flags, item.status),
        )
        entry['flags'] = item.flags[:10]
        for key in keys:
            index.setdefault(key, []).append(entry)
    for key in [key for key in index if key.startswith('uninstall:{')]:
        code = msi_key(key[len('uninstall:'):])
        if code:
            index.setdefault(code, []).extend(
                entry for entry in index[key] if entry.get('role') == 'uninstall entry'
            )


def _defender_event_entries(upload_id, lines, known, index):
    """Every Defender event line under the files it names: iter_defender_detections
    keeps one line per file and threat (the action taken), the others
    (the detection before it) are lines about the file too."""
    indexed = {entry.get('line_no') for entries in index.values() for entry in entries
               if entry.get('kind') == 'detection'}
    for no, title, item in spor_log.iter_section_items(lines, known):
        threat = spor_log.defender_threat(item.item) if title == spor_log.SECTION_DEFENDER else ''
        if not threat or no in indexed:
            continue
        for path in spor_log.defender_paths(item.rest):
            key = normalized_path(path)
            if not key:
                continue
            entry = {
                'kind': 'detection', 'upload_id': upload_id, 'log_type': LOG_TYPE_SPOR, 'line_no': no,
                'detection': threat[:255], 'action': '', 'severity': defender_severity(threat),
                'source': 'defender', 'file': file_name(path),
            }
            index.setdefault(key, []).append(entry)


def _timeline_entries(upload_id, lines, known, index):
    """Every TIMELINE line of a file under its path: iter_timeline_evidence
    keeps the first (newest or oldest) line per file, the later ones (the
    4688 start of a program a NEW line already shows) are lines about it too."""
    indexed = {entry.get('line_no') for entries in index.values() for entry in entries
               if entry.get('kind') == 'evidence'}
    for no, item in spor_log.iter_timeline_items(lines, known):
        if no in indexed or not spor_log.is_path(item.item):
            continue
        key = normalized_path(item.item)
        if not key:
            continue
        index.setdefault(key, []).append({
            'kind': 'evidence', 'upload_id': upload_id, 'log_type': LOG_TYPE_SPOR, 'line_no': no,
            'time': item.time, 'sources': item.tags[:80], 'file_status': item.status, 'details': item.rest[:200],
            'flags': item.flags[:10], 'severity': evidence_severity(item.flags, item.status),
            'file': file_name(item.item),
        })


def _line_keys(index):
    """{line no: [key]}: the keys each line's entries are indexed under, path
    keys first (a line linked by its file wins over its name)."""
    by_line = {}
    for key, entries in index.items():
        for entry in entries:
            no = entry.get('line_no')
            if no:
                keys = by_line.setdefault(no, [])
                if key not in keys:
                    keys.append(key)
    for keys in by_line.values():
        keys.sort(key=lambda key: not is_path_key(key))
    return by_line


def _detail_keys(item, own):
    """The keys of the files a line names in its details, besides its own:
    full paths (command lines, parents, "padded file X") and bare names in
    the folder of its file."""
    if spor_log.defender_threat(item.item):
        return []   # its file is its own; "process X" is whoever touched it
    # A file item names others after it; an event or registry item anywhere.
    text = item.rest if spor_log.is_path(item.item) else item.text
    keys = [key for key in argument_paths(text) if key not in own]
    main = _main_key(item)
    if main:
        folder = ntpath.dirname(main)
        for name in _BARE_NAME_RE.findall(item.text):
            key = f'{folder}\\{name.lower()}'
            if key not in own and key not in keys:
                keys.append(key)
    return [key for key in keys if not is_host_program(key)]


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
            self.codes[str(no)] = collector.status() or ('m' if marked else '')

    def entries(self, no):
        """The entries of a line (str or int), [] for one without links."""
        no = str(no)
        collector = self._links.get(int(no)) if no.isdigit() else None
        return collector.expand() if collector is not None else []

    def as_dict(self):
        """{line no (str): [entry]} of every linked line."""
        return {str(no): collector.expand() for no, collector in self._links.items()}


# The links of the logs looked at last, per worker process: the info box asks
# for one line at a time. Keyed by the log's content hash, so an edit of the
# log is never answered from an old copy.
_CACHE_SIZE = 3
_cache = OrderedDict()
_cache_lock = threading.Lock()


def for_upload(uploaded_log):
    """The SelfLinks of a Spor log, from the cache when it has them. Never
    raises (None on an error)."""
    key = (uploaded_log.pk, uploaded_log.content_hash or '')
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
    lines = (content or '').split('\n')
    known = spor_log.known_paths(lines)
    index = {}
    spor_log_entries(upload_id, lines, index, known)
    _defender_event_entries(upload_id, lines, known, index)
    _timeline_entries(upload_id, lines, known, index)
    pairs = _summary_pairs(upload_id, lines, known, index)
    _install_entries(upload_id, lines, known, index)
    by_line = _line_keys(index)
    links = {}

    def at(no):
        if no not in links:
            links[no] = _Links(no)
        return links[no]

    for summary, detail in pairs:
        at(summary['line_no']).paired.add(detail['line_no'])
        at(detail['line_no']).paired.add(summary['line_no'])
    for summary, detail in pairs:
        at(summary['line_no']).add(detail, MATCH_SUMMARY)
        at(detail['line_no']).add(summary, MATCH_SUMMARY)

    # The same file / entry elsewhere in the log.
    for no, keys in by_line.items():
        collector = at(no)
        for key in keys:
            match = _key_match(key)
            if match == '':
                continue
            for entry in index[key]:
                collector.add(entry, match)

    related = _RelatedIndex(index)
    _add_folders(index, related, at)
    _add_details(lines, known, index, by_line, at)
    flagged = _flagged_keys(index)
    for no, keys in by_line.items():
        for key in keys:
            if is_path_key(key) and not is_host_program(key) and not _is_folder_key(index, key, no):
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


def _add_details(lines, known, index, by_line, at):
    """Files named in a line's details: the line gets their lines ('detail'),
    their lines get the line's own entries ('named_by')."""
    for no, title, item in spor_log.iter_section_items(lines, known, skip=frozenset({spor_log.SECTION_LEGEND})):
        if title in _NO_DETAIL_SECTIONS or not item.trusted or no not in by_line:
            continue
        own = set(by_line[no])
        own_entries = [entry for key in by_line[no] for entry in index[key]
                       if entry.get('line_no') == no and not entry.get('folder')]
        added = 0
        for key in _detail_keys(item, own):
            if key not in index or added >= MAX_RELATED_PER_LINE:
                continue
            found = False
            for entry in index[key]:
                if entry.get('folder'):
                    continue
                found = at(no).add(entry, MATCH_DETAIL, other_path=_path_of(entry, key)) or found
                for mine in own_entries[:1]:
                    at(entry['line_no']).add(mine, MATCH_NAMED_BY)
            added += found


def _path_of(entry, key):
    return entry.get('path') or key


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
    the same uncommon name, as case_correlations._add_related does across
    logs (FILES lines are this log's hash rows). A Spor log lists thousands
    of files (game and app folders with the same DLLs), so copies and names
    count only when one of the two files has a strong finding (`flagged`)."""
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
