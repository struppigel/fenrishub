"""What a Spor log says, as correlation entries: Defender detections, file
facts (FILES, AMCACHE FILES), mentions in the module sections (under their
path and persistence name), SOFTWARE facts and timeline evidence."""

import logging
import ntpath
import re
from dataclasses import dataclass, field

from .. import spor_log
from ..correlation_keys import (
    argument_paths, identity_key, is_host_program, is_path_key, msi_key, software_keys,
)
from ..file_hashes import normalized_path
from ..log_highlighting import defender_severity
from ..log_types import LOG_TYPE_SPOR
from ..models import UploadedLog
from .collector import MAX_RELATED_PER_LINE
from .entries import (
    _add_defender_entries, _add_folder_entry, _add_path_entry, _file_info_entry, _mention_entry, _plain_mention,
    evidence_severity, file_name,
)

logger = logging.getLogger(__name__)


# A FILES "<name> <value>" part -> the file_info key it is stored under.
_FILES_FACT_KEYS = {
    'signature': 'signature', 'signer': 'signer', 'thumbprint': 'thumbprint', 'note': 'note',
    'file version': 'version', 'description': 'description', 'product': 'product', 'company': 'company',
    'original name': 'original_name', 'amcache sha1': 'sha1', 'md5': 'md5', 'size': 'size',
    'created': 'created', 'modified': 'modified',
}


def _spor_file_infos(upload_id, lines):
    """(path, file_info entry) of a Spor log's FILES and AMCACHE FILES lines."""
    for parsed in spor_log.iter_file_lines(lines):
        facts = {_FILES_FACT_KEYS[name]: value for name, value in parsed.details.items() if name in _FILES_FACT_KEYS}
        if 'signature' in facts:
            facts['signature'] = parsed.signature
        sha1 = facts.pop('sha1', '')
        md5 = facts.pop('md5', '')
        value = parsed.hash
        hashes = {'sha256': value if len(value) == 64 else '', 'md5': value if len(value) == 32 else md5,
                  'sha1': value if len(value) == 40 else sha1}
        if parsed.status:
            facts['file_status'] = parsed.status
        bad = parsed.signature in spor_log.BAD_SIGNATURES or spor_log.is_bad_signature(parsed.status)
        yield parsed.path, _file_info_entry(upload_id, LOG_TYPE_SPOR, parsed.line_no, parsed.path, 'spor_files', facts,
                                            hashes, 'w' if bad else '')
    for line_no, path, sha1 in spor_log.iter_amcache_files(lines):
        yield path, _file_info_entry(upload_id, LOG_TYPE_SPOR, line_no, path, 'spor_amcache', {}, {'sha1': sha1})


SOFTWARE_ROLES = {'uninstall': 'uninstall entry', 'installer': 'installer event', 'package': 'package'}


def _software_entries(upload_id, lines, index):
    """Spor's SOFTWARE facts: an Uninstall entry under its key (Addition's
    Installed Programs line) and its install folder; a Windows Installer
    event under its MSI product code; a Store / MSIX package under its folder
    (Addition's Packages line, and the files inside)."""
    for fact in spor_log.iter_software(lines):
        details = fact.details
        entry = {
            'kind': 'mention', 'upload_id': upload_id, 'log_type': LOG_TYPE_SPOR, 'line_no': fact.line_no,
            'section': spor_log.SECTION_SOFTWARE, 'subsection': fact.subsection[:160], 'time': fact.time,
            'tags': fact.tags[:80], 'text': fact.text[:300], 'role': SOFTWARE_ROLES[fact.kind], 'parent': '',
            'file_status': fact.status, 'flags': fact.flags[:10], 'extra': [],
            # Packages by their full name: not every operation names the app.
            'severity': evidence_severity(fact.flags, fact.status),
            'file': (details.get('package') or fact.name)[:120],
        }
        if fact.kind == 'uninstall':
            # Its Uninstall key only: the Windows Installer events stand for
            # the MSI product code.
            for key in software_keys(details.get('key', '')):
                if key.startswith('uninstall:'):
                    index.setdefault(key, []).append(entry)
            if details.get('folder'):
                _add_folder_entry(index, details['folder'], entry)
        elif fact.kind == 'installer':
            key = msi_key(details.get('product code', ''))
            if key:
                index.setdefault(key, []).append(entry)
        elif details.get('folder'):
            _add_folder_entry(index, details['folder'], entry)


def _spor_entries(upload_ids, index, spor_logs=None, facts=None):
    """What the related Spor logs say (build), merged into `index`. (Their
    FILES hashes are hash rows too: _hash_entries; sources.merge_same_line
    makes one entry of the two.) Keeps (upload_id, lines, known paths) of
    each in `spor_logs` when given, for their timeline events
    (_spor_timeline_events), and their SporFacts in `facts` {upload_id: ...}
    for the links forward.py adds through them."""
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type=LOG_TYPE_SPOR).only('pk', 'upload_id', 'content'):
        lines = (upload.content or '').split('\n')
        known = spor_log.known_paths(lines)
        if spor_logs is not None:
            spor_logs.append((upload.upload_id, lines, known))
        try:
            found = build(upload.upload_id, lines, known)
        except Exception:
            # One odd Spor log costs its own entries, never the other logs' of the case.
            logger.exception('Reading Spor log %s for correlations failed', upload.upload_id)
            continue
        if facts is not None:
            facts[upload.upload_id] = found
        for key, entries in found.index.items():
            index.setdefault(key, []).extend(entries)


def spor_log_entries(upload_id, lines, index, known=None):
    """What one Spor log says, into `index` ({key: [entry]}): Defender
    detections, file facts (FILES, AMCACHE FILES), mentions in the module
    sections (under their path and persistence name), SOFTWARE facts and
    timeline evidence. Pure: the log's lines only (spor_self.py reads a
    log's own lines with it too)."""
    if known is None:
        known = spor_log.known_paths(lines)
    _add_defender_entries(index, upload_id, LOG_TYPE_SPOR, spor_log.iter_defender_detections(lines))
    for path, entry in _spor_file_infos(upload_id, lines):
        _add_path_entry(index, path, entry)
    for mention in spor_log.iter_mentions(lines, known):
        entry = _mention_entry(upload_id, LOG_TYPE_SPOR, mention)
        _add_path_entry(index, mention.path, entry)
        if mention.identity:
            # A persistence entry under its name too: an FRST Run / service /
            # task line whose program differs or is gone still finds it.
            key = identity_key(*mention.identity)
            if key:
                index.setdefault(key, []).append(entry)
    _software_entries(upload_id, lines, index)
    for evidence in spor_log.iter_timeline_evidence(lines, known):
        key = normalized_path(evidence.path)
        if not key:
            continue
        index.setdefault(key, []).append({
            'kind': 'evidence',
            'upload_id': upload_id,
            'log_type': LOG_TYPE_SPOR,
            'line_no': evidence.line_no,
            'time': evidence.time,
            'sources': evidence.sources[:80],
            # Not `status`: the API gives every entry its status letter under that name.
            'file_status': evidence.file_status,
            'details': evidence.details[:200],
            'flags': evidence.flags[:10],
            'severity': evidence_severity(evidence.flags, evidence.file_status),
            'file': file_name(evidence.path),
        })


# ---------------------------------------------------------------------------
# What the links within a Spor log add to its index (spor_self.py, and FRST
# lines through forward.py)
# ---------------------------------------------------------------------------

# A file named by its bare name in a line's details: it is in the folder of
# the line's own file ("side-loads providers.dll", "loaded by host.exe").
_BARE_NAME_RE = re.compile(
    r'(?:side-loads|loaded by|forwards to|imported by) ([^\s;,()\\/:"<>|]{1,120}\.[A-Za-z0-9]{1,5})(?=[\s;,()]|$)'
)
# Sections whose lines name no other files in their details.
_NO_DETAIL_SECTIONS = frozenset({spor_log.SECTION_FILES, spor_log.SECTION_AMCACHE_FILES})


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
    word = (item.tags.split() or [''])[0].lower()   # "[ ]" gives tags of blanks only
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


def _detail_names(lines, known, index, by_line):
    """{line no: [keys]}: the files of the log a line names in its details
    (at most MAX_RELATED_PER_LINE), and {key: [entry]}: the lines naming each
    such file (each by its own entry)."""
    names, named_in = {}, {}
    for no, title, item in spor_log.iter_section_items(lines, known, skip=frozenset({spor_log.SECTION_LEGEND})):
        if title in _NO_DETAIL_SECTIONS or not item.trusted or no not in by_line:
            continue
        keys = [key for key in _detail_keys(item, set(by_line[no])) if key in index][:MAX_RELATED_PER_LINE]
        if not keys:
            continue
        names[no] = keys
        mine = next((entry for key in by_line[no] for entry in index[key]
                     if entry.get('line_no') == no and not entry.get('folder')), None)
        if mine is not None:
            for key in keys:
                named_in.setdefault(key, []).append(mine)
    return names, named_in


@dataclass
class SporFacts:
    """What one Spor log says, read once: `index` {key: [entry]} (every line
    about a file or entry under its keys), `by_line` {line no: [keys]},
    `partners` {line no: [entry]} (a SUMMARY line and the line it sums up,
    each the other's), `names` {line no: [keys]} (files a line names in its
    details) and `named_in` {key: [entry]} (the lines naming a file)."""
    upload_id: str
    index: dict
    by_line: dict
    partners: dict = field(default_factory=dict)
    names: dict = field(default_factory=dict)
    named_in: dict = field(default_factory=dict)


def build(upload_id, lines, known=None):
    """The SporFacts of a Spor log's lines (content.split('\n')). Used for
    the links within the log (spor_self.py) and, merged into the index of
    the related logs, for FRST lines (forward.py)."""
    if known is None:
        known = spor_log.known_paths(lines)
    index = {}
    spor_log_entries(upload_id, lines, index, known)
    _defender_event_entries(upload_id, lines, known, index)
    _timeline_entries(upload_id, lines, known, index)
    pairs = _summary_pairs(upload_id, lines, known, index)
    _install_entries(upload_id, lines, known, index)
    by_line = _line_keys(index)
    names, named_in = _detail_names(lines, known, index, by_line)
    partners = {}
    for summary, detail in pairs:
        partners.setdefault(summary['line_no'], []).append(detail)
        partners.setdefault(detail['line_no'], []).append(summary)
    return SporFacts(upload_id, index, by_line, partners, names, named_in)
