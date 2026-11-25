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


SOFTWARE_ROLES = {'uninstall': 'uninstall entry', 'installer': 'installer event', 'cached': 'cached package',
                  'package': 'package'}


def _software_entries(upload_id, lines, index):
    """Spor's SOFTWARE facts: an Uninstall entry under its key (Addition's
    Installed Programs line) and its install folder; a Windows Installer
    event under its MSI product code; a cached Windows Installer package
    under its product code and install folder; a Store / MSIX package under its folder
    (Addition's Packages line, and the files inside)."""
    for fact in spor_log.iter_software(lines):
        details = fact.details
        entry = {
            'kind': 'mention', 'upload_id': upload_id, 'log_type': LOG_TYPE_SPOR, 'line_no': fact.line_no,
            'section': spor_log.SECTION_SOFTWARE, 'subsection': fact.subsection[:160], 'time': fact.time,
            'tags': fact.tags[:80], 'text': fact.text[:300], 'role': SOFTWARE_ROLES[fact.kind], 'parent': '',
            'file_status': fact.status, 'flags': fact.flags[:10], 'extra': fact.extra[:spor_log.MAX_EXTRA],
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
        elif fact.kind in ('installer', 'cached'):
            key = msi_key(details.get('product code', ''))
            if key:
                index.setdefault(key, []).append(entry)
            if fact.kind == 'cached':
                # one "folder:" line per install folder and profile (unfold joins them, the details keep the first)
                folders = [value for key, value in fact.extra if key == 'folder'] or [details.get('folder', '')]
                for folder in dict.fromkeys(f.strip() for f in folders if f and f.strip()):
                    _add_folder_entry(index, folder, entry)
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


# USB DRIVES sub-lines that name a file the item line starts: "target:" (what
# autorun.inf runs), "argument file:" (a worm's hidden copy, named relative to
# the drive in a shortcut's arguments), "item list target:", "icon file:".
_USB_FILE_SUB_KEYS = frozenset({'target', 'argument file', 'item list target', 'icon file'})


def spor_log_entries(upload_id, lines, index, known=None, usb_files=None):
    """What one Spor log says, into `index` ({key: [entry]}): Defender
    detections, file facts (FILES, AMCACHE FILES), mentions in the module
    sections (under their path and persistence name), SOFTWARE facts and
    timeline evidence. Pure: the log's lines only (spor_self.py reads a
    log's own lines with it too). `usb_files` (a list) gets (item line no,
    key) of the files USB DRIVES sub-lines name (_USB_FILE_SUB_KEYS)."""
    if known is None:
        known = spor_log.known_paths(lines)
    _add_defender_entries(index, upload_id, LOG_TYPE_SPOR, spor_log.iter_defender_detections(lines))
    for path, entry in _spor_file_infos(upload_id, lines):
        _add_path_entry(index, path, entry)
    for mention in spor_log.iter_mentions(lines, known):
        entry = _mention_entry(upload_id, LOG_TYPE_SPOR, mention)
        if mention.folder and mention.section in (spor_log.SECTION_USB, spor_log.SECTION_DROPS):
            # A worm's hidden folder on a drive, a flagged loader project
            # folder: speaks for the files inside (not a broad one, e.g. a
            # hidden C:\ProgramData in the root listing).
            _add_folder_entry(index, mention.path, entry)
        else:
            _add_path_entry(index, mention.path, entry)
        if (usb_files is not None and mention.parent_line and mention.role in _USB_FILE_SUB_KEYS
                and mention.section == spor_log.SECTION_USB):
            key = _path_key(mention.path)
            if key and is_path_key(key) and not is_host_program(key):
                usb_files.append((mention.parent_line, key))
        if mention.identity:
            # A persistence entry under its name too: an FRST Run / service /
            # task line whose program differs or is gone still finds it.
            key = identity_key(*mention.identity)
            if key:
                index.setdefault(key, []).append(entry)
    _software_entries(upload_id, lines, index)
    for evidence in spor_log.iter_timeline_evidence(lines, known):
        key = _path_key(evidence.path)
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
            # Spor 0.7.0+: its "from:", "page:", ... sub-lines, as written.
            'extra': evidence.extra[:spor_log.MAX_EXTRA],
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


def _path_key(path):
    r"""The key of a file or folder a Spor line names: a folder without its
    trailing backslash ("E:\x\" keys like "E:\x", like FRST's folders)."""
    return normalized_path(spor_log.folder_path(path))


def _item_severity(item):
    """The severity of an item line: its Defender threat's, else its flags'
    and signature's (case_correlations.evidence_severity)."""
    threat = spor_log.defender_threat(item.item)
    if threat:
        return defender_severity(threat)
    return evidence_severity(item.flags, item.status)


def _main_key(item, known=None, volumes=None):
    """The key of the file an item line is about, '' for none: the Defender
    detection's file, the item, else the first file the item names
    (_text_path: "service installed: X: C:\\Program Files\\x.exe")."""
    if spor_log.defender_threat(item.item):
        paths = spor_log.defender_paths(item.rest, volumes)
        return normalized_path(paths[0]) if paths else ''
    if spor_log.is_path(item.item):
        return _path_key(item.item)
    path = _text_path(item.item, known)
    if path:
        return _path_key(path)
    found = argument_paths(item.item)
    return found[0] if found else ''


# Where a path starts in a SUMMARY finding's text ("service installed: X: C:\...",
# "DLL side-loading: C:\...", "invalid signature: \\?\C:\..."), and how a path
# with blanks ends there when FILES does not list it: at a file's extension or a
# folder's backslash before " (", two blanks, ", " / "; ", " => " or the end.
_TEXT_PATH_START_RE = re.compile(r'(?:(?<=[\s(:])|^)(?:\\\\\?\\|\\\?\?\\)?[A-Za-z]:\\')
_TEXT_PATH_END_RE = re.compile(r'^(.+?(?:\.[A-Za-z0-9]{1,8}|\\))(?= \(|  |, |; | => |$)')


def _text_path(text, known=None):
    """The first file or folder path a SUMMARY finding's text names, '' for
    none: the longest FILES path (`known`, spor_log.known_paths) it starts
    with, else up to the file's extension or the folder's backslash."""
    m = _TEXT_PATH_START_RE.search(text or '')
    if not m:
        return ''
    rest = spor_log.strip_device_prefix(text[m.start():])
    if known:
        path = spor_log.resolve_item_path(rest, known)
        if path:
            return path
    end = _TEXT_PATH_END_RE.match(rest)
    return end.group(1) if end else ''


# SUMMARY findings and Autodetect lines about a persistence entry or an
# installed program, not (only) a file: "service installed: <name>: ...",
# "service <name> (auto): ...", "task \<name>: ...", "installed program X,
# key HKLM-x32\...\{GUID}", "... product code {GUID}".
_SERVICE_INSTALLED_RE = re.compile(r'^service installed: (.{1,200}?): ')
_SERVICE_START_RE = re.compile(r'^service (.{1,200}?) \((?:auto|demand|boot|system|manual|disabled|delayed[^)]{0,20})\): ')
_TASK_ITEM_RE = re.compile(r'^task (\\.{1,300}?)(?: \(hidden\))?: ')
_SOFTWARE_KEY_RE = re.compile(r'\bkey (HK[A-Z]{1,4}(?:-x32)?\\\.\.\.\\[^;,\r\n]{1,300}?)(?= => |; |, |$)')
_PRODUCT_CODE_RE = re.compile(r'\bproduct code (\{[0-9A-Fa-f-]{36}\})')
# TIMELINE task and service events: "task \<name> created" (details of a file's
# line, or the item of a line without one: "task \<name> created: <command>"),
# "service <name> installed" (likewise; "service <name> (auto) changed").
_TASK_EVENT_RE = re.compile(r'(?:^|; )task (\\.{1,300}?) (?:created|changed)(?=[;:]|$)')
_SERVICE_EVENT_RE = re.compile(r'(?:^|; )service (.{1,200}?)(?: \([a-z ]{1,20}\))? (?:installed|changed)(?=[;:]|$)')


def _entry_keys(text):
    """The typed keys (svc: / task: / uninstall: / msi:) of a SUMMARY or
    Autodetect line's text."""
    keys = []
    for pattern, kind in ((_SERVICE_INSTALLED_RE, 'svc'), (_SERVICE_START_RE, 'svc'), (_TASK_ITEM_RE, 'task')):
        m = pattern.match(text)
        if m:
            key = identity_key(kind, m.group(1))
            if key:
                keys.append(key)
            break
    m = _SOFTWARE_KEY_RE.search(text)
    if m:
        keys.extend(sorted(software_keys(m.group(1))))
    m = _PRODUCT_CODE_RE.search(text)
    if m:
        key = msi_key(m.group(1))
        if key and key not in keys:
            keys.append(key)
    return keys


def _event_keys(item):
    """The typed keys of a TIMELINE task or service event ([TSK] / [SVC])."""
    tags = item.tags.split()
    keys = []
    if 'TSK' in tags:
        for text in (item.item, item.rest):
            m = _TASK_EVENT_RE.search(text)
            if m:
                keys.append(identity_key('task', m.group(1)))
                break
    if 'SVC' in tags:
        for text in (item.item, item.rest):
            m = _SERVICE_EVENT_RE.search(text)
            if m:
                keys.append(identity_key('svc', m.group(1)))
                break
    return [key for key in keys if key]


def _file_of(index, key):
    """The file name of a key as the log spells it (a folder's name when only
    folder lines name it; lowercased if unknown)."""
    for entry in sorted(index.get(key, ()), key=lambda entry: bool(entry.get('folder'))):
        if entry.get('file'):
            return entry['file']
    return ntpath.basename(key.rstrip('\\'))[:120]


# SUMMARY and TIMELINE sub-lines that name a file of their own (TIMELINE's
# "path:" / "script:" are evidence: iter_timeline_evidence): the first folder of
# a drop folder's group (Spor 0.8.0), a side-loaded DLL (0.8.1). Not a Defender
# detection's "file:" / "process:" items: they are details of their line (Spor
# 0.6 wrote them on it; both layouts link the same, test_spor_unfold).
_SUMMARY_PATH_KEYS = frozenset({'group', 'dll'})


def _sub_path(key, value, known, profile):
    """The path a SUMMARY / TIMELINE sub-line names (_SUMMARY_PATH_KEYS), '' for none."""
    item = spor_log.split_item(value, known, profile)
    if not item.trusted:
        return ''
    return spor_log.folder_path(item.item) if key == 'group' else item.item


def _group_entries(upload_id, lines, known, index):
    """The sub-lines of SUMMARY and TIMELINE that name a file (_SUMMARY_PATH_KEYS:
    "group:", "dll:", "file:", ...) under that file, so the line they belong
    to and the file's other lines link up. The sections' own sub-lines are
    mentions (iter_mentions)."""
    profile = spor_log.user_profile(lines, known)
    for title, start, end in spor_log.iter_sections(lines):
        if title not in (spor_log.SECTION_SUMMARY, spor_log.SECTION_TIMELINE):
            continue
        parent = ''   # the item line above, split only when it has such a sub-line
        for at in range(start + 1, end):
            body = lines[at].rstrip('\r')
            sub = spor_log._sub_line(body)
            if sub is None:
                if body.strip() and not body[:1].isspace():
                    parent = body.strip()
                continue
            key, value = sub
            if key not in _SUMMARY_PATH_KEYS or not value:
                continue
            path = _sub_path(key, value.strip(), known, profile)
            if not spor_log.is_path(path):
                continue
            owner = spor_log.split_item(parent, known, profile) if parent else None
            entry = _plain_mention(
                upload_id, LOG_TYPE_SPOR, at + 1, body.strip(), key, ntpath.basename(path.rstrip('\\')),
                section=title, time=owner.time if owner else '', tags=owner.tags if owner else '',
            )
            entry['parent'] = owner.item[:200] if owner else ''
            _add_path_entry(index, path, entry)


def _summary_pairs(upload_id, lines, known, index):
    """Index the SUMMARY lines under their file, and pair each with the
    section line it sums up: [(summary entry, detail entry)]. A finding
    about a service, task or installed program is under its typed key too."""
    volumes = spor_log.device_volumes(lines)
    by_time = {}
    for no, title, item in spor_log.iter_section_items(lines, known):
        if item.time and item.trusted:
            by_time.setdefault(item.time, []).append((no, title, item, _main_key(item, known, volumes)))
    pairs = []
    for no, item in spor_log.iter_summary_items(lines, known):
        if not item.trusted:
            continue
        main = _main_key(item, known, volumes)
        # The line as the log shows it, its Spor 0.7.0+ sub-lines ("file:" of a
        # Defender detection, "from:" of a download) as its extra.
        text, extra = spor_log.as_written(lines, no)
        entry = _plain_mention(
            upload_id, LOG_TYPE_SPOR, no, text, 'item', _file_of(index, main) if main else '',
            section=spor_log.SECTION_SUMMARY, time=item.time, tags=item.tags, extra=extra,
            severity=_item_severity(item),
        )
        entry['flags'] = item.flags[:10]
        entry['file_status'] = item.status
        if main:
            index.setdefault(main, []).append(entry)
        for key in _entry_keys(item.text):
            index.setdefault(key, []).append(entry)
        detail = _detail_line(item, main, by_time.get(item.time, ()) if item.time else ())
        if detail is None:
            continue
        detail_no, title, detail_item, detail_key = detail
        text, extra = spor_log.as_written(lines, detail_no)
        detail_entry = _plain_mention(
            upload_id, LOG_TYPE_SPOR, detail_no, text, 'details',
            _file_of(index, detail_key) if detail_key else '', section=title, time=detail_item.time,
            tags=detail_item.tags, extra=extra, severity=_item_severity(detail_item),
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
        text, extra = spor_log.as_written(lines, no)
        entry = _plain_mention(
            upload_id, LOG_TYPE_SPOR, no, text, 'item', item.item[:120],
            section=spor_log.SECTION_TIMELINE, time=item.time, tags=item.tags, extra=extra,
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
    volumes = spor_log.device_volumes(lines)
    for no, title, item in spor_log.iter_section_items(lines, known):
        threat = spor_log.defender_threat(item.item) if title == spor_log.SECTION_DEFENDER else ''
        if not threat or no in indexed:
            continue
        for path in spor_log.defender_paths(item.rest, volumes):
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
        key = _path_key(item.item)
        if not key:
            continue
        details, extra = item.rest, []
        if not spor_log.is_sub_line(lines[no - 1]):
            # An item line as written (Spor 0.7.0+: its "from:", ... sub-lines as extra);
            # a merged line's "path:" sub-line is its own.
            details = spor_log.rest_as_written(lines, no, known)
            extra = spor_log.sub_details(lines, no - 1)
        index.setdefault(key, []).append({
            'kind': 'evidence', 'upload_id': upload_id, 'log_type': LOG_TYPE_SPOR, 'line_no': no,
            'time': item.time, 'sources': item.tags[:80], 'file_status': item.status, 'details': details[:200],
            'extra': extra, 'flags': item.flags[:10], 'severity': evidence_severity(item.flags, item.status),
            'file': file_name(item.item),
        })


def _event_entries(upload_id, lines, known, index):
    """TIMELINE task and service events ("[TSK] ... task \\X created", "[SVC]
    ... service X installed") under the task's / service's typed key too, so
    they link to its PERSISTENCE line and SUMMARY finding: the line's own entry
    when it names a file, else a plain mention of it."""
    own = {}
    for entries in index.values():
        for entry in entries:
            if entry.get('kind') == 'evidence' and not entry.get('folder'):
                own.setdefault(entry.get('line_no'), entry)
    for no, item in spor_log.iter_timeline_items(lines, known):
        keys = _event_keys(item)
        if not keys:
            continue
        entry = own.get(no)
        if entry is None:
            text, extra = spor_log.as_written(lines, no)
            entry = _plain_mention(
                upload_id, LOG_TYPE_SPOR, no, text, 'item', '', section=spor_log.SECTION_TIMELINE,
                time=item.time, tags=item.tags, extra=extra, severity=evidence_severity(item.flags, item.status),
            )
            entry['flags'] = item.flags[:10]
        for key in keys:
            index.setdefault(key, []).append(entry)


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


def _own_entry(index, by_line, no):
    """The entry of line `no` about its own file (not a folder entry), or None."""
    return next((entry for key in by_line[no] for entry in index[key]
                 if entry.get('line_no') == no and not entry.get('folder')), None)


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
        mine = _own_entry(index, by_line, no)
        if mine is not None:
            for key in keys:
                named_in.setdefault(key, []).append(mine)
    return names, named_in


def _usb_sub_names(usb_files, index, by_line, names, named_in):
    """The files a USB DRIVES line's sub-lines name are named by the line too
    ('detail' / 'named_by', like files in its details): the worm's shortcut and
    its hidden copy, autorun.inf and what it starts. `usb_files`: (item line
    no, key) of those sub-lines (spor_log_entries)."""
    for item_no, key in usb_files:
        if item_no not in by_line or key in by_line[item_no]:
            continue
        listed = names.setdefault(item_no, [])
        if key in listed or len(listed) >= MAX_RELATED_PER_LINE:
            continue
        listed.append(key)
        mine = _own_entry(index, by_line, item_no)
        if mine is not None:
            named_in.setdefault(key, []).append(mine)


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
    usb_files = []
    spor_log_entries(upload_id, lines, index, known, usb_files)
    _defender_event_entries(upload_id, lines, known, index)
    _timeline_entries(upload_id, lines, known, index)
    _group_entries(upload_id, lines, known, index)
    pairs = _summary_pairs(upload_id, lines, known, index)
    _install_entries(upload_id, lines, known, index)
    _event_entries(upload_id, lines, known, index)
    by_line = _line_keys(index)
    names, named_in = _detail_names(lines, known, index, by_line)
    _usb_sub_names(usb_files, index, by_line, names, named_in)
    partners = {}
    for summary, detail in pairs:
        partners.setdefault(summary['line_no'], []).append(detail)
        partners.setdefault(detail['line_no'], []).append(summary)
    return SporFacts(upload_id, index, by_line, partners, names, named_in)
