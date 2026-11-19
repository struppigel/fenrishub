"""What other logs of the same infection case say about the files of an FRST log.

For each FRST / Addition line whose file path also appears in another log of
one of the upload's cases, collect what that log says about the file:

- a hash row (Malwarebytes, HitmanPro, Trojan Killer, MAU, Fixlog File: and
  Folder: blocks, folder listings): the detection, SHA256 / MD5 and the
  stored centralbox result if any (a bare hash counts too);
- a detection of a scanner without hashes (ESET, Emsisoft, AdwCleaner, and
  hash-less detections of the others): detection name and action;
- a Fixlog result ("<path> => moved successfully");
- a Spor log's Defender detections (kind 'detection') and its timeline
  (kind 'evidence': when the file ran, was created or downloaded, by which
  sources, with Spor's flags);
- facts about the file itself (kind 'file_info': a Spor log's FILES and
  AMCACHE FILES lines - signature, signer, version, company, original name,
  hashes - and an FRST Search log's File: entries - dates, size, attributes,
  company, MD5, signed or not);
- the other places a log names the file (kind 'mention': Spor's module
  sections - programs that loaded it, the Run key / service / task / install
  pointing at it, network use, downloads, a Defender-excluded folder it is in
  - an FRST Search folder or registry hit, a shortcut pointing at it);
- installed software (kind 'mention' too): Spor's SOFTWARE section (Uninstall
  entries, Windows Installer events, Store / MSIX packages) and MAU's removed
  products, under the program's Uninstall key / MSI product code (Addition's
  Installed Programs lines) or its folder (Packages lines, files inside); a
  Fixlog's installed-app investigation and MAU's products also under the
  program's display name (`app:` keys, versions compared), with their install
  folders; everything MAU deleted (files, folders, registry keys and values,
  services, tasks) and the files its products' MSI components point at.

Besides the line's own files (`match` says how else an entry was found):
- 'host': what is said about a host program the line runs a file through;
- 'sibling': a detection of another file in the same folder;
- 'name': a file of the same uncommon name in another folder;
- 'same_hash': another path with the same SHA256 (its hashes, detections);
- 'inside': for a folder line of the created / modified files sections,
  what is said about the files inside (status-giving entries one by one,
  the rest summed up in 'files inside' mentions);
- 'timing': created-files lines of the log within TIMING_WINDOW of a flagged
  one, and the related Spor logs' timeline events of that time.
'host', 'sibling', 'name' and 'timing' only inform (INFO_MATCHES): they never
give a line a status.

reverse_correlations() turns the stored answers around for any other log:
which FRST / Addition lines point at each of its lines.

Database and local parsing only: nothing is ever sent to centralbox. Paths
are compared with the analyzer's own key (normalize_path, lowercased).
"""

import bisect
import hashlib
import json
import logging
import ntpath
import re
from collections import Counter, namedtuple
from datetime import datetime, timedelta

from .analyzer import ANALYSIS_PAYLOAD_FORMAT
from .correlation_keys import (
    MATCH_ARGUMENT, MATCH_HOST, MATCH_PATH, app_key, argument_paths, identity_key, installed_program,
    is_host_program, is_path_key, line_keys, msi_key, name_key, software_keys, target_keys,
    task_key, versions_differ,
)
from . import frst_extractors as ex
from .file_hashes import _as_path, normalized_path
from . import spor_log
from .log_highlighting import defender_severity, highlight_log, threat_severity  # noqa: F401 (defender_severity re-exported)
from django.db import IntegrityError, transaction
from django.db.models import Count, Max, Q
from django.db.models.functions import Substr

from .machine_signals import (  # noqa: F401 (re-exported)
    KIND_COMPUTER, KIND_DISK, KIND_HW, KIND_PROFILE, KIND_SID, STRONG_KINDS, SYSTEM_DIFFERENT, SYSTEM_LIKELY, SYSTEM_SAME, SYSTEM_SIGNAL_CHARS,
    SYSTEM_UNKNOWN, compare, compare_with_reason, extract_signals, log_signals,
)
from .models import (
    CorrelationCache, HashAlias, HashVerdict, InfectionCaseLog, UploadedLog, UploadedLogAnalysis,
    UploadedLogFileHash, UploadedLogMachineSignal, iter_fixlog_results, sync_stat_correlated_hashes,
)
from .log_types import (
    ADDITION_LOG_TYPES, DETECTION_LOG_TYPES, LOG_TYPE_FRST_AND_ADDITION, LOG_TYPE_FRST_SEARCH, LOG_TYPE_SHORTCUT,
    LOG_TYPE_SPOR,
)
from .tool_log_facts import (
    SECTION_APP_INVESTIGATION, fixlog_app_facts, frst_search_facts, mau_facts, shortcut_mentions,
)
from .status_types import dominant_status

logger = logging.getLogger(__name__)

MAX_ENTRIES_PER_LINE = 60
# When a line has more entries than that, these come first (status-giving
# entries before all others), so what decides the line's status is never cut.
KIND_RANK = {'detection': 0, 'hash': 1, 'fixlog': 2, 'file_info': 3, 'evidence': 4, 'mention': 5}
# Part of every cache signature: bump it when what is computed changes.
CORRELATION_VERSION = 19
# Detections are read from the summary boxes of DETECTION_LOG_TYPES logs
# (log_highlighting); Defender events from the "Windows Defender:" section of
# ADDITION_LOG_TYPES logs (both in log_types).


SCOPE_CASE = 'case'
SCOPE_USER = 'user'


def related_upload_ids(uploaded_log, user):
    """(upload ids, scope, name): the logs to correlate the upload with.

    The other live logs of the viewer's own live cases that contain the
    upload (scope 'case'); if there are none, every other live log of the same
    forum user, any age, case-insensitive (scope 'user', name = the forum
    username); else nothing.

    The forum username is whatever the uploader typed (anonymous uploads
    included), so the 'user' scope trusts it; accepted as a known risk."""
    owner_id = getattr(user, 'pk', None)
    if owner_id is not None:
        case_ids = list(
            InfectionCaseLog.objects.filter(
                uploaded_log=uploaded_log, case__deleted_at__isnull=True, case__owner_id=owner_id,
            ).values_list('case_id', flat=True)
        )
        if case_ids:
            ids = list(
                InfectionCaseLog.objects.filter(case_id__in=case_ids, uploaded_log__deleted_at__isnull=True)
                .exclude(uploaded_log=uploaded_log)
                .values_list('uploaded_log_id', flat=True)
                .distinct()
            )
            return ids, SCOPE_CASE, ''
    name = (uploaded_log.forum_username or '').strip()
    if name:
        ids = list(
            UploadedLog.objects.filter(forum_username__iexact=name, deleted_at__isnull=True)
            .exclude(pk=uploaded_log.pk).values_list('pk', flat=True)
        )
        return ids, SCOPE_USER, name
    return [], '', ''


# --- Same system? machine_signals.py extracts and compares the signals; they
# are stored per log (UploadedLogMachineSignal) when its stats are rebuilt.


def system_signals(content):
    """(computer names, profile names), lowercased, from the start of a log's
    text (the head-only reading; the stored signals have more kinds)."""
    signals = extract_signals(content, head_only=True)
    return signals.get(KIND_COMPUTER, set()), signals.get(KIND_PROFILE, set())


def same_system(a, b):
    """'same', 'likely', 'different' or 'unknown' for two logs' signals:
    {kind: values} (machine_signals.compare), or (computers, profiles) pairs
    from system_signals."""
    def as_dict(signals):
        if isinstance(signals, tuple):
            computers, profiles = signals
            return {KIND_COMPUTER: set(computers), KIND_PROFILE: set(profiles)}
        return signals or {}
    return compare(as_dict(a), as_dict(b))


def system_verdicts(uploaded_log, upload_pks):
    """{upload pk: (verdict, deciding kind)} of these logs against the
    upload (stored signals, see stored_signals)."""
    signals = stored_signals({uploaded_log.pk, *upload_pks})
    own = signals.get(uploaded_log.pk) or {}
    return {pk: compare_with_reason(own, signals.get(pk) or {}) for pk in upload_pks}


def stored_signals(upload_pks):
    """{upload pk: {kind: hashed values}}: the stored machine signals, or for
    a log without any (stats not rebuilt since, or nothing found) the ones in
    the start of its text."""
    result = {pk: {} for pk in upload_pks}
    if not result:
        return result
    for upload_pk, kind, value in UploadedLogMachineSignal.objects.filter(upload_id__in=list(result)).values_list(
        'upload_id', 'kind', 'value',
    ):
        result[upload_pk].setdefault(kind, set()).add(value)
    missing = [pk for pk, signals in result.items() if not signals]
    if missing:
        heads = UploadedLog.objects.filter(pk__in=missing).annotate(
            head=Substr('content', 1, SYSTEM_SIGNAL_CHARS),
        ).values_list('pk', 'head')
        for pk, head in heads:
            result[pk] = log_signals(head or '')
    return result


def _fresh_payload(uploaded_log):
    """A fresh cached analysis of the upload: the log's own rule set's first
    (its rule verdicts pick the timing anchors), else any other in key order
    (the line texts are the same for every rule set)."""
    try:
        from .rule_sets import resolve_effective_rule_set_key
        preferred = resolve_effective_rule_set_key(uploaded_log)
    except Exception:
        preferred = None
    fresh = UploadedLogAnalysis.objects.filter(upload=uploaded_log, source_content_hash=uploaded_log.content_hash)
    # The keys first: only the payload used is fetched and decoded.
    keys = sorted(fresh.values_list('rule_set_key', flat=True), key=lambda key: (key != preferred, key))
    for key in keys:
        payload = fresh.filter(rule_set_key=key).values_list('payload', flat=True).first()
        if isinstance(payload, dict) and payload.get('format') == ANALYSIS_PAYLOAD_FORMAT:
            return payload
    return None


def _first_line_numbers(content, wanted):
    """{stripped line text: its first line number} for the wanted texts."""
    numbers = {}
    for no, raw in enumerate((content or '').split('\n'), start=1):
        text = raw.strip()
        if text in wanted and text not in numbers:
            numbers[text] = no
            if len(numbers) == len(wanted):
                break
    return numbers


def _centralbox_result(sha, md5, verdicts, unknown_md5s):
    if sha and sha in verdicts:
        return verdicts[sha]
    if md5 and md5 in unknown_md5s:
        return {'state': HashVerdict.STATE_UNKNOWN, 'checked_at': unknown_md5s[md5]}
    return None


def _hash_entries(upload_ids, index):
    from .centralbox import resolve_md5s

    rows = list(
        UploadedLogFileHash.objects.filter(upload_id__in=upload_ids).exclude(normalized_path='')
        .select_related('upload')
        .only('sha256', 'md5', 'line_no', 'anchor_line_no', 'detection', 'source', 'normalized_path', 'path',
              'upload__upload_id', 'upload__log_type')
    )
    md5_map = resolve_md5s({row.md5 for row in rows if row.md5 and not row.sha256})
    shas = {row.sha256 or md5_map.get(row.md5, '') for row in rows} - {''}
    verdicts = {row.sha256: row.as_dict() for row in HashVerdict.objects.filter(sha256__in=shas)}
    unknown_md5s = {
        md5: checked.date().isoformat()
        for md5, checked in HashAlias.objects.filter(
            md5__in={row.md5 for row in rows if row.md5}, sha256='',
        ).values_list('md5', 'checked_at')
    }
    covered = set()  # (upload pk, anchor line) of detections that have a hash row
    for row in rows:
        sha = row.sha256 or md5_map.get(row.md5, '')
        result = _centralbox_result(sha, row.md5, verdicts, unknown_md5s)
        covered.add((row.upload_id, row.anchor_line_no))
        index.setdefault(row.normalized_path, []).append({
            'kind': 'hash',
            'upload_id': row.upload.upload_id,
            'log_type': row.upload.log_type,
            'line_no': row.line_no,
            'anchor_line_no': row.anchor_line_no,
            'detection': row.detection,
            'severity': threat_severity(row.detection) if row.detection else '',
            'sha256': sha,
            'md5': row.md5,
            'centralbox': result,
            'file': file_name(row.path),
        })
    return covered


def _detection_entries(upload_ids, index, covered):
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type__in=DETECTION_LOG_TYPES).only(
        'pk', 'upload_id', 'log_type', 'content',
    ):
        highlight = highlight_log(upload.log_type, upload.content or '')
        if highlight is None:
            continue
        for item in highlight.summary:
            if (upload.pk, item.line_no) in covered:
                continue
            # A file path, or the typed keys of a registry value, service,
            # task, browser extension, ... (correlation_keys).
            entry = {
                'kind': 'detection',
                'upload_id': upload.upload_id,
                'log_type': upload.log_type,
                'line_no': item.line_no,
                'detection': item.name,
                'action': item.action,
                'severity': item.severity,
            }
            name = file_name(_as_path(item.target))
            if name:
                entry['file'] = name
            for key in target_keys(item.target):
                index.setdefault(key, []).append(entry)


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


def _fixlog_entries(upload_ids, index):
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type='Fixlog').only('pk', 'upload_id', 'content'):
        content = upload.content or ''
        if '<=== ' in content:
            _fixlog_app_entries(upload, index)
        for line_no, target, result in iter_fixlog_results(content):
            entry = {
                'kind': 'fixlog',
                'upload_id': upload.upload_id,
                'log_type': 'Fixlog',
                'line_no': line_no,
                'result': result.strip()[:200],
            }
            name = file_name(_as_path(target.strip().strip('"')))
            if name:
                entry['file'] = name
            for key in target_keys(target, result):
                index.setdefault(key, []).append(entry)
        if 'Threat' not in content:
            continue
        # Windows Defender events in the Fixlog: detections like a scanner's.
        _add_defender_entries(index, upload.upload_id, 'Fixlog', iter_defender_detections(content))


def file_name(path):
    """The last part of a path as the log spells it ('' for none): which
    file an entry is about, as a line can name several (its own file, files
    in its command line, a detected folder above it)."""
    return ntpath.basename((path or '').strip().strip('"').rstrip('\\'))[:120]


def _add_defender_entries(index, upload_id, log_type, detections, lines=None):
    """`lines` (the log's content.split('\\n')) adds each entry's line text:
    for the log's own entries, which the analyzer finds by it."""
    for line_no, threat, action, path in detections:
        key = normalized_path(path)
        if not key:
            continue
        entry = {
            'kind': 'detection',
            'upload_id': upload_id,
            'log_type': log_type,
            'line_no': line_no,
            'detection': threat[:255],
            'action': action[:100],
            'severity': defender_severity(threat),
            'source': 'defender',
            'file': file_name(path),
        }
        if lines is not None and 0 < line_no <= len(lines):
            entry['line_text'] = lines[line_no - 1].strip()[:300]
        index.setdefault(key, []).append(entry)


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


def _addition_entries(upload_ids, index, own=None):
    """Defender detections of the related Addition logs, and of the
    upload's own Addition part (`own`, a merged FRST&Addition log)."""
    uploads = list(
        UploadedLog.objects.filter(pk__in=upload_ids, log_type__in=ADDITION_LOG_TYPES)
        .only('pk', 'upload_id', 'content')
    )
    for upload in uploads:
        _add_defender_entries(
            index, upload.upload_id, 'Addition', iter_addition_defender_detections(upload.content or ''),
        )
    if own is not None and own.log_type == LOG_TYPE_FRST_AND_ADDITION:
        content = own.content or ''
        detections = iter_addition_defender_detections(content)
        if detections:
            _add_defender_entries(index, own.upload_id, 'Addition', detections, lines=content.split('\n'))


def evidence_severity(flags, file_status):
    """'w' for a Spor timeline entry with a flag that is not normal on many
    PCs, or a file whose signature does not hold; '' otherwise."""
    loud = any(flag not in spor_log.QUIET_FLAGS for flag in flags or ())
    return 'w' if loud or file_status in spor_log.BAD_SIGNATURE_STATUSES else ''


# A FILES "<name> <value>" part -> the file_info key it is stored under.
_FILES_FACT_KEYS = {
    'signature': 'signature', 'signer': 'signer', 'thumbprint': 'thumbprint', 'note': 'note',
    'file version': 'version', 'description': 'description', 'product': 'product', 'company': 'company',
    'original name': 'original_name', 'amcache sha1': 'sha1', 'md5': 'md5', 'size': 'size',
    'created': 'created', 'modified': 'modified',
}


def original_name_differs(path, original_name):
    """True when a file's version resource names another file ("invoice.pdf.exe"
    whose original name is "svchost.exe"). Shown, never rated: renamed
    installers are common."""
    base = ntpath.basename(path or '').lower()
    original = (original_name or '').strip().lower()
    if not base or not original:
        return False
    stem = base.rsplit('.', 1)[0]
    return not (original == base or original.startswith(base + '.') or original.rsplit('.', 1)[0] == stem)


def _file_info_entry(upload_id, log_type, line_no, path, source, facts, hashes, severity=''):
    entry = {
        'kind': 'file_info', 'upload_id': upload_id, 'log_type': log_type, 'line_no': line_no,
        'source': source, 'file': file_name(path), 'path': path[:400], 'severity': severity,
    }
    entry.update({key: value[:300] for key, value in facts.items() if value})
    entry.update({key: value.lower() for key, value in hashes.items() if value})
    if entry.get('original_name') and original_name_differs(path, entry['original_name']):
        entry['original_name_differs'] = True
    return entry


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
        bad = parsed.signature in spor_log.BAD_SIGNATURES or parsed.status in spor_log.BAD_SIGNATURE_STATUSES
        yield parsed.path, _file_info_entry(upload_id, LOG_TYPE_SPOR, parsed.line_no, parsed.path, 'spor_files', facts,
                                            hashes, 'w' if bad else '')
    for line_no, path, sha1 in spor_log.iter_amcache_files(lines):
        yield path, _file_info_entry(upload_id, LOG_TYPE_SPOR, line_no, path, 'spor_amcache', {}, {'sha1': sha1})


def _mention_entry(upload_id, log_type, mention):
    entry = {
        'kind': 'mention', 'upload_id': upload_id, 'log_type': log_type, 'line_no': mention.line_no,
        'section': mention.section[:80], 'subsection': mention.subsection[:160], 'time': mention.time,
        'tags': mention.tags[:80], 'text': mention.text[:300], 'role': mention.role, 'parent': mention.parent[:200],
        # Not `status`: the API gives every entry its status letter under that name.
        'file_status': mention.status, 'flags': mention.flags[:10], 'extra': mention.extra[:spor_log.MAX_EXTRA],
        'severity': evidence_severity(mention.flags, mention.status),
        # A persistence entry without a file of its own: named by its value / service / task.
        'file': file_name(mention.path) or (mention.identity[1][:120] if mention.identity else ''),
    }
    if mention.folder:
        entry['folder'] = True
    return entry


# Folders too broad to speak for the files inside them: a drive root, Windows,
# Program Files (and its Common Files / WindowsApps), ProgramData, a user
# profile and its AppData / Desktop / Downloads / Documents folders.
_BROAD_FOLDER_RE = re.compile(
    r'^[a-z]:(?:\\(?:windows|programdata'
    r'|program files(?: \(x86\))?(?:\\(?:common files|windowsapps))?'
    r'|users(?:\\[^\\]+(?:\\(?:desktop|downloads|documents'
    r'|appdata(?:\\(?:local|roaming|locallow)(?:\\programs)?)?))?)?))?$'
)


def is_broad_folder(key):
    """True for a folder key too broad to speak for the files inside it."""
    return bool(_BROAD_FOLDER_RE.match((key or '').rstrip('\\')))


# Folders whose files have nothing to do with each other besides the broad
# ones: Temp, the browser caches, Windows' own system folders.
_BROAD_PARENT_RE = re.compile(
    r'^[a-z]:\\(?:windows(?:\\temp|\\system32(?:\\drivers|\\tasks)?|\\syswow64)'
    r'|users\\[^\\]+\\appdata\\local(?:\\temp|\\microsoft\\windows\\(?:inetcache|webcache)))$'
)


def is_broad_parent(key):
    """True for a folder whose files say nothing about each other (siblings,
    a folder line's contents): the broad folders, Temp, the browser caches,
    System32."""
    key = (key or '').rstrip('\\')
    return is_broad_folder(key) or bool(_BROAD_PARENT_RE.match(key))


def _add_folder_entry(index, folder, entry):
    """Index `entry` as a folder mention (the files inside get it too), unless
    the folder is too broad."""
    key = normalized_path(folder).rstrip('\\')
    if key and not is_broad_folder(key):
        index.setdefault(key, []).append({**entry, 'folder': True})


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


def _plain_mention(upload_id, log_type, line_no, text, role, file='', section='', time='', tags='', extra=(),
                   severity=''):
    """A mention entry built from parts (not from a parsed Spor item)."""
    return {
        'kind': 'mention', 'upload_id': upload_id, 'log_type': log_type, 'line_no': line_no,
        'section': section, 'subsection': '', 'time': time, 'tags': tags[:80], 'text': text[:300],
        'role': role, 'parent': '', 'file_status': '', 'flags': [],
        'extra': [list(pair) for pair in extra][:spor_log.MAX_EXTRA], 'severity': severity, 'file': file[:120],
    }


def _mau_mention(upload_id, line_no, text, role, file, extra=(), severity=''):
    return _plain_mention(upload_id, 'MAU', line_no, text, role, file, section='MAU', extra=extra, severity=severity)


def _mau_entries(upload_ids, index):
    """What the related MAU logs removed (tool_log_facts.mau_facts): each
    product under its MSI product code, Uninstall key and display name
    (Addition's Installed Programs line), and its install folder; the folder
    it was installed from (often a dropper's Temp folder); every deleted
    file, folder, registry key / value, service and task."""
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type='MAU').only('upload_id', 'log_type', 'content'):
        products, items = mau_facts(upload.content or '')
        for product in products:
            name = product.name if product.name and product.name != product.ident else ''
            text = name + (f' ({product.publisher})' if product.publisher else '') if name else product.ident
            extra = [('product code', product.ident[:80])] if msi_key(product.ident) else []
            if product.version:
                extra.append(('version', product.version[:80]))
            if product.install_location:
                extra.append(('install folder', product.install_location[:200]))
            if product.install_source:
                extra.append(('installed from', product.install_source[:200]))
            entry = _mau_mention(upload.upload_id, product.line_no, text, 'removed by MAU', name or product.ident, extra)
            if name:
                entry['version'] = product.version[:100]
            keys = {msi_key(product.ident), app_key(name)}
            for key in product.uninstall_keys:
                keys.update(software_keys(key))
            for key in sorted(keys - {''}):
                index.setdefault(key, []).append(entry)
            if product.install_location:
                _add_folder_entry(index, product.install_location, entry)
            if product.install_source:
                _add_folder_entry(index, product.install_source, {**entry, 'role': 'MAU install source'})
            for line_no, path in product.key_paths:
                # A file the product's MSI components point at: what it installed.
                _add_path_entry(index, path, _mau_mention(
                    upload.upload_id, line_no, f'{name or product.ident}: {path}', 'installed by product (MAU)',
                    file_name(path),
                ))
        for item in items:
            target = item.target.strip().strip('"')
            role = 'MAU failed to delete' if item.failed else 'deleted by MAU'
            path = _as_path(target) if item.kind in ('File', 'Dir') else ''
            entry = _mau_mention(
                upload.upload_id, item.line_no, f'[{item.kind}] {target}', role,
                file_name(path) if path else ntpath.basename(target.rstrip('\\')),
                severity='w' if item.failed else '',
            )
            if item.kind == 'Dir':
                if path:
                    _add_folder_entry(index, path, entry)
            elif item.kind == 'File':
                if path:
                    _add_path_entry(index, path, entry)
            elif item.kind == 'Service':
                index.setdefault(f'svc:{target.lower()}', []).append(entry)
            elif item.kind == 'Task':
                key = task_key(target)
                if key:
                    index.setdefault(key, []).append(entry)
            elif item.kind == 'RegValue':
                # "<key>\<value>": a Run value is "<Run key>|<value>" to
                # target_keys. The values of an Uninstall key stand for the
                # product, which its own entry (or the key's) already gives.
                key_path, _sep, value = target.rpartition('\\')
                for key in target_keys(f'{key_path}|{value}' if key_path else target):
                    if not is_path_key(key) and not key.startswith(('uninstall:', 'msi:')):
                        index.setdefault(key, []).append(entry)
            else:
                for key in target_keys(target):
                    if not is_path_key(key):
                        index.setdefault(key, []).append(entry)


def _fixlog_app_entries(upload, index):
    """The installed-app investigation of a Fixlog (a fixlist PowerShell
    snippet, tool_log_facts.fixlog_app_facts): each app under its display
    name (Addition's Installed Programs line; the versions are compared when
    matched) and its install folder (the files inside), or its one file."""
    for app in fixlog_app_facts(upload.content or ''):
        extra = []
        if app.path:
            extra.append(('path', app.path[:200]))
        if app.state:
            extra.append(('state', app.state[:80]))
        if app.files or app.folders:
            extra.append(('contents', f'{app.files} files, {app.folders} folders'))
        if app.unsigned:
            extra.append(('unsigned PE files', str(app.unsigned)))
        for path, signer in app.invalid[:5]:
            extra.append(('invalid signature', f'{file_name(path)}: {signer}'))
        if app.signers:
            extra.append(('signers', ', '.join(app.signers)[:200]))
        text = app.name + (f' [{app.version}]' if app.version else '') + (f' ({app.publisher})' if app.publisher else '')
        entry = {
            'kind': 'mention', 'upload_id': upload.upload_id, 'log_type': 'Fixlog', 'line_no': app.line_no,
            'section': SECTION_APP_INVESTIGATION, 'subsection': '', 'time': '', 'tags': '', 'text': text[:300],
            'role': 'installed app', 'parent': '', 'file_status': app.state[:40], 'flags': [],
            'extra': [list(pair) for pair in extra][:spor_log.MAX_EXTRA],
            'severity': 'w' if app.invalid else '', 'file': app.name[:120], 'version': app.version[:100],
        }
        key = app_key(app.name)
        if key:
            index.setdefault(key, []).append(entry)
        if not app.path or app.state:
            continue
        if app.is_folder:
            _add_folder_entry(index, app.path, entry)
        else:
            _add_path_entry(index, app.path, entry)


def _add_path_entry(index, path, entry):
    key = normalized_path(path)
    if key:
        index.setdefault(key, []).append(entry)


def _spor_entries(upload_ids, index, spor_logs=None):
    """What the related Spor logs say: Defender detections, timeline
    evidence, file facts (FILES, AMCACHE FILES) and mentions in the module
    sections. (Their FILES hashes are hash rows too: _hash_entries.) Keeps
    (upload_id, lines, known paths) of each in `spor_logs` when given, for
    their timeline events (_spor_timeline_events), read only when needed."""
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type=LOG_TYPE_SPOR).only('pk', 'upload_id', 'content'):
        lines = (upload.content or '').split('\n')
        known = spor_log.known_paths(lines)
        if spor_logs is not None:
            spor_logs.append((upload.upload_id, lines, known))
        _add_defender_entries(index, upload.upload_id, LOG_TYPE_SPOR, spor_log.iter_defender_detections(lines))
        for path, entry in _spor_file_infos(upload.upload_id, lines):
            _add_path_entry(index, path, entry)
        for mention in spor_log.iter_mentions(lines, known):
            entry = _mention_entry(upload.upload_id, LOG_TYPE_SPOR, mention)
            _add_path_entry(index, mention.path, entry)
            if mention.identity:
                # A persistence entry under its name too: an FRST Run / service /
                # task line whose program differs or is gone still finds it.
                key = identity_key(*mention.identity)
                if key:
                    index.setdefault(key, []).append(entry)
        _software_entries(upload.upload_id, lines, index)
        for evidence in spor_log.iter_timeline_evidence(lines, known):
            key = normalized_path(evidence.path)
            if not key:
                continue
            index.setdefault(key, []).append({
                'kind': 'evidence',
                'upload_id': upload.upload_id,
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


def _frst_search_entries(upload_ids, index):
    """File: entries (file_info) and folder / registry hits (mention) of the
    related FRST Search logs. (Their MD5s are hash rows too.)"""
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type=LOG_TYPE_FRST_SEARCH).only('upload_id', 'content'):
        files, mentions = frst_search_facts(upload.content or '')
        for facts in files:
            _add_path_entry(index, facts.path, _file_info_entry(
                upload.upload_id, LOG_TYPE_FRST_SEARCH, facts.line_no, facts.path, facts.source, facts.facts,
                {'md5': facts.md5},
            ))
        for mention in mentions:
            _add_path_entry(index, mention.path, _mention_entry(upload.upload_id, LOG_TYPE_FRST_SEARCH, mention))


def _shortcut_entries(upload_ids, index):
    """Shortcuts of the related Shortcut logs: under their target and their .lnk file."""
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type=LOG_TYPE_SHORTCUT).only('upload_id', 'content'):
        for mention in shortcut_mentions(upload.content or ''):
            _add_path_entry(index, mention.path, _mention_entry(upload.upload_id, LOG_TYPE_SHORTCUT, mention))


def mention_text(entry):
    """A mention in a few words: its flags, else where in the log it is."""
    loud = [flag for flag in entry.get('flags') or () if flag not in spor_log.QUIET_FLAGS]
    if loud:
        return ' '.join(loud)
    where = ' \u203a '.join(part for part in (entry.get('section') or '', entry.get('subsection') or '') if part)
    return ' '.join(part for part in (where, entry.get('file_status') or '') if part)


def evidence_text(entry):
    """A Spor timeline entry in a few words: its flags, else when and by
    which sources the file was seen."""
    loud = [flag for flag in entry.get('flags') or () if flag not in spor_log.QUIET_FLAGS]
    if loud:
        return ' '.join(loud)
    seen = ' '.join(part for part in (str(entry.get('time') or '')[:16], entry.get('sources') or '') if part)
    return ' '.join(part for part in (seen, entry.get('file_status') or '') if part)


def _system_verdicts(uploaded_log, upload_pks):
    """{upload_id: does that log come from the upload's machine?} for the
    related logs and the upload itself (its own entries: the Addition part,
    lines at the same time)."""
    pks = dict(UploadedLog.objects.filter(pk__in=list(upload_pks)).values_list('upload_id', 'pk'))
    signals = stored_signals({uploaded_log.pk, *pks.values()})
    own = signals.get(uploaded_log.pk) or {}
    verdicts = {upload_id: compare(own, signals.get(pk) or {}) for upload_id, pk in pks.items()}
    verdicts[uploaded_log.upload_id] = compare(own, own)
    return verdicts


# A finding as a line-verdict status letter (status_types): detection
# severities from the log pages, centralbox verdicts. Fixlog results and
# unchecked / unknown hashes have none.
_SEVERITY_STATUS = {'b': 'B', 'p': 'P', 'g': 'G', 'w': '!', 'c': 'C', 'j': 'J', 'i': 'I'}
_VERDICT_STATUS = {'malicious': 'B', 'suspicious': '!', 'clean': 'C'}


# Malware and PUPs; and every status that flags something.
MALWARE_STATUSES = frozenset({'B', 'P'})
FLAGGED_STATUSES = frozenset({'B', 'P', '!', 'G'})

MATCH_SIBLING = 'sibling'
MATCH_NAME = 'name'
MATCH_TIMING = 'timing'
MATCH_SAME_HASH = 'same_hash'
MATCH_INSIDE = 'inside'
# The role of the mention that sums up what is said about a folder line's files.
ROLE_FILES_INSIDE = 'files inside'
# The statuses an entry found through a match may give its line (all for a
# match not listed). Informational matches give none: a host program the line
# runs something through, a detected file in the same folder, a file of the
# same name elsewhere, a line or event at the same time. A file inside a
# folder line's folder speaks for the folder only when it is malware or a PUP.
_MATCH_STATUSES = {
    MATCH_HOST: frozenset(), MATCH_SIBLING: frozenset(), MATCH_NAME: frozenset(), MATCH_TIMING: frozenset(),
    MATCH_INSIDE: MALWARE_STATUSES,
}
INFO_MATCHES = frozenset(match for match, statuses in _MATCH_STATUSES.items() if not statuses)


def entry_status(entry):
    """The worst status letter one correlation entry stands for, or '' (as
    far as its match lets it: _MATCH_STATUSES)."""
    allowed = _MATCH_STATUSES.get(entry.get('match'))
    if allowed is not None and not allowed:
        return ''
    status = finding_status(entry)
    return status if allowed is None or status in allowed else ''


def finding_status(entry):
    """The worst status letter of what an entry says (its detection
    severity, its centralbox verdict), however it was matched; ''."""
    candidates = []
    result = entry.get('centralbox')
    if isinstance(result, dict) and result.get('verdict') in _VERDICT_STATUS:
        candidates.append(_VERDICT_STATUS[result['verdict']])
    severity = _SEVERITY_STATUS.get(entry.get('severity') or '')
    if severity:
        candidates.append(severity)
    return dominant_status(candidates, default='')


def correlation_status(entries):
    """The worst status of a line's entries by the line-verdict precedence
    (B > P > C > A > ! > G > S > I > J), skipping logs from another system; ''
    when no entry has one."""
    statuses = [
        status for status in (entry_status(entry) for entry in entries if entry.get('system') != SYSTEM_DIFFERENT)
        if status
    ]
    return dominant_status(statuses, default='')


def _signature(uploaded_log, upload_ids, scope, name):
    """sha1 over everything the correlations depend on (see CorrelationCache)."""
    related = sorted(
        UploadedLog.objects.filter(pk__in=upload_ids).values_list('pk', 'content_hash', 'log_type')
    )
    rows = UploadedLogFileHash.objects.filter(upload_id__in=upload_ids)
    # The related logs' own hash rows: they are rebuilt after the upload (in
    # the background, with the stats), without changing the content hash.
    rows_state = rows.aggregate(n=Count('pk'), latest=Max('pk'))
    md5s = rows.exclude(md5='').values('md5')
    # The SHA256s of the related logs, plus those their MD5s stand for
    # (pairs seen in any log, and centralbox's MD5 answers): a newer verdict
    # for any of them changes the correlations.
    verdicts_changed = HashVerdict.objects.filter(
        Q(sha256__in=rows.exclude(sha256='').values('sha256'))
        | Q(sha256__in=UploadedLogFileHash.objects.filter(md5__in=md5s).exclude(sha256='').values('sha256'))
        | Q(sha256__in=HashAlias.objects.filter(md5__in=md5s).exclude(sha256='').values('sha256')),
    ).aggregate(latest=Max('checked_at'))['latest']
    aliases_changed = HashAlias.objects.filter(md5__in=md5s).aggregate(latest=Max('checked_at'))['latest']
    pairs_changed = UploadedLogFileHash.objects.filter(md5__in=md5s).exclude(sha256='').aggregate(
        latest=Max('pk'),
    )['latest']
    # The machine signals of the upload and its related logs (same-system
    # badges): rebuilt with the stats, like the hash rows.
    signals_state = UploadedLogMachineSignal.objects.filter(
        upload_id__in=[uploaded_log.pk, *upload_ids],
    ).aggregate(n=Count('pk'), latest=Max('pk'))
    # The upload's own analyses: their rule verdicts pick the timing anchors.
    # A re-analysis rewrites the row (updated_at); tag updates do not.
    analyses = UploadedLogAnalysis.objects.filter(upload=uploaded_log).aggregate(
        n=Count('pk'), latest=Max('updated_at'),
    )
    raw = json.dumps([
        CORRELATION_VERSION, uploaded_log.content_hash, scope, name, related,
        signals_state['n'] or 0, signals_state['latest'] or 0,
        analyses['n'] or 0, analyses['latest'].isoformat() if analyses['latest'] else '',
        verdicts_changed.isoformat() if verdicts_changed else '',
        aliases_changed.isoformat() if aliases_changed else '',
        pairs_changed or 0,
        rows_state['n'] or 0, rows_state['latest'] or 0,
    ], default=str)
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()


# How an entry was matched when not through the line's own file (correlation_keys).
MATCH_NOTES = {
    MATCH_ARGUMENT: 'file in command line',
    'registry': 'same registry value',
    'service': 'same service',
    'task': 'same task',
    'extension': 'same extension',
    'clsid': 'same CLSID',
    'firewall': 'same firewall rule',
    'uninstall': 'same installed program',
    'msi': 'same installed program',
    'app': 'same installed program (by name)',
    'browser': 'same browser setting',
    MATCH_HOST: 'host program',
    MATCH_SIBLING: 'detected file in same folder',
    MATCH_NAME: 'same file name elsewhere',
    MATCH_SAME_HASH: 'same file content elsewhere',
    MATCH_INSIDE: 'inside this folder',
    MATCH_TIMING: 'at the same time',
}
# Matches whose note names the file the entry is about.
_NOTE_FILE_MATCHES = frozenset({MATCH_ARGUMENT, MATCH_SIBLING, MATCH_NAME, MATCH_SAME_HASH, MATCH_INSIDE})


def summary_note(entries, status, own_upload_id=''):
    """What the entry that gave a line its correlation status says, for the
    log page's summary box: the detection name or family, the centralbox
    verdict if any, and the log type it was found in (never log ids)."""
    for entry in entries:
        if entry.get('system') == SYSTEM_DIFFERENT or entry_status(entry) != status:
            continue
        result = entry.get('centralbox') or {}
        name = result.get('family') or result.get('malware_type') or entry.get('detection') or ''
        if entry.get('kind') == 'evidence':
            name = evidence_text(entry)
        elif entry.get('kind') == 'mention':
            name = mention_text(entry)
        elif entry.get('kind') == 'file_info':
            name = 'signature ' + entry['signature'] if entry.get('signature') else 'file details'
        verdict = result.get('verdict') or ''
        where = 'in detected folder' if entry.get('in_folder') else ''
        how = MATCH_NOTES.get(entry.get('match') or '', '')
        if entry.get('match') in _NOTE_FILE_MATCHES and entry.get('file'):
            how = f"{how}: {entry['file']}"
        source = 'Defender' if entry.get('source') == 'defender' else ''
        # An entry of the log itself (Defender events of its Addition part).
        found_in = "this log's Addition part" if own_upload_id and entry.get('upload_id') == own_upload_id \
            else entry.get('log_type', '')
        parts = [
            part for part in (name, f'centralbox: {verdict}' if verdict else '', source, how, where, found_in)
            if part
        ]
        return ' · '.join(parts) or 'finding'
    return 'finding'


def _empty(scope='', name=''):
    return {'scope': scope, 'name': name, 'lines': {}, 'statuses': {}, 'notes': {}}


def _own_defender_detections(uploaded_log):
    """True when a merged FRST&Addition log's own Addition part lists a
    Defender detection of a file."""
    if uploaded_log.log_type != LOG_TYPE_FRST_AND_ADDITION:
        return False
    return bool(iter_addition_defender_detections(uploaded_log.content or ''))


def _lookup(uploaded_log, user):
    """(answer, None) when there is nothing to correlate, else (None, (upload
    ids, scope, name, scope_key, signature, cache row or None))."""
    if uploaded_log.log_type not in UploadedLog.ANALYZED_LOG_TYPES:
        return _empty(), None
    upload_ids, scope, name = related_upload_ids(uploaded_log, user)
    # A merged FRST&Addition log speaks for itself through the Defender
    # events of its Addition part, with or without related logs.
    if not upload_ids and not _own_defender_detections(uploaded_log):
        return _empty(scope, name), None
    if scope == SCOPE_CASE and user is not None:
        scope_key = f'case:{user.pk}'
    else:
        scope_key = 'user' if scope == SCOPE_USER else 'self'
    signature = _signature(uploaded_log, upload_ids, scope, name)
    cached = CorrelationCache.objects.filter(upload=uploaded_log, scope_key=scope_key).first()
    if cached is not None and not isinstance(cached.payload, dict):
        cached = None
    return None, (upload_ids, scope, name, scope_key, signature, cached)


def cached_correlations(uploaded_log, user=None):
    """(answer or None, fresh) without computing anything: the stored answer
    even when it is outdated (fresh False), None when nothing is stored yet.
    For the log page, which shows it at once and asks
    correlations_for_upload (through the endpoint) when it is not fresh.
    Never raises."""
    try:
        answer, state = _lookup(uploaded_log, user)
        if answer is not None:
            return answer, True
        _ids, _scope, _name, _key, signature, cached = state
        if cached is None:
            return None, False
        return cached.payload, cached.signature == signature
    except Exception:
        logger.exception('Reading cached correlations failed for %s', getattr(uploaded_log, 'upload_id', '?'))
        return None, True


def correlations_for_upload(uploaded_log, user=None):
    """{scope, name, lines: {stripped line text: [entry]}, statuses: {line text:
    status letter}, notes: {line text: summary note}} for the upload's lines
    with a file seen in a related log (related_upload_ids). Cached per viewer
    scope (CorrelationCache) and recomputed when the signature changes. Empty
    lines for anything else. Never raises."""
    try:
        answer, state = _lookup(uploaded_log, user)
        if answer is not None:
            return answer
        upload_ids, scope, name, scope_key, signature, cached = state
        if cached is not None and cached.signature == signature:
            return cached.payload
        payload = _fresh_payload(uploaded_log)
        if payload is None:
            return _empty(scope, name)
        result = _compute(uploaded_log, upload_ids, payload)
        statuses = {text: correlation_status(entries) for text, entries in result.items()}
        answer = {
            'scope': scope, 'name': name, 'lines': result, 'statuses': statuses,
            'notes': {
                text: summary_note(result[text], status, uploaded_log.upload_id)
                for text, status in statuses.items() if status
            },
        }
        _store(uploaded_log, scope_key, signature, answer)
        try:
            sync_stat_correlated_hashes(uploaded_log.pk, correlated_sha256s(answer))
        except Exception:
            logger.exception('Storing correlated hashes in stats failed for %s', uploaded_log.upload_id)
        return answer
    except Exception:
        logger.exception('Case correlations failed for %s', getattr(uploaded_log, 'upload_id', '?'))
        return _empty()


# --- The other way round: which FRST / Addition lines point at a line of
# another log (its page and the analyzer show them on that log's lines).

# What a forward entry is, in a few words, for the reverse view.
_REVERSE_WHAT = {
    'hash': 'file hash', 'detection': 'detection', 'fixlog': 'fixlist result', 'file_info': 'file details',
    'evidence': 'timeline', 'mention': 'mention',
}
# FRST line verdicts that colour a reverse marker; the others stay neutral.
REVERSE_MARKER_STATUSES = FLAGGED_STATUSES


def _reverse_what(entry):
    if entry.get('kind') == 'mention' and entry.get('role'):
        return entry['role']
    return _REVERSE_WHAT.get(entry.get('kind'), entry.get('kind') or '')


def _frst_line_facts(frst, texts):
    """{stripped line text: (first line number, rule status)} of an FRST /
    Addition log, for the texts asked. The status comes from a fresh analysis,
    the log's own rule set first ('' when there is none)."""
    wanted = set(texts)
    numbers = _first_line_numbers(frst.content, wanted)
    statuses = {}
    for line in (_fresh_payload(frst) or {}).get('lines') or ():
        if isinstance(line, dict):
            text = (line.get('line') or '').strip()
            if text in wanted and text not in statuses:
                statuses[text] = line.get('dominant_status') or ''
    return {text: (numbers.get(text, 0), statuses.get(text, '')) for text in wanted}


def reverse_correlations(uploaded_log, user=None, compute=False):
    """{scope, name, fresh, lines: {line no: [entry]}, texts: {line no:
    stripped text}} for a log that is not an FRST / Addition log: the lines
    of its related FRST / Addition logs (related_upload_ids) whose
    correlations name one of its lines, under that line's number.

    Read from those logs' correlations: the stored ones only (`fresh` False
    when one of them is outdated or missing), or computed when needed with
    `compute` (the endpoint). Each entry: kind 'reverse', the FRST log's
    upload_id / log_type, its line_no and text, its rule status
    (`line_status`), `what` this log says there, and the forward entry's
    match, in_folder and system. Never raises."""
    answer = {'scope': '', 'name': '', 'fresh': True, 'lines': {}, 'texts': {}}
    try:
        if uploaded_log.log_type in UploadedLog.ANALYZED_LOG_TYPES:
            return answer
        upload_ids, scope, name = related_upload_ids(uploaded_log, user)
        answer['scope'], answer['name'] = scope, name
        if not upload_ids:
            return answer
        analyzed = UploadedLog.objects.filter(
            pk__in=upload_ids, log_type__in=UploadedLog.ANALYZED_LOG_TYPES,
        ).order_by('-created_at', '-pk')
        lines = {}
        seen = set()
        own_id = uploaded_log.upload_id
        for frst in analyzed:
            if compute:
                forward, fresh = correlations_for_upload(frst, user), True
            else:
                forward, fresh = cached_correlations(frst, user)
            answer['fresh'] = answer['fresh'] and bool(fresh)
            texts = (forward or {}).get('lines') if isinstance(forward, dict) else None
            if not isinstance(texts, dict):
                continue
            hits = {}
            for text, entries in texts.items():
                # A 'files inside' summary stands for many lines, not its first.
                found = [
                    entry for entry in entries or ()
                    if isinstance(entry, dict) and entry.get('upload_id') == own_id and entry.get('line_no')
                    and entry.get('role') != ROLE_FILES_INSIDE
                ]
                if found:
                    hits[text] = found
            if not hits:
                continue
            facts = _frst_line_facts(frst, hits)
            for text, entries in hits.items():
                frst_no, status = facts.get(text, (0, ''))
                for entry in entries:
                    no = str(entry['line_no'])
                    slot = (no, frst.upload_id, text)
                    if slot in seen:
                        continue
                    seen.add(slot)
                    reverse = {
                        'kind': 'reverse', 'upload_id': frst.upload_id, 'log_type': frst.log_type,
                        'line_no': frst_no, 'text': text[:300], 'line_status': status,
                        'what': _reverse_what(entry), 'system': entry.get('system', SYSTEM_UNKNOWN),
                    }
                    for key in ('match', 'in_folder'):
                        if entry.get(key):
                            reverse[key] = entry[key]
                    lines.setdefault(no, []).append(reverse)
        if not lines:
            return answer
        for entries in lines.values():
            # Lines that name this one directly before the files inside a
            # folder it names, each in line order, so the cap never drops them.
            entries.sort(key=lambda entry: (bool(entry.get('in_folder')), entry['line_no'] or 0))
            del entries[MAX_ENTRIES_PER_LINE:]
        content_lines = (uploaded_log.content or '').split('\n')
        answer['lines'] = lines
        answer['texts'] = {
            no: content_lines[int(no) - 1].strip() for no in lines if 0 < int(no) <= len(content_lines)
        }
        return answer
    except Exception:
        logger.exception('Reverse correlations failed for %s', getattr(uploaded_log, 'upload_id', '?'))
        return {'scope': '', 'name': '', 'fresh': True, 'lines': {}, 'texts': {}}


def reverse_status(entries):
    """The marker status of a line's reverse entries: the worst FRST rule
    verdict among REVERSE_MARKER_STATUSES (logs of another system and
    informational matches left out: a flagged task says nothing about the
    wscript.exe it runs through), else ''."""
    return dominant_status([
        entry.get('line_status') for entry in entries if _reverse_rates(entry)
    ], default='')


def _reverse_rates(entry):
    return (entry.get('line_status') in REVERSE_MARKER_STATUSES and entry.get('system') != SYSTEM_DIFFERENT
            and entry.get('match') not in INFO_MATCHES)


def reverse_note(entries, status):
    """What the reverse entry that gave a line its marker status says."""
    for entry in entries:
        if entry.get('line_status') == status and _reverse_rates(entry):
            return f"{entry.get('log_type', '')} L{entry.get('line_no') or '?'}: {entry.get('text', '')[:120]}"
    return ''


def correlated_sha256s(answer):
    """The SHA256s an answer correlates with the log's lines, leaving out
    logs from another system and informational matches (as correlation_status
    does). For /stats/, which finds the hashes' centralbox tags (see
    tagging.centralbox_tags_by_sha)."""
    lines = answer.get('lines') if isinstance(answer, dict) else None
    return sorted({
        entry['sha256']
        for entries in (lines or {}).values() for entry in entries or ()
        if isinstance(entry, dict) and entry.get('sha256') and entry.get('system') != SYSTEM_DIFFERENT
        and entry.get('match') not in INFO_MATCHES
    })


def _store(uploaded_log, scope_key, signature, answer):
    """Cache a computed answer. Two requests computing it at once (the log
    page's refresh and its related-logs tab) race to create the row; the
    loser's answer is just as good, so a failed write is only logged."""
    try:
        with transaction.atomic():
            CorrelationCache.objects.update_or_create(
                upload=uploaded_log, scope_key=scope_key,
                defaults={'signature': signature, 'payload': answer},
            )
    except IntegrityError:
        pass
    except Exception:
        logger.exception('Storing correlations failed for %s', getattr(uploaded_log, 'upload_id', '?'))


class _LineEntries:
    """The entries of one analyzed line, each related log line once, each
    with `system` (does its log come from the upload's machine?)."""

    def __init__(self, text, verdicts):
        self.entries = []
        self.seen = set()
        self.program = installed_program(text)
        self.verdicts = verdicts
        # A created / modified files line: CreatedLine (see _add_timing).
        self.created = None

    def add(self, entry, match, in_folder=False, other_path='', slot=None):
        """Add `entry` unless its log line is listed already (or `slot`, for
        an entry that stands for several lines). True when added."""
        slot = slot or (entry.get('upload_id'), entry.get('line_no'), entry.get('kind'))
        if slot in self.seen:
            return False
        if match == 'app' and self.program and versions_differ(self.program[1], entry.get('version')):
            return False  # another version of a program with the same name
        self.seen.add(slot)
        extra = {}
        if match != MATCH_PATH:
            extra['match'] = match
        if in_folder:
            extra['in_folder'] = True
        if other_path:
            extra['other_path'] = other_path[:400]
        added = {**entry, **extra} if extra else entry
        added['system'] = self.verdicts.get(entry.get('upload_id'), SYSTEM_UNKNOWN)
        self.entries.append(added)
        return True


# How many entries a line gets per informational / copy match: detected
# siblings, files of the same name, other paths with the same content, lines
# and events at the same time.
MAX_RELATED_PER_LINE = 5
# Flagged entries of the files inside a folder line listed one by one; all
# others (and any beyond) are summed up per log and kind.
MAX_INSIDE_ENTRIES = 20
# The SHA256 of an empty file: copies of it are no copies of anything.
_EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


def _rank(entry):
    """Sort key: status-giving entries first, then by kind."""
    return (not entry_status(entry), KIND_RANK.get(entry.get('kind'), 9))


class _RelatedIndex:
    """Lookups over the index for files related to a line's file without
    sharing its path: detected files by folder, files by name, paths by
    content (SHA256) and the path keys in order (the files inside a folder)."""

    def __init__(self, index):
        self.index = index
        self.path_keys = sorted(key for key in index if is_path_key(key))
        self.detected_by_parent = {}
        self.by_name = {}
        self.paths_by_sha = {}
        self.shas_by_path = {}
        for key in self.path_keys:
            for entry in index[key]:
                if entry.get('folder'):
                    continue
                if entry['kind'] == 'detection' or (entry['kind'] == 'hash' and entry_status(entry) in MALWARE_STATUSES):
                    self.detected_by_parent.setdefault(ntpath.dirname(key), []).append((key, entry))
                sha = entry.get('sha256') if entry['kind'] in ('hash', 'file_info') else ''
                if sha and sha != _EMPTY_SHA256:
                    self.paths_by_sha.setdefault(sha, set()).add(key)
                    self.shas_by_path.setdefault(key, set()).add(sha)
            name = name_key(key)
            if name:
                self.by_name.setdefault(name, []).append(key)

    def siblings(self, key):
        """(path, entry) of detections of other files in the key's folder."""
        parent = ntpath.dirname(key)
        if not parent or is_broad_parent(parent):
            return []
        return [(path, entry) for path, entry in self.detected_by_parent.get(parent, ()) if path != key]

    def same_name(self, key):
        """Other paths of a file with the key's (uncommon) name."""
        name = name_key(key)
        return [path for path in self.by_name.get(name, ()) if path != key] if name else []

    def same_content(self, key):
        """Other paths with a SHA256 the key's file has."""
        paths = set()
        for sha in self.shas_by_path.get(key, ()):
            paths |= self.paths_by_sha[sha]
        paths.discard(key)
        return sorted(paths)

    def inside(self, folder):
        """(path, entries) of the keys below a folder key, in order."""
        prefix = folder.rstrip('\\') + '\\'
        start = bisect.bisect_left(self.path_keys, prefix)
        for position in range(start, len(self.path_keys)):
            path = self.path_keys[position]
            if not path.startswith(prefix):
                break
            yield path, self.index[path]


# Where programs are installed: two copies of a file there (another version
# folder, a vendor's shared DLL) are what installers do.
_INSTALLED_PREFIXES = ('c:\\program files', 'c:\\windows\\')


def _both_installed(key, other):
    return key.startswith(_INSTALLED_PREFIXES) and other.startswith(_INSTALLED_PREFIXES)


def _add_related(collector, related, key):
    """The files related to one of the line's files without sharing its
    path: detected siblings, copies (same content: their detections and
    hashes) and files of the same name. Copies and names between two
    installed programs' folders only when the copy is flagged."""
    added = 0
    for path, entry in related.siblings(key):
        if added >= MAX_RELATED_PER_LINE:
            break
        added += collector.add(entry, MATCH_SIBLING, other_path=path)
    for path in related.same_content(key)[:MAX_RELATED_PER_LINE]:
        for entry in related.index.get(path, ()):
            if entry['kind'] not in ('hash', 'detection') or entry.get('folder'):
                continue
            if _both_installed(key, path) and entry_status(entry) not in FLAGGED_STATUSES:
                continue
            collector.add(entry, MATCH_SAME_HASH, other_path=path)
    added = 0
    for path in related.same_name(key):
        if _both_installed(key, path):
            continue
        for entry in sorted(related.index.get(path, ()), key=_rank):
            if added >= MAX_RELATED_PER_LINE:
                return
            if not entry.get('folder'):
                added += collector.add(entry, MATCH_NAME, other_path=path)


# What the files inside a folder line are, in a few words, per kind.
_INSIDE_WHAT = {
    'hash': 'file hashes', 'detection': 'detections', 'fixlog': 'Fixlog results', 'file_info': 'file details',
    'evidence': 'Spor timeline entries', 'mention': 'mentions',
}


def _inside_what(entry):
    """What an entry about a file inside a folder line is, in a few words:
    a mention's role when it reads as one ("deleted by MAU"), else where in
    its log it is ("mentions in AMCACHE"), else its kind."""
    if entry['kind'] != 'mention':
        return _INSIDE_WHAT.get(entry['kind'], entry['kind'])
    role = entry.get('role') or ''
    if ' ' in role:
        return role
    section = entry.get('section') or ''
    return f'mentions in {section}' if section else 'mentions'


def _add_inside(collector, related, folder):
    """What other logs say about the files inside a folder line's folder:
    flagged entries one by one, the others summed up per (log, what) in a
    'files inside' mention. Only malware and PUPs colour the line
    (_MATCH_STATUSES)."""
    if is_broad_parent(folder):
        return
    listed = 0
    groups = {}
    for path, entries in related.inside(folder):
        for entry in entries:
            if finding_status(entry) in FLAGGED_STATUSES and listed < MAX_INSIDE_ENTRIES:
                listed += collector.add(entry, MATCH_INSIDE, other_path=path)
                continue
            # The file names in order, each once (a dict keeps the order).
            group = groups.setdefault((entry['upload_id'], _inside_what(entry)), {'first': entry, 'files': {}})
            group['files'].setdefault(entry.get('file') or file_name(path))
    for (upload_id, what), group in groups.items():
        first, files = group['first'], list(group['files'])
        names = ', '.join(files[:5]) + (', ...' if len(files) > 5 else '')
        collector.add(
            _plain_mention(upload_id, first.get('log_type', ''), first.get('line_no'), f'{len(files)} {what}: {names}',
                           ROLE_FILES_INSIDE),
            MATCH_INSIDE, slot=(ROLE_FILES_INSIDE, upload_id, what),
        )


# --- At the same time: created-files lines of the log within a few minutes of
# a flagged one, and the related Spor logs' timeline events then.

TIMING_WINDOW = timedelta(minutes=2)
# More created files in one minute than this is Windows Update or an
# installer: that minute ties nothing together.
_TIMING_CROWDED_MINUTE = 25
_TIMING_SKIP_PREFIXES = ('c:\\windows\\', 'c:\\program files\\windowsapps\\')
# Scheduled task files are Windows' files written for whoever made the task.
_TIMING_KEEP_PREFIXES = ('c:\\windows\\system32\\tasks\\',)
# A created-files line flagged by its rule verdict, or by its correlations
# (which flag more lines with '!', so only malware and PUPs count there).
_TIMING_RULE_ANCHORS = frozenset({'B', 'P', '!'})
_TIMING_TIME_FORMAT = '%Y-%m-%d %H:%M'
ROLE_SAME_TIME = 'same time'

# A created / modified files line: its text, created time (to the minute),
# path key and rule status.
CreatedLine = namedtuple('CreatedLine', 'text when key status')
# A Spor TIMELINE item in the PC's local time.
TimelineEvent = namedtuple('TimelineEvent', 'when upload_id line_no item key')


def _created_line(text, key, status):
    """The CreatedLine of a created / modified files line ('____D' folder
    lines too: (CreatedLine, is folder)), or (None, False)."""
    entry = ex.extract_onemonth(text) if text[:1].isdigit() else None
    if entry is None or not entry.date:
        return None, False
    try:
        when = datetime.fromisoformat(entry.date).replace(second=0)
    except ValueError:
        return None, False
    return CreatedLine(text, when, key, status), 'd' in (entry.attributes or '').lower()


def _timed_lines(collectors):
    """The created lines worth timing: not Windows' own files (task files
    are), not in a crowded minute."""
    found = [
        collector.created for collector in collectors.values()
        if collector.created is not None and not (
            collector.created.key.startswith(_TIMING_SKIP_PREFIXES)
            and not collector.created.key.startswith(_TIMING_KEEP_PREFIXES)
        )
    ]
    per_minute = Counter(line.when for line in found)
    return [line for line in found if per_minute[line.when] <= _TIMING_CROWDED_MINUTE]


def _spor_timeline_events(upload_id, lines, known):
    """[TimelineEvent] of a Spor log's TIMELINE items in the PC's local time;
    [] when its header does not tell the time base. Spor names only the
    offset when it ran: events before a daylight saving change are an hour
    off (and then seldom matched)."""
    offset = spor_log.local_offset_minutes(lines)
    if offset is None:
        return []
    events = []
    for line_no, item in spor_log.iter_timeline_items(lines, known):
        try:
            when = datetime.fromisoformat(item.time) + timedelta(minutes=offset)
        except ValueError:
            continue
        key = normalized_path(item.item) if spor_log.is_path(item.item) else ''
        events.append(TimelineEvent(when, upload_id, line_no, item, key))
    return events


def _add_timing(uploaded_log, collectors, spor_logs, verdicts):
    """Created-files lines within TIMING_WINDOW of a flagged created-files
    line (its rule status B / P / !, or correlation status B / P) get that
    line; those lines and the flagged ones get the timeline events of that
    time of the related Spor logs of this machine (`spor_logs`: (upload_id,
    lines, known paths)). Informational: never a status."""
    created = _timed_lines(collectors)
    anchors = sorted((
        line for line in created
        if line.status in _TIMING_RULE_ANCHORS or correlation_status(collectors[line.text].entries) in MALWARE_STATUSES
    ), key=lambda line: line.when)
    if not anchors:
        return
    numbers = _first_line_numbers(uploaded_log.content, {anchor.text for anchor in anchors})
    anchor_times = [anchor.when for anchor in anchors]
    clustered = {anchor.text for anchor in anchors}
    for line in created:
        low = bisect.bisect_left(anchor_times, line.when - TIMING_WINDOW)
        high = bisect.bisect_right(anchor_times, line.when + TIMING_WINDOW)
        close = sorted(
            (anchor for anchor in anchors[low:high] if anchor.text != line.text),
            key=lambda anchor: abs(anchor.when - line.when),
        )[:MAX_RELATED_PER_LINE]
        for anchor in close:
            collectors[line.text].add(_plain_mention(
                uploaded_log.upload_id, uploaded_log.log_type, numbers.get(anchor.text, 0), anchor.text,
                ROLE_SAME_TIME, file_name(anchor.key), time=anchor.when.strftime(_TIMING_TIME_FORMAT),
            ), MATCH_TIMING)
            clustered.add(line.text)
    events = sorted(
        (event for upload_id, lines, known in spor_logs if verdicts.get(upload_id) != SYSTEM_DIFFERENT
         for event in _spor_timeline_events(upload_id, lines, known)),
        key=lambda event: event.when,
    )
    times = [event.when for event in events]
    for line in created:
        if line.text not in clustered:
            continue
        # FRST gives the minute only: the window runs to its last second.
        low = bisect.bisect_left(times, line.when - TIMING_WINDOW)
        high = bisect.bisect_right(times, line.when + TIMING_WINDOW + timedelta(seconds=59))
        added = 0
        for event in sorted(events[low:high], key=lambda event: abs(event.when - line.when)):
            if added >= MAX_RELATED_PER_LINE:
                break
            if event.key == line.key:
                continue  # the line's own file: matched by its path already
            item = event.item
            added += collectors[line.text].add(_plain_mention(
                event.upload_id, LOG_TYPE_SPOR, event.line_no, item.text, ROLE_SAME_TIME,
                file_name(item.item) if spor_log.is_path(item.item) else '', section=spor_log.SECTION_TIMELINE,
                time=event.when.strftime('%Y-%m-%d %H:%M:%S'), tags=item.tags, extra=[('time in log', item.time)],
            ), MATCH_TIMING)


def _compute(uploaded_log, upload_ids, payload):
    """{line text: [entry]} from scratch."""
    index = {}
    covered = _hash_entries(upload_ids, index)
    _detection_entries(upload_ids, index, covered)
    _fixlog_entries(upload_ids, index)
    _addition_entries(upload_ids, index, own=uploaded_log)
    spor_logs = []
    _spor_entries(upload_ids, index, spor_logs)
    _frst_search_entries(upload_ids, index)
    _shortcut_entries(upload_ids, index)
    _mau_entries(upload_ids, index)
    # A scanner that detected a whole folder (e.g. AdwCleaner's Folders
    # section) also speaks for the files and folders inside it, and so does
    # a folder mention (a Defender path exclusion).
    detections = {}
    for key, entries in index.items():
        found = [entry for entry in entries if entry['kind'] == 'detection' or entry.get('folder')]
        if found:
            detections[key] = found
    related = _RelatedIndex(index)
    verdicts = _system_verdicts(uploaded_log, upload_ids)
    collectors = {}
    for line in payload.get('lines') or []:
        if not isinstance(line, dict):
            continue
        text = (line.get('line') or '').strip()
        if not text or text in collectors:
            continue
        collector = collectors[text] = _LineEntries(text, verdicts)
        own_files = []
        keys = line_keys(line)
        for key, match in keys:
            for entry in index.get(key) or ():
                collector.add(entry, match)
            if not is_path_key(key) or match == MATCH_HOST:
                continue  # typed keys have no folders; a host program speaks for nothing
            own_files.append(key)
            parent, previous = ntpath.dirname(key), key
            while detections and parent and parent != previous and len(collector.entries) < MAX_ENTRIES_PER_LINE:
                for entry in detections.get(parent, ()):
                    collector.add(entry, match, in_folder=True)
                parent, previous = ntpath.dirname(parent), parent
        for key in own_files:
            _add_related(collector, related, key)
        # line_keys gives the line's own file first.
        main = next((key for key, match in keys if match == MATCH_PATH), '')
        if main:
            collector.created, folder = _created_line(text, main, line.get('dominant_status') or '')
            if folder:
                _add_inside(collector, related, main)
    _add_timing(uploaded_log, collectors, spor_logs, verdicts)
    result = {}
    for text, collector in collectors.items():
        entries = collector.entries
        if not entries:
            continue
        # Informational entries last; over the cap, status-giving ones first,
        # so the cap never drops one of those.
        capped = len(entries) > MAX_ENTRIES_PER_LINE
        entries.sort(key=lambda entry: (entry.get('match') in INFO_MATCHES, *(_rank(entry) if capped else ())))
        result[text] = entries[:MAX_ENTRIES_PER_LINE]
    return result


# What a same-machine suggestion matched on, for the related-logs tab (the
# values themselves are never shown).
SAME_MACHINE_LABELS = {
    KIND_SID: 'machine SID',
    KIND_DISK: 'disk ID',
    'computer+hw': 'computer name and hardware',
}


def same_machine_logs(uploaded_log, exclude_pks=(), limit=20):
    """[(upload pk, [labels])] of live logs outside `exclude_pks` that look
    like they come from the upload's machine, newest first: a shared machine
    SID or Disk ID, or the same computer name together with the same
    hardware; never one the full comparison calls a different system. For
    logs uploaded under another forum name (or none). Never raises."""
    try:
        own = {}
        for kind, value in UploadedLogMachineSignal.objects.filter(upload=uploaded_log).values_list('kind', 'value'):
            own.setdefault(kind, set()).add(value)
        query = Q()
        for kind in STRONG_KINDS:
            if own.get(kind):
                query |= Q(kind=kind, value__in=own[kind])
        excluded = {uploaded_log.pk, *exclude_pks}
        live = UploadedLogMachineSignal.objects.filter(upload__deleted_at__isnull=True).exclude(upload_id__in=excluded)
        found = {}
        if query:
            for upload_pk, kind in live.filter(query).values_list('upload_id', 'kind').distinct():
                found.setdefault(upload_pk, set()).add(kind)
        if own.get(KIND_COMPUTER) and own.get(KIND_HW):
            # Hardware alone is shared by many machines ("System Product
            # Name"): only the logs with the same computer name are checked.
            named = set(
                live.filter(kind=KIND_COMPUTER, value__in=own[KIND_COMPUTER]).values_list('upload_id', flat=True)[:500]
            )
            if named:
                for upload_pk in set(
                    live.filter(upload_id__in=named, kind=KIND_HW, value__in=own[KIND_HW])
                    .values_list('upload_id', flat=True)
                ):
                    found.setdefault(upload_pk, set()).update({KIND_COMPUTER, KIND_HW})
        if not found:
            return []
        matched = {}
        for upload_pk, kinds in found.items():
            labels = [SAME_MACHINE_LABELS[kind] for kind in STRONG_KINDS if kind in kinds]
            if KIND_COMPUTER in kinds and KIND_HW in kinds:
                labels.append(SAME_MACHINE_LABELS['computer+hw'])
            if labels:
                matched[upload_pk] = labels
        if not matched:
            return []
        newest = list(
            UploadedLog.objects.filter(pk__in=list(matched)).order_by('-created_at', '-pk')
            .values_list('pk', flat=True)[:limit * 2]
        )
        theirs = stored_signals(newest)
        own_all = stored_signals([uploaded_log.pk])[uploaded_log.pk]
        result = [
            (pk, matched[pk]) for pk in newest if compare(own_all, theirs.get(pk) or {}) != SYSTEM_DIFFERENT
        ]
        return result[:limit]
    except Exception:
        logger.exception('Finding same-machine logs failed for %s', getattr(uploaded_log, 'upload_id', '?'))
        return []
