"""What other logs of the same infection case say about the files of an FRST log.

For each FRST / Addition line whose file path also appears in another log of
one of the upload's cases, collect what that log says about the file:

- a hash row (Malwarebytes, HitmanPro, Trojan Killer, MAU, Fixlog File: and
  Folder: blocks, folder listings): the detection, SHA256 / MD5 and the
  stored centralbox result if any (a bare hash counts too);
- a detection of a scanner without hashes (ESET, Emsisoft, AdwCleaner, and
  hash-less detections of the others): detection name and action;
- a Fixlog result ("<path> => moved successfully").

Database and local parsing only: nothing is ever sent to centralbox. Paths
are compared with the analyzer's own key (normalize_path, lowercased).
"""

import hashlib
import json
import logging
import ntpath
import re

from .analyzer import ANALYSIS_PAYLOAD_FORMAT
from .correlation_keys import MATCH_PATH, argument_paths, is_path_key, line_keys, target_keys
from .file_hashes import _as_path, normalized_path
from .log_highlighting import highlight_log, threat_severity
from django.db import IntegrityError, transaction
from django.db.models import Count, Max, Q
from django.db.models.functions import Substr

from .machine_signals import (  # noqa: F401 (re-exported)
    KIND_COMPUTER, KIND_DISK, KIND_HW, KIND_PROFILE, KIND_SID, STRONG_KINDS, SYSTEM_DIFFERENT, SYSTEM_LIKELY, SYSTEM_SAME, SYSTEM_SIGNAL_CHARS,
    SYSTEM_UNKNOWN, compare, extract_signals, log_signals,
)
from .models import (
    CorrelationCache, HashAlias, HashVerdict, InfectionCaseLog, UploadedLog, UploadedLogAnalysis,
    UploadedLogFileHash, UploadedLogMachineSignal, iter_fixlog_results,
)
from .status_types import STATUS_PRECEDENCE

logger = logging.getLogger(__name__)

MAX_ENTRIES_PER_LINE = 20
# Part of every cache signature: bump it when what is computed changes.
CORRELATION_VERSION = 8
# Detections are read from these logs' summary boxes (log_highlighting).
DETECTION_LOG_TYPES = ('ESET', 'Emsisoft', 'AdwCleaner', 'Malwarebytes', 'HitmanPro', 'Trojan Killer')
# Defender events are read from these logs' "Windows Defender:" section.
ADDITION_LOG_TYPES = ('Addition', 'FRST&Addition')
LOG_TYPE_FRST_AND_ADDITION = 'FRST&Addition'


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
    """Any fresh cached analysis of the upload (the line texts are the same for every rule set)."""
    for payload in (
        UploadedLogAnalysis.objects.filter(upload=uploaded_log, source_content_hash=uploaded_log.content_hash)
        .values_list('payload', flat=True)
    ):
        if isinstance(payload, dict) and payload.get('format') == ANALYSIS_PAYLOAD_FORMAT:
            return payload
    return None


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
        .only('sha256', 'md5', 'line_no', 'anchor_line_no', 'detection', 'source', 'normalized_path',
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
# Defender's category prefix ("PUA:Win32/...") where the generic rating
# (threat_severity) would call it malware.
_DEFENDER_CATEGORY_SEVERITY = {
    'pua': 'p', 'puadlmanager': 'p', 'puaminer': 'p', 'puabundler': 'p', 'softwarebundler': 'p',
    'browsermodifier': 'p', 'adware': 'p', 'program': 'p', 'monitoringtool': 'p',
    'hacktool': 'g', 'remoteaccess': 'g', 'tool': 'g',
}


def defender_severity(threat):
    """Summary severity of a Defender threat name ("Trojan:Win32/Malgent!MSR")."""
    category = threat.split(':', 1)[0].strip().lower() if ':' in threat else ''
    return _DEFENDER_CATEGORY_SEVERITY.get(category) or threat_severity(threat)


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
        for line_no, target, result in iter_fixlog_results(content):
            entry = {
                'kind': 'fixlog',
                'upload_id': upload.upload_id,
                'log_type': 'Fixlog',
                'line_no': line_no,
                'result': result.strip()[:200],
            }
            for key in target_keys(target, result):
                index.setdefault(key, []).append(entry)
        if 'Threat' not in content:
            continue
        # Windows Defender events in the Fixlog: detections like a scanner's.
        _add_defender_entries(index, upload.upload_id, 'Fixlog', iter_defender_detections(content))


def _add_defender_entries(index, upload_id, log_type, detections):
    for line_no, threat, action, path in detections:
        key = normalized_path(path)
        if not key:
            continue
        index.setdefault(key, []).append({
            'kind': 'detection',
            'upload_id': upload_id,
            'log_type': log_type,
            'line_no': line_no,
            'detection': threat[:255],
            'action': action[:100],
            'severity': defender_severity(threat),
            'source': 'defender',
        })


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
    lines = content[start:].split('\n')
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
                current[0][key] = match.group(2)
                current[1][key] = first_line_no + offset
                last_key = key
            continue
        if not line.strip():
            last_key = None
            continue
        if current is not None and last_key in ('path', 'name', 'action'):
            current[0][last_key] += line
    return events


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
                keys = argument_paths(cmdline.group(1)) if cmdline else []
                path = keys[0] if keys else ''
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
    if own is not None and own.log_type == LOG_TYPE_FRST_AND_ADDITION:
        uploads.append(own)
    for upload in uploads:
        _add_defender_entries(
            index, upload.upload_id, 'Addition', iter_addition_defender_detections(upload.content or ''),
        )


def _add_system_badges(uploaded_log, index):
    """Give every entry `system`: does its log come from the same machine?"""
    upload_ids = {entry['upload_id'] for entries in index.values() for entry in entries}
    if not upload_ids:
        return
    pks = dict(UploadedLog.objects.filter(upload_id__in=upload_ids).values_list('upload_id', 'pk'))
    signals = stored_signals({uploaded_log.pk, *pks.values()})
    own = signals.get(uploaded_log.pk) or {}
    verdict_by_upload = {upload_id: compare(own, signals.get(pk) or {}) for upload_id, pk in pks.items()}
    for entries in index.values():
        for entry in entries:
            entry['system'] = verdict_by_upload.get(entry['upload_id'], SYSTEM_UNKNOWN)


# A finding as a line-verdict status letter (status_types): detection
# severities from the log pages, centralbox verdicts. Fixlog results and
# unchecked / unknown hashes have none.
_SEVERITY_STATUS = {'b': 'B', 'p': 'P', 'g': 'G', 'w': '!', 'c': 'C', 'j': 'J', 'i': 'I'}
_VERDICT_STATUS = {'malicious': 'B', 'suspicious': '!', 'clean': 'C'}


def entry_status(entry):
    """The worst status letter one correlation entry stands for, or ''."""
    candidates = []
    result = entry.get('centralbox')
    if isinstance(result, dict) and result.get('verdict') in _VERDICT_STATUS:
        candidates.append(_VERDICT_STATUS[result['verdict']])
    severity = _SEVERITY_STATUS.get(entry.get('severity') or '')
    if severity:
        candidates.append(severity)
    return min(candidates, key=STATUS_PRECEDENCE.index) if candidates else ''


def correlation_status(entries):
    """The worst status of a line's entries by the line-verdict precedence
    (B > P > C > A > ! > G > S > I > J), skipping logs from another system; ''
    when no entry has one."""
    statuses = [
        status for status in (entry_status(entry) for entry in entries if entry.get('system') != SYSTEM_DIFFERENT)
        if status
    ]
    return min(statuses, key=STATUS_PRECEDENCE.index) if statuses else ''


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
    raw = json.dumps([
        CORRELATION_VERSION, uploaded_log.content_hash, scope, name, related,
        signals_state['n'] or 0, signals_state['latest'] or 0,
        verdicts_changed.isoformat() if verdicts_changed else '',
        aliases_changed.isoformat() if aliases_changed else '',
        pairs_changed or 0,
        rows_state['n'] or 0, rows_state['latest'] or 0,
    ], default=str)
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()


# How an entry was matched when not through the line's own file (correlation_keys).
MATCH_NOTES = {
    'argument': 'file in command line',
    'registry': 'same registry value',
    'service': 'same service',
    'task': 'same task',
    'extension': 'same extension',
    'clsid': 'same CLSID',
    'firewall': 'same firewall rule',
}


def summary_note(entries, status):
    """What the entry that gave a line its correlation status says, for the
    log page's summary box: the detection name or family, the centralbox
    verdict if any, and the log type it was found in (never log ids)."""
    for entry in entries:
        if entry.get('system') == SYSTEM_DIFFERENT or entry_status(entry) != status:
            continue
        result = entry.get('centralbox') or {}
        name = result.get('family') or result.get('malware_type') or entry.get('detection') or ''
        verdict = result.get('verdict') or ''
        where = 'in detected folder' if entry.get('in_folder') else ''
        how = MATCH_NOTES.get(entry.get('match') or '', '')
        source = 'Defender' if entry.get('source') == 'defender' else ''
        parts = [
            part for part in (
                name, f'centralbox: {verdict}' if verdict else '', source, how, where, entry.get('log_type', ''),
            )
            if part
        ]
        return ' · '.join(parts) or 'finding'
    return 'finding'


def _empty(scope='', name=''):
    return {'scope': scope, 'name': name, 'lines': {}, 'statuses': {}, 'notes': {}}


def _lookup(uploaded_log, user):
    """(answer, None) when there is nothing to correlate, else (None, (upload
    ids, scope, name, scope_key, signature, cache row or None))."""
    if uploaded_log.log_type not in UploadedLog.ANALYZED_LOG_TYPES:
        return _empty(), None
    upload_ids, scope, name = related_upload_ids(uploaded_log, user)
    if not upload_ids:
        return _empty(scope, name), None
    scope_key = f'case:{user.pk}' if scope == SCOPE_CASE and user is not None else 'user'
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
                text: summary_note(result[text], status) for text, status in statuses.items() if status
            },
        }
        _store(uploaded_log, scope_key, signature, answer)
        return answer
    except Exception:
        logger.exception('Case correlations failed for %s', getattr(uploaded_log, 'upload_id', '?'))
        return _empty()


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


def _compute(uploaded_log, upload_ids, payload):
    """{line text: [entry]} from scratch."""
    index = {}
    covered = _hash_entries(upload_ids, index)
    _detection_entries(upload_ids, index, covered)
    _fixlog_entries(upload_ids, index)
    _addition_entries(upload_ids, index, own=uploaded_log)
    if not index:
        return {}
    # A scanner that detected a whole folder (e.g. AdwCleaner's Folders
    # section) also speaks for the files and folders inside it.
    detections = {}
    for key, entries in index.items():
        found = [entry for entry in entries if entry['kind'] == 'detection']
        if found:
            detections[key] = found
    result = {}
    for line in payload.get('lines') or []:
        if not isinstance(line, dict):
            continue
        text = (line.get('line') or '').strip()
        if not text or text in result:
            continue
        entries = []
        seen = set()

        def add(entry, match, in_folder=False):
            slot = (entry.get('upload_id'), entry.get('line_no'), entry.get('kind'))
            if slot in seen:
                return
            seen.add(slot)
            extra = {}
            if match != MATCH_PATH:
                extra['match'] = match
            if in_folder:
                extra['in_folder'] = True
            entries.append({**entry, **extra} if extra else entry)

        for key, match in line_keys(line):
            for entry in index.get(key) or ():
                add(entry, match)
            if not is_path_key(key):
                continue  # typed keys have no folders
            parent, previous = ntpath.dirname(key), key
            while detections and parent and parent != previous and len(entries) < MAX_ENTRIES_PER_LINE:
                for entry in detections.get(parent, ()):
                    add(entry, match, in_folder=True)
                parent, previous = ntpath.dirname(parent), parent
        if entries:
            result[text] = entries[:MAX_ENTRIES_PER_LINE]
    if result:
        _add_system_badges(uploaded_log, result)
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
        pair = own.get(KIND_COMPUTER) and own.get(KIND_HW)
        if pair:
            query |= Q(kind=KIND_COMPUTER, value__in=own[KIND_COMPUTER]) | Q(kind=KIND_HW, value__in=own[KIND_HW])
        if not query:
            return []
        excluded = {uploaded_log.pk, *exclude_pks}
        found = {}
        for upload_pk, kind in (
            UploadedLogMachineSignal.objects.filter(query, upload__deleted_at__isnull=True)
            .exclude(upload_id__in=excluded).values_list('upload_id', 'kind').distinct()
        ):
            found.setdefault(upload_pk, set()).add(kind)
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
