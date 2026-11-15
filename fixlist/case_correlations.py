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

from . import frst_extractors as ex
from .analyzer import ANALYSIS_PAYLOAD_FORMAT
from .file_hashes import _as_path, normalized_path
from .log_highlighting import highlight_log, threat_severity
from django.db.models import Count, Max, Q

from .models import (
    CorrelationCache, HashAlias, HashVerdict, InfectionCaseLog, UploadedLog, UploadedLogAnalysis,
    UploadedLogFileHash, iter_fixlog_results,
)
from .status_types import STATUS_PRECEDENCE

logger = logging.getLogger(__name__)

MAX_ENTRIES_PER_LINE = 20
# Part of every cache signature: bump it when what is computed changes.
CORRELATION_VERSION = 5
# Detections are read from these logs' summary boxes (log_highlighting).
DETECTION_LOG_TYPES = ('ESET', 'Emsisoft', 'AdwCleaner', 'Malwarebytes', 'HitmanPro', 'Trojan Killer')


SCOPE_CASE = 'case'
SCOPE_USER = 'user'


def related_upload_ids(uploaded_log, user):
    """(upload ids, scope, name): the logs to correlate the upload with.

    The other live logs of the viewer's own live cases that contain the
    upload (scope 'case'); if there are none, every other live log of the same
    forum user, any age, case-insensitive (scope 'user', name = the forum
    username); else nothing."""
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


# --- Same system? Computer names printed in log headers, and the Windows
# profile names in C:\Users\<name>\ paths.
_RAN_BY_RE = re.compile(r'^Ran by (.+?) \(.*?\) on (\S+) \(', re.MULTILINE)
_COMPUTER_NAME_RE = re.compile(r'^\s*Computer name(?: \.)*\s*:\s*(\S+)', re.MULTILINE | re.IGNORECASE)
_PROFILE_RE = re.compile(r'[A-Za-z]:\\Users\\([^\\"\r\n]{1,64})\\', re.IGNORECASE)
_SHARED_PROFILES = frozenset({'public', 'default', 'default user', 'all users', 'defaultuser0', 'username'})

SYSTEM_SAME = 'same'
SYSTEM_DIFFERENT = 'different'
SYSTEM_UNKNOWN = 'unknown'


def system_signals(content):
    """(computer names, profile names), lowercased, from a log's text."""
    content = content or ''
    computers = set()
    profiles = set()
    for user_name, computer in _RAN_BY_RE.findall(content):
        computers.add(computer.lower())
        profiles.add(user_name.strip().lower())
    for computer in _COMPUTER_NAME_RE.findall(content):
        computers.add(computer.lower())
    for profile in _PROFILE_RE.findall(content):
        profile = profile.strip().lower()
        if profile and profile not in _SHARED_PROFILES:
            profiles.add(profile)
    return computers, profiles


def same_system(a, b):
    """'same', 'different' or 'unknown' for two (computers, profiles) pairs:
    computer names decide when both logs print one, else profile names."""
    (computers_a, profiles_a), (computers_b, profiles_b) = a, b
    if computers_a and computers_b:
        return SYSTEM_SAME if computers_a & computers_b else SYSTEM_DIFFERENT
    if profiles_a and profiles_b:
        return SYSTEM_SAME if profiles_a & profiles_b else SYSTEM_DIFFERENT
    return SYSTEM_UNKNOWN


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
            key = normalized_path(_as_path(item.target))
            if not key:
                continue
            index.setdefault(key, []).append({
                'kind': 'detection',
                'upload_id': upload.upload_id,
                'log_type': upload.log_type,
                'line_no': item.line_no,
                'detection': item.name,
                'action': item.action,
                'severity': item.severity,
            })


def _fixlog_entries(upload_ids, index):
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type='Fixlog').only('pk', 'upload_id', 'content'):
        for line_no, target, result in iter_fixlog_results(upload.content or ''):
            key = normalized_path(_as_path(target))
            if not key:
                continue
            index.setdefault(key, []).append({
                'kind': 'fixlog',
                'upload_id': upload.upload_id,
                'log_type': 'Fixlog',
                'line_no': line_no,
                'result': result.strip()[:200],
            })


def _line_key(line):
    components = line.get('components') if isinstance(line.get('components'), dict) else {}
    path = components.get('filepath') or ''
    text = line.get('line') or ''
    if not path and ':\\' in text:
        try:
            path = ex.extract_any_frst_path(text) or ''
        except Exception:
            path = ''
    return normalized_path(path)


def _add_system_badges(uploaded_log, index):
    """Give every entry `system`: does its log come from the same machine?"""
    upload_ids = {entry['upload_id'] for entries in index.values() for entry in entries}
    if not upload_ids:
        return
    own = system_signals(uploaded_log.content)
    verdict_by_upload = {
        upload_id: same_system(own, system_signals(content))
        for upload_id, content in UploadedLog.objects.filter(upload_id__in=upload_ids).values_list('upload_id', 'content')
    }
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
    raw = json.dumps([
        CORRELATION_VERSION, uploaded_log.content_hash, scope, name, related,
        verdicts_changed.isoformat() if verdicts_changed else '',
        aliases_changed.isoformat() if aliases_changed else '',
        pairs_changed or 0,
        rows_state['n'] or 0, rows_state['latest'] or 0,
    ], default=str)
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()


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
        parts = [part for part in (name, f'centralbox: {verdict}' if verdict else '', where, entry.get('log_type', '')) if part]
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
        CorrelationCache.objects.update_or_create(
            upload=uploaded_log, scope_key=scope_key,
            defaults={'signature': signature, 'payload': answer},
        )
        return answer
    except Exception:
        logger.exception('Case correlations failed for %s', getattr(uploaded_log, 'upload_id', '?'))
        return _empty()


def _compute(uploaded_log, upload_ids, payload):
    """{line text: [entry]} from scratch."""
    index = {}
    covered = _hash_entries(upload_ids, index)
    _detection_entries(upload_ids, index, covered)
    _fixlog_entries(upload_ids, index)
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
        key = _line_key(line)
        if not key:
            continue
        entries = list(index.get(key) or [])
        parent, previous = ntpath.dirname(key), key
        while detections and parent and parent != previous and len(entries) < MAX_ENTRIES_PER_LINE:
            entries.extend({**entry, 'in_folder': True} for entry in detections.get(parent, ()))
            parent, previous = ntpath.dirname(parent), parent
        if entries:
            result[text] = entries[:MAX_ENTRIES_PER_LINE]
    if result:
        _add_system_badges(uploaded_log, result)
    return result
