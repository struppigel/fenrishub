"""JSON endpoints for the centralbox SHA256 verdicts.

None of them can break a page: the log page and the analyzer render without
them and only call them afterwards. When centralbox is off, paused or failing
they answer 200 with `available: false` and whatever verdicts are stored.
Lookups are bounded (a few seconds, a few calls); the suggestions endpoint
never calls centralbox at all.
"""

import logging
import ntpath

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from ..log_highlighting import SummaryItem

from .. import centralbox
from .. import frst_extractors as ex
from ..case_correlations import cached_correlations, correlations_for_upload, related_upload_ids, summary_note
from ..file_hashes import is_md5, is_sha256
from ..models import HashVerdict, RuleTag, UploadedLog, UploadedLogFileHash
from ..tagging import centralbox_tags_by_sha
from ..validators import BadJsonError, PayloadTooLargeError, PayloadValidator

logger = logging.getLogger(__name__)

PAGE_CHECK_MAX_CALLS = 25
PAGE_CHECK_DEADLINE_SECONDS = 8.0
MANUAL_CHECK_DEADLINE_SECONDS = 8.0
MAX_SUGGESTION_LOG_LINES = 200000


def _tags_by_sha(shas):
    """{sha: [tag name]} of the tags matched through centralbox results, without
    tags of priority-0 categories (hidden in listings too)."""
    by_sha = centralbox_tags_by_sha(shas)
    if not by_sha:
        return {}
    names = dict(
        RuleTag.objects.filter(pk__in=set().union(*by_sha.values()), category__priority__gt=0)
        .values_list('pk', 'name')
    )
    result = {}
    for sha, tag_ids in by_sha.items():
        shown = sorted((names[tag_id] for tag_id in tag_ids if tag_id in names), key=str.lower)
        if shown:
            result[sha] = shown
    return result


def page_hash_context(uploaded_log, user=None):
    """What the log page needs to draw markers, from the database only:
    {available, auto: [{sha256, line_no, anchor_line_no, flag}], verdicts,
    tags, fresh, can_fresh_lookup, ...}. Empty dict for log types without
    hashes. Never raises."""
    try:
        rows = list(
            UploadedLogFileHash.objects.filter(upload=uploaded_log)
            .values_list('sha256', 'line_no', 'anchor_line_no', 'auto', 'source', 'md5')
        )
        if not rows:
            return {}
        auto = [
            {'sha256': sha, 'line_no': line_no, 'anchor_line_no': anchor,
             # Scanner detections, MAU files and Fixlog File: entries get a flag in the summary box.
             'flag': source in ('malwarebytes', 'hitmanpro', 'fixlog_file', 'mau')}
            for sha, line_no, anchor, is_auto, source, md5 in rows if is_auto
        ]
        # MD5-only rows (Trojan Killer, Fixlog Folder:): marked through the
        # SHA256 they stand for (a pair seen in another log, or centralbox's answer).
        md5_rows = [
            {'md5': md5, 'line_no': line_no, 'anchor_line_no': anchor,
             'flag': source in ('trojan_killer', 'fixlog_folder')}
            for sha, line_no, anchor, is_auto, source, md5 in rows if md5 and not sha
        ]
        md5s = {row['md5'] for row in md5_rows}
        md5_map = centralbox.resolve_md5s(md5s)
        shas = {sha for sha, *_ in rows if sha} | set(md5_map.values())
        verdicts = {row.sha256: row.as_dict() for row in HashVerdict.objects.filter(sha256__in=shas)}
        available = centralbox.is_available()
        return {
            'available': available,
            'auto': auto,
            # Logs with many hashes are not checked by themselves (menu only).
            'auto_check': len({row['sha256'] for row in auto}) <= centralbox.auto_check_limit(),
            'verdicts': verdicts,
            # Hashes checked by hand (e.g. in a Fixlog folder listing): their
            # line is in the summary box too (add_hash_summary).
            'checked_rows': [
                {'sha256': sha, 'anchor_line_no': line_no}
                for sha, line_no, anchor, is_auto, source, md5 in rows if sha and not is_auto and sha in verdicts
            ],
            'md5_rows': md5_rows,
            'md5_map': md5_map,
            'md5_unknown': centralbox.unknown_md5s(md5s - set(md5_map)),
            'tags': _tags_by_sha(shas),
            'fresh': centralbox.fresh_lookup_info(shas | md5s),
            # Any helper, with the server key (once per hash per cooldown).
            'can_fresh_lookup': available,
            'upload_id': uploaded_log.upload_id,
            'check_url': reverse('centralbox_upload_check_api', args=[uploaded_log.upload_id]),
            'hash_url': reverse('centralbox_hash_check_api'),
            'fresh_url': reverse('centralbox_fresh_start_api'),
            'fresh_status_url': reverse('centralbox_fresh_status_api', args=['0' * 64]),
        }
    except Exception:
        logger.exception('Building the centralbox page context failed for %s', uploaded_log.upload_id)
        return {}


_SUMMARY_SEVERITY = {'malicious': 'b', 'suspicious': 'w', 'clean': 'c'}


def add_hash_summary(highlight, uploaded_log, context):
    """Summary box of a Fixlog or MAU log: the lines whose hash has a stored
    centralbox result, next to what the highlighter lists. Fixlog: also every
    File: entry, and "not in centralbox" answers (e.g. checked by hand in a
    folder listing). MAU (dozens of hashes, checked by themselves): only real
    verdicts, at the file's path line. The page adds the centralbox flag.
    Database only; never raises."""
    try:
        if highlight is None or not context:
            return
        mau = uploaded_log.log_type == 'MAU'
        verdicts = context.get('verdicts') or {}
        md5_map = context.get('md5_map') or {}
        md5_unknown = context.get('md5_unknown') or {}
        items = []
        seen = {item.line_no for item in highlight.summary}
        rows = (
            UploadedLogFileHash.objects.filter(upload=uploaded_log)
            .values_list('sha256', 'md5', 'line_no', 'anchor_line_no', 'source', 'path')
        )
        for sha, md5, line_no, anchor, source, path in rows:
            if sha:
                verdict, kind = verdicts.get(sha), 'SHA-256'
            elif md5 in md5_map:
                # An MD5-only row (Folder: block) whose SHA256 is known.
                verdict, kind = verdicts.get(md5_map[md5]), 'MD5'
            elif md5 in md5_unknown:
                verdict, kind = {'state': HashVerdict.STATE_UNKNOWN}, 'MD5'
            else:
                continue
            if source == 'fixlog_file':
                line, name = anchor, 'File:'
            elif mau:
                if (verdict or {}).get('verdict') not in _SUMMARY_SEVERITY:
                    continue
                line, name = anchor, kind
            elif verdict is not None:
                line, name = line_no, kind
            else:
                continue
            if line in seen:
                continue
            seen.add(line)
            severity = _SUMMARY_SEVERITY.get((verdict or {}).get('verdict'), 'i')
            items.append(SummaryItem(line, severity, name, path or sha))
        if items:
            highlight.summary = sorted(highlight.summary + items, key=lambda item: item.line_no)
            highlight.summary_title = (
                f'{highlight.summary_title} and centralbox results' if mau and highlight.summary_title
                else 'Fixlog failures, files and centralbox results'
            )
    except Exception:
        logger.exception('Adding hashes to the summary failed for %s', uploaded_log.upload_id)


@login_required
@require_http_methods(['POST'])
def centralbox_upload_check_api(request, upload_id):
    """Look up the log's automatic hashes that have no fresh verdict yet."""
    uploaded_log = get_object_or_404(UploadedLog, upload_id=upload_id)
    shas = centralbox.auto_hashes_of([uploaded_log.pk])
    result = centralbox.check_hashes(
        shas, max_calls=PAGE_CHECK_MAX_CALLS, deadline_seconds=PAGE_CHECK_DEADLINE_SECONDS,
    )
    return JsonResponse(result)


@login_required
@require_http_methods(['POST'])
def centralbox_hash_check_api(request):
    """Look up one hash an analyst picked from the hash menu (e.g. in a Fixlog
    folder listing). Only hashes that occur in the given log are accepted."""
    sha, _uploaded_log, error = _json_hash_and_log(request)
    if error:
        return error
    if is_md5(sha):
        # An MD5-only file (Trojan Killer, Fixlog Folder:): through a known
        # SHA256, else centralbox's MD5 answer.
        result = centralbox.check_md5(sha, force=True)
        answer = {
            'available': result['available'], 'verdict': result['verdict'],
            'sha256': result['sha256'], 'unknown': result['unknown'],
        }
    else:
        # An explicit click: ask centralbox again even if a fresh answer is
        # stored (e.g. someone just submitted the sample there); limited per hash.
        result = centralbox.check_hashes(
            [sha], max_calls=2, deadline_seconds=MANUAL_CHECK_DEADLINE_SECONDS, force=True,
        )
        answer = {'available': result['available'], 'verdict': result['verdicts'].get(sha)}
    return JsonResponse(answer)


def _hash_in_log(uploaded_log, value):
    """A SHA256 of the log, or an MD5 the log lists without a SHA256 (Trojan Killer)."""
    rows = UploadedLogFileHash.objects.filter(upload=uploaded_log)
    if is_md5(value):
        return rows.filter(md5=value, sha256='').exists()
    return rows.filter(sha256=value).exists()


def _json_hash_and_log(request):
    """(sha, uploaded_log, error_response) from a {sha256, upload_id} body."""
    try:
        data = PayloadValidator.json_payload(request)
    except (BadJsonError, PayloadTooLargeError) as exc:
        return None, None, PayloadValidator.error_response(str(exc))
    if not isinstance(data, dict):
        return None, None, PayloadValidator.error_response('Invalid JSON payload.')
    sha = str(data.get('sha256') or '').strip().lower()
    if not (is_sha256(sha) or is_md5(sha)):
        return None, None, PayloadValidator.error_response('sha256 must be a SHA-256 (64 hex) or MD5 (32 hex) hash.')
    uploaded_log = get_object_or_404(UploadedLog, upload_id=str(data.get('upload_id') or '').strip())
    if not _hash_in_log(uploaded_log, sha):
        return None, None, PayloadValidator.error_response('That hash is not in this log.', status=404)
    return sha, uploaded_log, None


def _fresh_response(result):
    status = result.pop('http_status', 200)
    return JsonResponse(result, status=status)


@login_required
@require_http_methods(['POST'])
def centralbox_fresh_start_api(request):
    """Start a fresh centralbox analysis of one hash of the log, with the
    server key, for any helper. Once per hash per cooldown, for everyone."""
    sha, _uploaded_log, error = _json_hash_and_log(request)
    if error:
        return error
    return _fresh_response(centralbox.start_fresh_lookup(sha, request.user))


@login_required
@require_http_methods(['GET'])
def centralbox_fresh_status_api(request, sha256):
    """Progress of a fresh lookup; stores the result once centralbox is done."""
    return _fresh_response(centralbox.poll_fresh_lookup(sha256))


def _line_path_key(line):
    try:
        path = ex.extract_any_frst_path(line)
        return ex.normalize_path(path).lower().strip() if path else ''
    except Exception:
        return ''


@login_required
@require_http_methods(['GET'])
def centralbox_suggestions_api(request):
    """FRST lines whose file has a malicious SHA256 in another log of the same
    infection case. Database only: never calls centralbox. Each suggestion is
    keyed by the line's stripped text, as the analyzer identifies lines; the
    analyzer decides whether to show it (not on B lines) and how (conflict)."""
    empty = {'available': False, 'suggestions': [], 'pending': 0}
    upload_id = (request.GET.get('upload_id') or '').strip()
    if not upload_id:
        return JsonResponse(empty)
    uploaded_log = UploadedLog.objects.filter(upload_id=upload_id).first()
    if uploaded_log is None or uploaded_log.log_type not in UploadedLog.ANALYZED_LOG_TYPES:
        return JsonResponse(empty)
    try:
        # The same logs as the correlation icon: own cases, else the forum user's logs.
        other_ids, _scope, _name = related_upload_ids(uploaded_log, request.user)
        if not other_ids:
            return JsonResponse(empty)
        # Manual-only rows (e.g. a Fixlog folder listing) count too once an
        # analyst has checked them; only automatic ones are ever pending.
        rows = list(
            UploadedLogFileHash.objects.filter(upload_id__in=other_ids)
            .exclude(normalized_path='')
            .select_related('upload')
            .only('sha256', 'md5', 'line_no', 'path', 'normalized_path', 'detection', 'auto',
                  'upload__upload_id', 'upload__log_type')
        )
        # Trojan Killer rows carry only an MD5: use the SHA256 it stands for.
        md5_map = centralbox.resolve_md5s({r.md5 for r in rows if r.md5 and not r.sha256})
        for r in rows:
            if not r.sha256 and r.md5 in md5_map:
                r.sha256 = md5_map[r.md5]
        rows = [r for r in rows if r.sha256]
        verdicts = {
            row.sha256: row for row in HashVerdict.objects.filter(sha256__in={r.sha256 for r in rows})
        }
        available = centralbox.is_available()
        pending = sum(1 for sha in centralbox.auto_hashes_of(other_ids) if sha not in verdicts)
        if pending and available:
            centralbox.schedule_uploads_check(other_ids)

        by_path = {}
        for row in rows:
            verdict = verdicts.get(row.sha256)
            if verdict is None or verdict.verdict != HashVerdict.VERDICT_MALICIOUS:
                continue
            by_path.setdefault(row.normalized_path, (row, verdict))
        if not by_path:
            return JsonResponse({'available': available, 'suggestions': [], 'pending': pending})

        # Only lines naming one of the files are parsed (cheap substring test first).
        names = {ntpath.basename(key) for key in by_path if ntpath.basename(key)}
        suggestions = []
        seen_lines = set()
        for raw in (uploaded_log.content or '').splitlines()[:MAX_SUGGESTION_LOG_LINES]:
            line = raw.strip()
            if not line or line in seen_lines:
                continue
            lowered = line.lower()
            if not any(name in lowered for name in names):
                continue
            match = by_path.get(_line_path_key(line))
            if match is None:
                continue
            seen_lines.add(line)
            row, verdict = match
            info = verdict.as_dict()
            suggestions.append({
                'line': line,
                'status': 'B',
                'sha256': row.sha256,
                'verdict': info['verdict'],
                'family': info['family'],
                'malware_type': info['malware_type'],
                'threat_score': info['threat_score'],
                'checked_at': info['checked_at'],
                'report_url': info['report_url'],
                'source': {
                    'upload_id': row.upload.upload_id,
                    'log_type': row.upload.log_type,
                    'line_no': row.line_no,
                    'detection': row.detection,
                    'path': row.path,
                },
            })
        return JsonResponse({'available': available, 'suggestions': suggestions, 'pending': pending})
    except Exception:
        logger.exception('centralbox suggestions failed for %s', upload_id)
        return JsonResponse(empty)


@login_required
@require_http_methods(['GET'])
def case_correlations_api(request):
    """What related logs say about the files of the upload's FRST / Addition
    lines: {scope ('case' / 'user'), name, correlations: {line text: [entry]}}.
    Related: the viewer's own cases with the log, else the same forum user's
    logs. Database and local parsing only; empty when there is nothing to tell."""
    upload_id = (request.GET.get('upload_id') or '').strip()
    uploaded_log = UploadedLog.objects.filter(upload_id=upload_id).first() if upload_id else None
    if uploaded_log is None:
        return JsonResponse({'scope': '', 'name': '', 'correlations': {}, 'statuses': {}, 'notes': {}})
    result = correlations_for_upload(uploaded_log, request.user)
    return JsonResponse({
        'scope': result['scope'], 'name': result['name'],
        'correlations': result['lines'], 'statuses': result.get('statuses') or {},
        'notes': result.get('notes') or {},
    })


# Summary severity (log_highlighting.SummaryItem) for a correlation status letter.
_CORRELATION_SUMMARY_SEVERITY = {
    'B': 'b', 'P': 'p', 'C': 'c', 'A': 'w', '!': 'w', 'G': 'g', 'S': 'i', 'I': 'i', 'J': 'j',
}


def page_correlation_context(uploaded_log, user, highlight):
    """Correlations for the log page of an FRST / Addition log, keyed by line
    number like the page's #L<n> anchors: {scope, name, lines: {no: {status,
    entries}}, fresh, refresh_url}. Lines whose related logs have a finding
    with a status (a coloured marker) also go into the summary box.

    Only what is stored is shown (case_correlations.cached_correlations): the
    page never waits for them. When that is outdated or missing, `fresh` is
    false and the page asks `refresh_url` afterwards. Never raises."""
    try:
        result, fresh = cached_correlations(uploaded_log, user)
        context = {
            'fresh': bool(fresh),
            'refresh_url': f"{reverse('case_correlations_api')}?upload_id={uploaded_log.upload_id}",
            'scope': '', 'name': '', 'lines': {},
            # Lookups of correlated hashes from the info panel (each with the
            # related log that holds the hash, as the analyzer does).
            'can_lookup': centralbox.is_available(),
            'hash_url': reverse('centralbox_hash_check_api'),
            'fresh_url': reverse('centralbox_fresh_start_api'),
            'fresh_status_url': reverse('centralbox_fresh_status_api', args=['0' * 64]),
        }
        if result is None:
            return context
        context['scope'] = result.get('scope', '')
        context['name'] = result.get('name', '')
        texts = result.get('lines') or {}
        if not texts:
            return context if not fresh else {}
        statuses = result.get('statuses') or {}
        notes = result.get('notes') or {}
        lines = {}
        for no, raw in enumerate((uploaded_log.content or '').split('\n'), start=1):
            for piece in raw.splitlines():
                text = piece.strip()
                if text in texts:
                    lines[str(no)] = {'status': statuses.get(text, ''), 'entries': texts[text], 'text': text}
        if not lines:
            return context if not fresh else {}
        if highlight is not None:
            listed = {item.line_no: item for item in highlight.summary}
            added = []
            for no, data in lines.items():
                severity = _CORRELATION_SUMMARY_SEVERITY.get(data['status'])
                if not severity:
                    continue
                note = notes.get(data['text']) or summary_note(data['entries'], data['status'])
                note = f'correlated: {note}'
                existing = listed.get(int(no))
                if existing is not None:
                    # Already listed by its rule verdict: what the related log
                    # says follows that entry.
                    existing.correlation = note
                    continue
                # The line itself, like the rule-verdict entries; what the
                # related log says follows it.
                added.append(SummaryItem(
                    int(no), severity, data['text'], status=data['status'],
                    correlation=note, correlation_added=True,
                ))
            if added:
                highlight.summary = sorted(highlight.summary + added, key=lambda item: item.line_no)
        for data in lines.values():
            data.pop('text', None)
        context['lines'] = lines
        return context
    except Exception:
        logger.exception('Building the correlation page context failed for %s', uploaded_log.upload_id)
        return {}
