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

from .. import centralbox, centralbox_auto
from ..correlations import spor_self
from ..case_correlations import (
    add_stored_results, cached_correlations, correlations_for_upload, related_upload_ids, reverse_correlations, reverse_note,
    reverse_status, summary_note,
)
from ..correlation_keys import line_path_keys
from ..file_hashes import is_md5, is_sha256
from ..log_types import LOG_TYPE_SPOR
from ..models import HashVerdict, RuleTag, UploadedLog, UploadedLogFileHash
from ..tagging import centralbox_tags_by_sha
from ..validators import PayloadValidator

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
             # Scanner detections, MAU files, Fixlog File: entries and the files a
             # Spor log flags get a flag in the summary box.
             'flag': source in ('malwarebytes', 'hitmanpro', 'fixlog_file', 'mau', 'spor')}
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
            # Waiting for an automatic fresh lookup (centralbox_auto.py).
            'queued': centralbox_auto.queued_hashes(shas | md5s),
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
    """Summary box of a Fixlog, MAU or Spor log: the lines whose hash has a
    stored centralbox result, next to what the highlighter lists. Fixlog: also
    every File: entry, and "not in centralbox" answers (e.g. checked by hand in
    a folder listing). MAU and Spor (dozens to thousands of hashes): only real
    verdicts, at the file's path line. The page adds the centralbox flag.
    Database only; never raises."""
    try:
        if highlight is None or not context:
            return
        mau = uploaded_log.log_type in ('MAU', LOG_TYPE_SPOR)
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
    """A SHA256 of the log, or an MD5 the log lists without a SHA256 (Trojan
    Killer), or the SHA256 such an MD5 is known to stand for (the correlations
    show it with the MD5's file: centralbox.resolve_md5s, database only)."""
    rows = UploadedLogFileHash.objects.filter(upload=uploaded_log)
    if is_md5(value):
        return rows.filter(md5=value, sha256='').exists()
    if rows.filter(sha256=value).exists():
        return True
    md5s = set(rows.filter(sha256='').exclude(md5='').values_list('md5', flat=True))
    return bool(md5s) and value in centralbox.resolve_md5s(md5s).values()


def _json_hash_and_log(request):
    """(sha, uploaded_log, error_response) from a {sha256, upload_id} body."""
    data, error = PayloadValidator.json_object(request)
    if error:
        return None, None, error
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


AUTO_QUEUE_DEBOUNCE_SECONDS = 60


def _queue_auto_fresh(uploaded_log, other_ids, user):
    """Queue fresh lookups for the case's likely malicious hashes, with the
    viewer's B / ! / P lines of this FRST log; at most once a minute per log
    and viewer, as the analyzer asks for suggestions repeatedly."""
    from django.core.cache import cache

    try:
        if not cache.add(f'centralbox-auto-queue:{uploaded_log.pk}:{user.pk}', 1, timeout=AUTO_QUEUE_DEBOUNCE_SECONDS):
            return
        flagged = centralbox_auto.flagged_frst_paths([uploaded_log], user=user)
        centralbox_auto.enqueue_auto_fresh(list(other_ids) + [uploaded_log.pk], flagged)
    except Exception:
        logger.exception('Queueing automatic fresh lookups failed for %s', uploaded_log.upload_id)


@login_required
@require_http_methods(['GET'])
def centralbox_suggestions_api(request):
    """FRST lines whose file has a malicious SHA256 in another log of the same
    infection case. Database only: never calls centralbox. Each suggestion is
    keyed by the line's stripped text, as the analyzer identifies lines; the
    analyzer decides whether to show it (not on B lines) and how (conflict).

    Also queues automatic fresh lookups for the case's likely malicious hashes
    (centralbox_auto.py), and tells how many of the case's hashes wait in that
    queue (`queued`) or have a fresh lookup running (`running`), so the
    analyzer asks again until they are done."""
    empty = {'available': False, 'suggestions': [], 'pending': 0, 'queued': 0, 'running': 0}
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
        _queue_auto_fresh(uploaded_log, other_ids, request.user)
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
        # Both forms: an MD5 may wait in the queue though its SHA256 is now known.
        queued, running = centralbox_auto.queue_state(
            {r.sha256 for r in rows} | {r.md5 for r in rows} | set(md5_map.values())
        )
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
            return JsonResponse({'available': available, 'suggestions': [], 'pending': pending,
                                 'queued': queued, 'running': running})

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
            # The line's file, else a file in its command line.
            match = next(
                (by_path[key] for key in line_path_keys(line) if key in by_path), None,
            )
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
        return JsonResponse({'available': available, 'suggestions': suggestions, 'pending': pending,
                             'queued': queued, 'running': running})
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
    if uploaded_log.log_type not in UploadedLog.ANALYZED_LOG_TYPES:
        # Any other log: the FRST / Addition lines that point at its lines
        # (reverse: true), keyed by its own line texts like the forward answer.
        return JsonResponse(_reverse_answer(uploaded_log, request.user))
    result = correlations_for_upload(uploaded_log, request.user)
    return JsonResponse({
        'scope': result['scope'], 'name': result['name'],
        'correlations': result['lines'], 'statuses': result.get('statuses') or {},
        'notes': result.get('notes') or {},
    })


def _reverse_answer(uploaded_log, user):
    """The endpoint's answer for a log that is not an FRST / Addition log."""
    result = reverse_correlations(uploaded_log, user, compute=True)
    correlations, statuses, notes = {}, {}, {}
    for no, entries in result['lines'].items():
        text = result['texts'].get(no, '')
        if not text:
            continue
        merged = correlations.setdefault(text, [])
        merged.extend(entry for entry in entries if entry not in merged)
    for text, entries in correlations.items():
        status = reverse_status(entries)
        if status:
            statuses[text] = status
            notes[text] = reverse_note(entries, status)
    return {
        'scope': result['scope'], 'name': result['name'], 'reverse': True,
        'correlations': correlations, 'statuses': statuses, 'notes': notes,
    }


def _lookup_context():
    """What the log page's info box needs to look up the hashes it shows on
    centralbox (check / fresh lookup, each with the log that holds the hash)."""
    return {
        'can_lookup': centralbox.is_available(),
        'hash_url': reverse('centralbox_hash_check_api'),
        'fresh_url': reverse('centralbox_fresh_start_api'),
        'fresh_status_url': reverse('centralbox_fresh_status_api', args=['0' * 64]),
    }


def page_reverse_correlation_context(uploaded_log, user):
    """For the log page of any log that is not an FRST / Addition log: the
    lines of its related FRST / Addition logs that point at its lines, in the
    shape of page_correlation_context (reverse: true), so the same markers
    and info box show them. A marker is coloured by the FRST line's rule
    verdict when that is B, P, ! or G. Nothing goes into the summary box.
    Stored correlations only (case_correlations.reverse_correlations); when
    one is outdated, `fresh` is false and the page asks `refresh_url`. Never raises."""
    try:
        result = reverse_correlations(uploaded_log, user)
        if not result['lines'] and result['fresh']:
            return {}
        context = {
            'fresh': bool(result['fresh']),
            'refresh_url': f"{reverse('case_correlations_api')}?upload_id={uploaded_log.upload_id}",
            'scope': result['scope'], 'name': result['name'], 'reverse': True,
            'upload_id': uploaded_log.upload_id,
            **_lookup_context(),
            'lines': {
                no: {'status': reverse_status(entries), 'entries': entries}
                for no, entries in result['lines'].items()
            },
        }
        return context
    except Exception:
        logger.exception('Building the reverse correlation page context failed for %s', uploaded_log.upload_id)
        return {}


def add_self_link_context(uploaded_log, context):
    """A Spor log page's links between its own lines (correlations/spor_self.py), added
    to its reverse correlation context (or a new one in the same shape):
    `self_lines` {line no: code} (status letter, 'm' for a neutral marker, ''
    for links from the hover icons only), `self_url`, which gives one line's
    entries when its info box opens (all of them would be too big for the
    page), and `self_lookup` [line no]: lines whose linked FILES hashes have
    no centralbox report yet (their icon offers a lookup). Never raises; the
    context unchanged for other logs."""
    if uploaded_log.log_type != LOG_TYPE_SPOR:
        return context
    try:
        links = spor_self.for_upload(uploaded_log)
        if links is None or not links.codes:
            return context
        if not context:
            context = {
                'fresh': True,
                'refresh_url': f"{reverse('case_correlations_api')}?upload_id={uploaded_log.upload_id}",
                'scope': '', 'name': '', 'reverse': True, 'upload_id': uploaded_log.upload_id,
                **_lookup_context(), 'lines': {},
            }
        context['self_lines'] = links.codes
        context['self_url'] = f"{reverse('spor_self_links_api')}?upload_id={uploaded_log.upload_id}"
        if context.get('can_lookup'):
            context['self_lookup'] = _self_lookup_lines(links.linked_hashes())
        return context
    except Exception:
        logger.exception('Adding Spor self links failed for %s', uploaded_log.upload_id)
        return context


# HashVerdict lookups per query (the IN list of one query).
_VERDICT_CHUNK = 900


def _self_lookup_lines(linked):
    """[line no] of the lines (linked: {no: {SHA-256 or MD5}}) with a hash
    that has no centralbox report (state known), as CentralboxLookup.targets
    decides for the hashes it is given. Database only."""
    shas = {value for hashes in linked.values() for value in hashes if is_sha256(value)}
    md5_map = centralbox.resolve_md5s({value for hashes in linked.values() for value in hashes if is_md5(value)})
    wanted = sorted(shas | set(md5_map.values()))
    known = set()
    for start in range(0, len(wanted), _VERDICT_CHUNK):
        known.update(HashVerdict.objects.filter(
            sha256__in=wanted[start:start + _VERDICT_CHUNK], state=HashVerdict.STATE_KNOWN,
        ).values_list('sha256', flat=True))

    def open_hash(value):
        sha = value if is_sha256(value) else md5_map.get(value, '')
        return not (sha and sha in known)

    return sorted((no for no, hashes in linked.items() if any(open_hash(value) for value in hashes)), key=int)


@login_required
@require_http_methods(['GET'])
def spor_self_links_api(request):
    """{entries: [entry]}: what the other lines of a Spor log say about one
    of its lines (?upload_id=...&line=N, correlations/spor_self.py)."""
    upload_id = (request.GET.get('upload_id') or '').strip()
    line = (request.GET.get('line') or '').strip()
    # The content (up to a few MB) only on a cache miss of for_upload.
    uploaded_log = UploadedLog.objects.filter(upload_id=upload_id, log_type=LOG_TYPE_SPOR).only(
        'pk', 'upload_id', 'log_type', 'content_hash',
    ).first() if upload_id else None
    if uploaded_log is None or not line.isdigit():
        return JsonResponse({'entries': []})
    links = spor_self.for_upload(uploaded_log)
    # The stored centralbox result of each FILES hash (database only): the
    # info box shows it, and offers a lookup for the hashes without one.
    entries = add_stored_results(links.entries(line)) if links is not None else []
    return JsonResponse({'entries': entries})


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
            # The log itself: its own entries (Addition part) jump within the page.
            'upload_id': uploaded_log.upload_id,
            # Lookups of correlated hashes from the info panel (each with the
            # related log that holds the hash, as the analyzer does).
            **_lookup_context(),
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
                note = notes.get(data['text']) or summary_note(data['entries'], data['status'], uploaded_log.upload_id)
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
