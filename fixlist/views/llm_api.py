"""
Read-only token API (/api/v1/) for LLM clients.

Serves what a logged-in helper can already read in the browser: every
non-trashed upload, its verdicts under the caller's own rule set, content
search, infection cases by id, and the fixlist snippets the caller owns or that
are shared. Listing cases is limited to the caller's own,
as on the cases page. Authentication, limits and logging live in api_auth.

Fields holding text that came from the infected machine or its user (log lines,
forum username, filename, symptom description) are prefixed `untrusted_`, so a
model reading the JSON is told at every use that the text is data, not
instructions.
"""

import re

from django.db.models import Q
from django.http import JsonResponse

from ..models import FixlistSnippet, InfectionCase, InfectionCaseLog, UploadedLog
from ..rule_sets import SHARED_RULE_SET_KEY, resolve_user_rule_set_key
from ..status_types import STATUS_LABELS, VALID_STATUSES
from ..upload_utils import get_fresh_cached_analysis, get_or_compute_upload_analysis
from .api_auth import api_token_required, charge_api_units, rate_limited_response
from .infection_cases import _build_case_timeline
from .log_search import _first_hit, _logs_in_id_order, search_matching_log_ids
from .uploads import filter_uploads_by_text

UPLOAD_ID_RE = re.compile(r'[A-Za-z0-9_.-]{1,64}')
CASE_ID_RE = re.compile(r'[A-Za-z0-9_-]{1,24}')
FORUM_USERNAME_MAX_CHARS = 100
QUERY_MAX_CHARS = 500

LIST_DEFAULT_LIMIT = 20
LIST_MAX_LIMIT = 50
LIST_MAX_OFFSET = 10000
SNIPPETS_DEFAULT_LIMIT = 50
SNIPPETS_MAX_LIMIT = 100
LINES_DEFAULT_LIMIT = 500
LINES_MAX_LIMIT = 2000
LINES_MAX_OFFSET = 200000
# A stale or missing cache means a full analyzer run; charge it like a search.
ANALYSIS_RECOMPUTE_EXTRA_UNITS = 9


def _error(message, status=400):
    return JsonResponse({'error': message}, status=status)


def _not_found():
    return _error('Not found.', 404)


def _int_param(request, name, default, minimum, maximum):
    """Read an int query param clamped to [minimum, maximum]; None when malformed."""
    raw = (request.GET.get(name) or '').strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return None
    return max(minimum, min(maximum, value))


def _iso(value):
    return value.isoformat() if value else None


def _live_uploads():
    return (
        UploadedLog.objects.filter(deleted_at__isnull=True)
        .select_related('recipient_user')
        .defer('content')
    )


def _own_case_ids_by_upload(user, upload_pks):
    """Map upload pk -> case ids of the caller's own live cases holding it.

    Other helpers' case ids are never listed: in the browser a case is found
    through its owner's case list or a link the owner shared.
    """
    links = (
        InfectionCaseLog.objects.filter(
            uploaded_log_id__in=upload_pks,
            case__owner=user,
            case__deleted_at__isnull=True,
        )
        .values_list('uploaded_log_id', 'case__case_id')
        .order_by('added_at')
    )
    case_ids = {}
    for upload_pk, case_id in links:
        case_ids.setdefault(upload_pk, []).append(case_id)
    return case_ids


def _upload_metadata(uploaded_log, case_ids):
    return {
        'upload_id': uploaded_log.upload_id,
        'untrusted_forum_username': uploaded_log.forum_username,
        'untrusted_original_filename': uploaded_log.original_filename,
        'log_type': uploaded_log.log_type,
        'is_incomplete': uploaded_log.is_incomplete,
        'created_at': _iso(uploaded_log.created_at),
        'scan_date': _iso(uploaded_log.scan_date),
        'helper': uploaded_log.recipient_user.username if uploaded_log.recipient_user else None,
        'total_line_count': uploaded_log.total_line_count,
        # Counts under the assigned helper's rule set, as shown on the uploads page.
        'status_counts': {
            code: getattr(uploaded_log, field)
            for code, field in UploadedLog.ANALYSIS_STATUS_FIELD_MAP.items()
        },
        'own_case_ids': case_ids.get(uploaded_log.pk, []),
    }


def _uploads_metadata(user, uploads):
    case_ids = _own_case_ids_by_upload(user, [uploaded_log.pk for uploaded_log in uploads])
    return [_upload_metadata(uploaded_log, case_ids) for uploaded_log in uploads]


def _get_live_upload(upload_id, *, with_content):
    if not UPLOAD_ID_RE.fullmatch(upload_id or ''):
        return None
    uploads = UploadedLog.objects.filter(deleted_at__isnull=True).select_related('recipient_user')
    if not with_content:
        uploads = uploads.defer('content')
    return uploads.filter(upload_id=upload_id).first()


@api_token_required('api_v1_uploads')
def api_uploads(request):
    """List uploads, newest first. Filters: q (id/poster/helper/filename), username, type."""
    limit = _int_param(request, 'limit', LIST_DEFAULT_LIMIT, 1, LIST_MAX_LIMIT)
    offset = _int_param(request, 'offset', 0, 0, LIST_MAX_OFFSET)
    if limit is None or offset is None:
        return _error('limit and offset must be integers.')

    uploads = _live_uploads()
    search_query = (request.GET.get('q') or '').strip()[:QUERY_MAX_CHARS]
    if search_query:
        uploads = filter_uploads_by_text(uploads, search_query)
    username = (request.GET.get('username') or '').strip()
    if username:
        uploads = uploads.filter(forum_username__iexact=username)
    log_type = (request.GET.get('type') or '').strip()
    if log_type:
        uploads = uploads.filter(log_type=log_type)

    total = uploads.count()
    page = list(uploads[offset:offset + limit])
    return JsonResponse({
        'total': total,
        'offset': offset,
        'limit': limit,
        'uploads': _uploads_metadata(request.user, page),
    })


@api_token_required('api_v1_upload')
def api_upload(request, upload_id):
    """One upload's metadata and full log text."""
    uploaded_log = _get_live_upload(upload_id, with_content=True)
    if uploaded_log is None:
        return _not_found()
    payload = _uploads_metadata(request.user, [uploaded_log])[0]
    payload['untrusted_content'] = uploaded_log.content
    return JsonResponse(payload)


def _non_blank_line_numbers(content):
    """1-based numbers of the lines the analyzer looks at (it skips blank ones)."""
    return [
        number
        for number, raw_line in enumerate((content or '').splitlines(), start=1)
        if raw_line.strip()
    ]


def _compact_line(number, entry):
    """Drop the presentation-only fields of an analyzer line; keep the verdict."""
    return {
        'n': number,
        'text': entry.get('line', ''),
        'status': entry.get('dominant_status', '?'),
        'status_label': entry.get('status_label', ''),
        'status_codes': entry.get('status_codes', ''),
        'entry_type': entry.get('entry_type', ''),
        'matcher': entry.get('matcher', ''),
        'reasons': entry.get('reasons', []),
        'components': entry.get('components', {}),
        'dates': entry.get('dates', []),
        'fixlist_replacement': entry.get('fixlist_replacement'),
    }


@api_token_required('api_v1_upload_analysis')
def api_upload_analysis(request, upload_id):
    """Per-line verdicts for one upload under the caller's rule set.

    `status` filters by verdict letter (comma-separated, e.g. B,P,?).
    """
    limit = _int_param(request, 'limit', LINES_DEFAULT_LIMIT, 1, LINES_MAX_LIMIT)
    offset = _int_param(request, 'offset', 0, 0, LINES_MAX_OFFSET)
    if limit is None or offset is None:
        return _error('limit and offset must be integers.')
    status_param = (request.GET.get('status') or '').strip()
    statuses = {code.strip() for code in status_param.split(',') if code.strip()}
    invalid = statuses - VALID_STATUSES
    if invalid:
        return _error(
            f"Unknown status code(s): {', '.join(sorted(invalid))}. "
            f"Valid: {' '.join(sorted(VALID_STATUSES))}."
        )

    uploaded_log = _get_live_upload(upload_id, with_content=True)
    if uploaded_log is None:
        return _not_found()

    rule_set_key = resolve_user_rule_set_key(request.user)
    if get_fresh_cached_analysis(uploaded_log, rule_set_key) is None:
        if not charge_api_units(request, ANALYSIS_RECOMPUTE_EXTRA_UNITS):
            return rate_limited_response(60)
    analysis, _computed = get_or_compute_upload_analysis(uploaded_log, rule_set_key)

    entries = analysis.get('lines', [])
    numbers = _non_blank_line_numbers(uploaded_log.content)
    if len(numbers) != len(entries):
        numbers = [None] * len(entries)
    lines = [
        _compact_line(number, entry)
        for number, entry in zip(numbers, entries)
        if not statuses or entry.get('dominant_status') in statuses
    ]

    payload = _uploads_metadata(request.user, [uploaded_log])[0]
    payload.update({
        'rule_set': 'shared' if rule_set_key == SHARED_RULE_SET_KEY else 'private',
        'status_legend': STATUS_LABELS,
        'summary': analysis.get('summary', {}),
        'warnings': analysis.get('warnings', []),
        'matching_line_count': len(lines),
        'offset': offset,
        'limit': limit,
        'untrusted_lines': lines[offset:offset + limit],
    })
    return JsonResponse(payload)


@api_token_required('api_v1_search', cost=10)
def api_search(request):
    """Search log contents (substring, or re2-safe regex with regex=1)."""
    query = (request.GET.get('q') or '').strip()
    if not query:
        return _error('q is required.')
    if len(query) > QUERY_MAX_CHARS:
        return _error(f'q must be at most {QUERY_MAX_CHARS} characters.')
    limit = _int_param(request, 'limit', LIST_DEFAULT_LIMIT, 1, LIST_MAX_LIMIT)
    if limit is None:
        return _error('limit must be an integer.')
    use_regex = request.GET.get('regex') == '1'
    log_type = (request.GET.get('type') or '').strip()

    log_ids, truncated, search_error, matcher = search_matching_log_ids(
        query, use_regex, limit, False, log_type
    )
    if search_error:
        return _error(search_error)

    logs = _logs_in_id_order(log_ids, with_content=True)
    case_ids = _own_case_ids_by_upload(request.user, [uploaded_log.pk for uploaded_log in logs])
    matches = []
    for uploaded_log in logs:
        entry = _upload_metadata(uploaded_log, case_ids)
        hit = _first_hit(uploaded_log.content, matcher) if matcher else None
        entry['first_hit'] = (
            {'line_number': hit[0], 'untrusted_text': hit[1] + hit[2] + hit[3]} if hit else None
        )
        matches.append(entry)
    return JsonResponse({'truncated': truncated, 'limit': limit, 'matches': matches})


def _case_summary(infection_case, user):
    return {
        'case_id': infection_case.case_id,
        'forum_username': infection_case.username,
        'status': infection_case.status,
        'is_training': infection_case.is_training,
        'owner': infection_case.owner.username,
        'is_own_case': infection_case.owner_id == user.id,
        'created_at': _iso(infection_case.created_at),
        'updated_at': _iso(infection_case.updated_at),
    }


def _visible_snippets(user):
    """Snippets the caller can use in the browser: their own plus every shared one."""
    return (
        FixlistSnippet.objects.filter(Q(owner=user) | Q(is_shared=True))
        .select_related('owner')
        .order_by('category', 'name', 'pk')
    )


def _snippet_payload(snippet, user):
    return {
        'snippet_id': snippet.pk,
        'name': snippet.name,
        'category': snippet.category,
        'owner': snippet.owner.username,
        'is_own': snippet.owner_id == user.id,
        'is_shared': snippet.is_shared,
        'updated_at': _iso(snippet.updated_at),
        'content': snippet.content,
    }


@api_token_required('api_v1_snippets')
def api_snippets(request):
    """Fixlist snippets: own and shared. q matches name, content or owner; category filters exactly.

    Alert rules in an analysis often name the snippet a helper should use.
    """
    limit = _int_param(request, 'limit', SNIPPETS_DEFAULT_LIMIT, 1, SNIPPETS_MAX_LIMIT)
    offset = _int_param(request, 'offset', 0, 0, LIST_MAX_OFFSET)
    if limit is None or offset is None:
        return _error('limit and offset must be integers.')

    snippets = _visible_snippets(request.user)
    search_query = (request.GET.get('q') or '').strip()[:QUERY_MAX_CHARS]
    if search_query:
        snippets = snippets.filter(
            Q(name__icontains=search_query)
            | Q(content__icontains=search_query)
            | Q(owner__username__icontains=search_query)
        )
    category = (request.GET.get('category') or '').strip()
    if category:
        snippets = snippets.filter(category=category)

    total = snippets.count()
    return JsonResponse({
        'total': total,
        'offset': offset,
        'limit': limit,
        'categories': sorted(set(_visible_snippets(request.user).values_list('category', flat=True))),
        'snippets': [
            _snippet_payload(snippet, request.user) for snippet in snippets[offset:offset + limit]
        ],
    })


@api_token_required('api_v1_snippet')
def api_snippet(request, snippet_id):
    """One fixlist snippet by id, if it is the caller's own or shared."""
    snippet = _visible_snippets(request.user).filter(pk=snippet_id).first()
    if snippet is None:
        return _not_found()
    return JsonResponse(_snippet_payload(snippet, request.user))


@api_token_required('api_v1_user')
def api_user(request, forum_username):
    """A forum poster's uploads (all helpers) and the caller's own cases for them."""
    forum_username = (forum_username or '').strip()
    if not forum_username or len(forum_username) > FORUM_USERNAME_MAX_CHARS:
        return _not_found()
    limit = _int_param(request, 'limit', LIST_MAX_LIMIT, 1, LIST_MAX_LIMIT)
    if limit is None:
        return _error('limit must be an integer.')

    uploads = _live_uploads().filter(forum_username__iexact=forum_username)
    own_cases = (
        InfectionCase.objects.filter(
            owner=request.user,
            username__iexact=forum_username,
            deleted_at__isnull=True,
        )
        .select_related('owner')
    )
    return JsonResponse({
        'untrusted_forum_username': forum_username,
        'upload_total': uploads.count(),
        'uploads': _uploads_metadata(request.user, list(uploads[:limit])),
        'own_cases': [_case_summary(infection_case, request.user) for infection_case in own_cases],
    })


def _timeline_entry(item, user, case_ids):
    item_type = item['item_type']
    entry = {'type': item_type, 'created_at': _iso(item['created_at'])}
    if item_type == 'log':
        entry['upload'] = _upload_metadata(item['uploaded_log'], case_ids)
    elif item_type == 'fixlist':
        # Same text the share link serves to any logged-in helper. The owner's
        # internal note is never included.
        fixlist = item['fixlist']
        entry.update({'fixlist_id': fixlist.pk, 'line_count': fixlist.line_count, 'content': fixlist.content})
    elif item_type == 'response':
        fixlist = item['fixlist']
        entry.update({'fixlist_id': fixlist.pk, 'response': fixlist.response})
    elif item_type == 'note':
        note = item['note']
        entry.update({
            'note_id': note.pk,
            'author': note.created_by.username if note.created_by else None,
            'content': note.content,
        })
    return entry


@api_token_required('api_v1_case')
def api_case(request, case_id):
    """One infection case and its timeline: logs, fixlists, responses, notes."""
    if not CASE_ID_RE.fullmatch(case_id or ''):
        return _not_found()
    infection_case = (
        InfectionCase.objects.filter(deleted_at__isnull=True, case_id=case_id)
        .select_related('owner')
        .first()
    )
    if infection_case is None:
        return _not_found()

    timeline = _build_case_timeline(infection_case)
    upload_pks = [item['uploaded_log'].pk for item in timeline if item['item_type'] == 'log']
    case_ids = _own_case_ids_by_upload(request.user, upload_pks)

    payload = _case_summary(infection_case, request.user)
    payload.update({
        'untrusted_symptom_description': infection_case.symptom_description,
        'reference_url': infection_case.reference_url,
        'timeline': [_timeline_entry(item, request.user, case_ids) for item in timeline],
    })
    return JsonResponse(payload)
