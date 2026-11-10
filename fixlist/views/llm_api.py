"""
Token API (/api/v1/) for LLM clients.

Mostly read-only: the write endpoints (rule tags, speeches, fixlist snippets and
classification rules) need a superuser's write token, see api_auth. Serves what a logged-in
helper can already read in the browser: every
non-trashed upload, its verdicts under the caller's own rule set, content
search, infection cases by id, the fixlist snippets and speeches the caller
owns or that are shared, the caller's fixlist starter template, and every
classification rule, as on the rules page. Listing cases is limited to the caller's own,
as on the cases page. Authentication, limits and logging live in api_auth.

Fields holding text that came from the infected machine or its user (log lines,
forum username, filename, symptom description) are prefixed `untrusted_`, so a
model reading the JSON is told at every use that the text is data, not
instructions.

Version 2 of the API (see api_auth.API_VERSION) only added parameters, fields
and endpoints: a request without the new parameters gets the same response as
before. Search, the rule dry run and rule matching also take a POST with a JSON
body, for input that does not fit a URL.
"""

import re
import time

from django.db.models import Q
from django.http import JsonResponse
from django.urls import reverse

from .. import frst_extractors as ex
from ..analyzer import _get_cached_rule_buckets, evaluate_regex_pattern, inspect_line_matches
from ..api_line_search import (
    COMPONENT_KEYS,
    LINES_PER_LOG_MAX,
    SEARCH_MAX_MATCHES,
    LineSearch,
    cached_matching_logs,
    non_blank_line_numbers,
    parse_components,
    serialize_hit,
)
from ..api_params import (
    ParamError,
    apply_upload_scope,
    flag_param,
    int_param,
    list_param,
    optional_int_param,
    scope_cache_part,
    text_param,
)
from ..models import ClassificationRule, FixlistSnippet, InfectionCase, InfectionCaseLog, RuleTag, Speech, UploadedLog
from ..rule_sets import SHARED_RULE_SET_KEY, resolve_user_rule_set_key
from ..status_types import STATUS_LABELS, VALID_STATUSES
from ..rule_test_service import (
    build_rule_test_results,
    compare_rule_scans,
    line_outcome,
    literal_prefilter,
    scan_logs_for_rule_matches,
    scan_logs_for_wholelog_matches,
    summarize_rule_test,
)
from ..tagging import (
    TagConditions,
    apply_tag,
    attach_rule_tags,
    attach_tags_to_matches,
    describe_conditions,
    logs_with_tags,
    matching_rule_ids,
    parse_tag_ids,
    save_tag,
    serialize_tag,
    unmatched_tagged_rule_ids,
)
from ..upload_duplicates import duplicate_info_for, duplicate_metadata, non_canonical_pks
from ..validators import BadJsonError, PayloadTooLargeError, PayloadValidator
from ..upload_utils import get_fresh_cached_analysis, get_or_compute_upload_analysis
from .api_auth import api_token_required, charge_api_units, rate_limited_response
from .auth import DEFAULT_ANALYZER_FIXLIST_TEMPLATE, effective_analyzer_fixlist_template
from .guest import is_moderator
from .infection_cases import _build_case_timeline
from .log_search import _build_matcher, _logs_in_id_order
from .rules import (
    _apply_rule_edit,
    _patterns_for,
    _read_rule_test_payload,
    _rule_form_from_rule,
    create_rules,
)
from .snippets import _validate_snippet_form
from .speeches import _speech_validation_error, speeches_for_tags
from .uploads import filter_uploads_by_text

UPLOAD_ID_RE = re.compile(r'[A-Za-z0-9_.-]{1,64}')
CASE_ID_RE = re.compile(r'[A-Za-z0-9_-]{1,24}')
FORUM_USERNAME_MAX_CHARS = 100
QUERY_MAX_CHARS = 500

LIST_DEFAULT_LIMIT = 20
LIST_MAX_LIMIT = 50
LIST_MAX_OFFSET = 10000
LIBRARY_DEFAULT_LIMIT = 50
LIBRARY_MAX_LIMIT = 100
LINES_DEFAULT_LIMIT = 500
LINES_MAX_LIMIT = 2000
LINES_MAX_OFFSET = 200000
# get_upload slices (start_line/max_lines/match).
SLICE_MAX_LINES = 5000
SLICE_MAX_CONTEXT = 5
SLICE_PARAMS = ('start_line', 'max_lines', 'match', 'context')
# A stale or missing cache means a full analyzer run; charge it like a search.
ANALYSIS_RECOMPUTE_EXTRA_UNITS = 9
# Filtering the upload list by tag reads every candidate's cached analysis.
TAG_FILTER_EXTRA_UNITS = 9
TAGS_PARAM_MAX_ITEMS = 20


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


def _params(request):
    """``(params, error_response)``: the query string of a GET, the JSON object of a POST."""
    if request.method == 'POST':
        return _write_payload(request)
    return request.GET, None


def _tag_ids_param(params):
    """``(tag_ids, error_response)`` from the `tags` param: comma-separated, or a JSON list.

    Each item is a tag id or a tag name (case-insensitive; names never hold a
    comma). An unknown one is an error naming it rather than being dropped, so
    a client learns of a typo instead of getting a wider search.
    """
    try:
        items = list_param(params, 'tags')
    except ParamError as exc:
        return None, _error(str(exc))
    if len(items) > TAGS_PARAM_MAX_ITEMS:
        return None, _error(f'tags takes at most {TAGS_PARAM_MAX_ITEMS} tags.')
    tag_ids = []
    unknown = []
    for item in items:
        if item.isdigit():
            tag = RuleTag.objects.filter(pk=int(item)).first()
        else:
            tag = RuleTag.objects.filter(name__iexact=item).first()
        if tag is None:
            unknown.append(item)
        elif tag.pk not in tag_ids:
            tag_ids.append(tag.pk)
    if unknown:
        return None, _error(f"Unknown tag(s): {', '.join(unknown)}. list_tags shows the tags.")
    return tag_ids, None


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


def _live_upload_rows():
    return UploadedLog.objects.filter(deleted_at__isnull=True)


def _upload_metadata(uploaded_log, case_ids, duplicates=None):
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
        # Another upload of the same scan (see upload_duplicates): duplicate_of
        # names the more complete copy, duplicates the copies of this one.
        **duplicate_metadata((duplicates or {}).get(uploaded_log.pk)),
    }


def _uploads_metadata(user, uploads):
    uploads = list(uploads)
    case_ids = _own_case_ids_by_upload(user, [uploaded_log.pk for uploaded_log in uploads])
    duplicates = duplicate_info_for(uploads, _live_upload_rows())
    return [_upload_metadata(uploaded_log, case_ids, duplicates) for uploaded_log in uploads]


def _get_live_upload(upload_id, *, with_content):
    if not UPLOAD_ID_RE.fullmatch(upload_id or ''):
        return None
    uploads = UploadedLog.objects.filter(deleted_at__isnull=True).select_related('recipient_user')
    if not with_content:
        uploads = uploads.defer('content')
    return uploads.filter(upload_id=upload_id).first()


@api_token_required('api_v1_uploads')
def api_uploads(request):
    """List uploads, newest first. Filters: q (id/poster/helper/filename), username,
    type / exclude_type (comma-separated log types), created_after / created_before
    (ISO dates, inclusive), tags (every one found in the upload's cached analysis
    under the caller's rule set), dedupe (hide copies of a more complete upload of
    the same scan, see upload_duplicates)."""
    limit = _int_param(request, 'limit', LIST_DEFAULT_LIMIT, 1, LIST_MAX_LIMIT)
    offset = _int_param(request, 'offset', 0, 0, LIST_MAX_OFFSET)
    if limit is None or offset is None:
        return _error('limit and offset must be integers.')
    tag_ids, error = _tag_ids_param(request.GET)
    if error:
        return error

    uploads = _live_uploads()
    search_query = (request.GET.get('q') or '').strip()[:QUERY_MAX_CHARS]
    if search_query:
        uploads = filter_uploads_by_text(uploads, search_query)
    username = (request.GET.get('username') or '').strip()
    if username:
        uploads = uploads.filter(forum_username__iexact=username)
    try:
        uploads = apply_upload_scope(uploads, request.GET)
        dedupe = flag_param(request.GET, 'dedupe')
    except ParamError as exc:
        return _error(str(exc))
    extra = {}
    if tag_ids:
        if not charge_api_units(request, TAG_FILTER_EXTRA_UNITS):
            return rate_limited_response(60)
        tagged_pks, unanalyzed_count = logs_with_tags(
            tag_ids, resolve_user_rule_set_key(request.user), uploads,
        )
        uploads = uploads.filter(pk__in=tagged_pks)
        extra['tag_unanalyzed_count'] = unanalyzed_count

    if dedupe:
        # Paged in Python: the hidden copies can be many, too many for an SQL IN.
        hidden = non_canonical_pks(uploads)
        ordered = [pk for pk in uploads.values_list('pk', flat=True) if pk not in hidden]
        total = len(ordered)
        page_pks = ordered[offset:offset + limit]
        by_pk = {uploaded_log.pk: uploaded_log for uploaded_log in _live_uploads().filter(pk__in=page_pks)}
        page = [by_pk[pk] for pk in page_pks if pk in by_pk]
        extra['duplicates_hidden'] = len(hidden)
    else:
        total = uploads.count()
        page = list(uploads[offset:offset + limit])
    return JsonResponse({
        'total': total,
        'offset': offset,
        'limit': limit,
        **extra,
        'uploads': _uploads_metadata(request.user, page),
    })


def _upload_slice(content, params):
    """The `untrusted_lines` slice get_upload returns when a slice parameter is given, else None.

    `start_line` and `max_lines` pick a range of lines (numbered as in the log
    text, blank lines included); `match` (substring, or regex with `regex`,
    case-insensitive unless `case_sensitive`) keeps only matching lines from
    there on, each with `context` lines around it. `next_line` continues.
    """
    if not any(params.get(name) not in (None, '') for name in SLICE_PARAMS):
        return None
    start_line = int_param(params, 'start_line', 1, 1, LINES_MAX_OFFSET)
    max_lines = int_param(params, 'max_lines', LINES_DEFAULT_LIMIT, 1, SLICE_MAX_LINES)
    match = text_param(params, 'match', max_chars=QUERY_MAX_CHARS)
    context = int_param(params, 'context', 0, 0, SLICE_MAX_CONTEXT)
    use_regex = flag_param(params, 'regex')
    case_sensitive = flag_param(params, 'case_sensitive')

    lines = [line.rstrip('\r') for line in (content or '').splitlines()]
    payload = {'line_count': len(lines)}
    if match:
        matcher, error = _build_matcher(match, use_regex, case_sensitive)
        if error:
            raise ParamError(f'match: {error}')
        wanted = set()
        match_count = 0
        for number in range(start_line, len(lines) + 1):
            if matcher(lines[number - 1]) is None:
                continue
            match_count += 1
            low = max(start_line, number - context)
            high = min(len(lines), number + context)
            wanted.update(range(low, high + 1))
        numbers = sorted(wanted)
        payload['matching_line_count'] = match_count
    else:
        numbers = list(range(start_line, len(lines) + 1))
    selected = numbers[:max_lines]
    payload['next_line'] = numbers[max_lines] if len(numbers) > max_lines else None
    payload['untrusted_lines'] = [{'n': number, 'text': lines[number - 1]} for number in selected]
    return payload


@api_token_required('api_v1_upload')
def api_upload(request, upload_id):
    """One upload's metadata and its log text: all of it in untrusted_content, or with
    start_line / max_lines / match (+ regex, case_sensitive, context) only those lines,
    as untrusted_lines."""
    uploaded_log = _get_live_upload(upload_id, with_content=True)
    if uploaded_log is None:
        return _not_found()
    try:
        sliced = _upload_slice(uploaded_log.content, request.GET)
    except ParamError as exc:
        return _error(str(exc))
    payload = _uploads_metadata(request.user, [uploaded_log])[0]
    if sliced is None:
        payload['untrusted_content'] = uploaded_log.content
    else:
        payload.update(sliced)
    return JsonResponse(payload)


_non_blank_line_numbers = non_blank_line_numbers

# The keys of a line in get_analysis (_compact_line); `fields` picks among them.
LINE_FIELDS = (
    'n', 'text', 'status', 'status_label', 'status_codes', 'entry_type', 'matcher', 'reasons',
    'components', 'dates', 'fixlist_replacement', 'rule_ids', 'tag_ids', 'tags',
)


def _compact_line(number, entry, tag_names):
    """Drop the presentation-only fields of an analyzer line; keep the verdict.

    `tag_names` maps tag id -> name for the tags found in the log.
    """
    tag_ids = entry.get('tag_ids', [])
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
        # The rules that decided the line; get_rule reads one.
        'rule_ids': entry.get('rule_ids', []),
        # Rule tags of the rules that decided the line (see rule_tags).
        'tag_ids': tag_ids,
        'tags': [tag_names[tag_id] for tag_id in tag_ids if tag_id in tag_names],
    }


def _served_analysis(request, uploaded_log):
    """``(analysis, rule_set_key, error_response)`` for one upload under the caller's rule set.

    A stale or missing cache costs extra units, since it means an analyzer run.
    Tags are attached when served, never cached: lines and warnings get
    tag_ids and the payload gets rule_tags.
    """
    rule_set_key = resolve_user_rule_set_key(request.user)
    if get_fresh_cached_analysis(uploaded_log, rule_set_key) is None:
        if not charge_api_units(request, ANALYSIS_RECOMPUTE_EXTRA_UNITS):
            return None, rule_set_key, rate_limited_response(60)
    analysis, _computed = get_or_compute_upload_analysis(uploaded_log, rule_set_key)
    attach_rule_tags(analysis)
    return analysis, rule_set_key, None


def _numbered_entries(uploaded_log, analysis):
    """``[(line number, entry)]`` for the analysis lines, numbered as in the log text."""
    entries = analysis.get('lines', [])
    numbers = _non_blank_line_numbers(uploaded_log.content)
    if len(numbers) != len(entries):
        numbers = [None] * len(entries)
    return list(zip(numbers, entries))


@api_token_required('api_v1_upload_analysis')
def api_upload_analysis(request, upload_id):
    """Per-line verdicts for one upload under the caller's rule set.

    `status` filters by verdict letter (comma-separated, e.g. B,P,?); `tags`
    keeps the lines carrying any of the given tags (names or ids). `fields`
    (comma-separated, see LINE_FIELDS) keeps only those keys of each line, and
    `summary=0` leaves out the summary, warnings, tags found and status legend,
    for reading many logs or paging through one.
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
    tag_ids, error = _tag_ids_param(request.GET)
    if error:
        return error
    try:
        fields = list_param(request.GET, 'fields')
        with_summary = flag_param(request.GET, 'summary', default=True)
    except ParamError as exc:
        return _error(str(exc))
    unknown_fields = [field for field in fields if field not in LINE_FIELDS]
    if unknown_fields:
        return _error(f"Unknown field(s): {', '.join(unknown_fields)}. Valid: {', '.join(LINE_FIELDS)}.")

    uploaded_log = _get_live_upload(upload_id, with_content=True)
    if uploaded_log is None:
        return _not_found()

    analysis, rule_set_key, error = _served_analysis(request, uploaded_log)
    if error:
        return error

    tag_names = {tag['id']: tag['name'] for tag in analysis.get('rule_tags', [])}
    wanted_tags = set(tag_ids)
    lines = [
        _compact_line(number, entry, tag_names)
        for number, entry in _numbered_entries(uploaded_log, analysis)
        if (not statuses or entry.get('dominant_status') in statuses)
        and (not wanted_tags or wanted_tags.intersection(entry.get('tag_ids', [])))
    ]
    page = lines[offset:offset + limit]
    if fields:
        page = [{key: line[key] for key in fields} for line in page]

    payload = _uploads_metadata(request.user, [uploaded_log])[0]
    payload['rule_set'] = 'shared' if rule_set_key == SHARED_RULE_SET_KEY else 'private'
    if with_summary:
        payload.update({
            'status_legend': STATUS_LABELS,
            'summary': analysis.get('summary', {}),
            'warnings': analysis.get('warnings', []),
            'rule_tags': analysis.get('rule_tags', []),
        })
    payload.update({
        'matching_line_count': len(lines),
        'offset': offset,
        'limit': limit,
        'untrusted_lines': page,
    })
    return JsonResponse(payload)


SEARCH_GET_QUERY_MAX_CHARS = QUERY_MAX_CHARS
SEARCH_POST_QUERY_MAX_CHARS = 2000
COUNT_ALL_EXTRA_UNITS = 10


@api_token_required('api_v1_search', cost=10, methods=('GET', 'POST'))
def api_search(request):
    """Search log contents line by line, newest logs first.

    Lines are chosen by `q` (substring, or re2-safe regex with regex=1;
    case-insensitive unless case_sensitive=1), by `components` (parsed FRST
    entry fields, see api_line_search.ComponentFilter), or both; `tags` keeps
    logs containing every given tag (and alone picks the lines carrying one).
    `statuses` keeps only lines with those verdicts in the log's cached
    analysis; `with_verdicts` adds each hit's verdict. `lines_per_log` hits per
    log come back with `hit_count`, the log's total; `first_hit` is the first.
    Paged with offset/limit; `count_all` counts every matching log and line.
    Scope: type / exclude_type, created_after / created_before, dedupe. GET as
    before, or POST with a JSON body for queries up to 2000 characters.
    """
    params, error = _params(request)
    if error:
        return error
    tag_ids, error = _tag_ids_param(params)
    if error:
        return error
    try:
        query = text_param(params, 'q')
        max_chars = SEARCH_POST_QUERY_MAX_CHARS if request.method == 'POST' else SEARCH_GET_QUERY_MAX_CHARS
        if len(query) > max_chars:
            return _error(f'q must be at most {max_chars} characters.')
        components, message = parse_components(params.get('components'))
        if message:
            return _error(message)
        if not query and not tag_ids and not components:
            return _error('q or tags is required (or components).')
        limit = int_param(params, 'limit', LIST_DEFAULT_LIMIT, 1, LIST_MAX_LIMIT)
        offset = int_param(params, 'offset', 0, 0, SEARCH_MAX_MATCHES)
        use_regex = flag_param(params, 'regex')
        case_sensitive = flag_param(params, 'case_sensitive')
        lines_per_log = int_param(params, 'lines_per_log', 1, 1, LINES_PER_LOG_MAX)
        statuses = list_param(params, 'statuses', max_items=len(VALID_STATUSES))
        with_verdicts = flag_param(params, 'with_verdicts') or bool(statuses)
        count_all = flag_param(params, 'count_all')
        dedupe = flag_param(params, 'dedupe')
        scoped = apply_upload_scope(_live_upload_rows(), params)
        scope_part = scope_cache_part(params)
    except ParamError as exc:
        return _error(str(exc))
    invalid = set(statuses) - VALID_STATUSES
    if invalid:
        return _error(
            f"Unknown status code(s): {', '.join(sorted(invalid))}. "
            f"Valid: {' '.join(sorted(VALID_STATUSES))}."
        )

    rule_set_key = resolve_user_rule_set_key(request.user)
    search = LineSearch(
        query=query, use_regex=use_regex, case_sensitive=case_sensitive, components=components,
        statuses=statuses, tag_ids=tag_ids, rule_set_key=rule_set_key,
    )
    if search.error:
        return _error(search.error)
    if count_all and not charge_api_units(request, COUNT_ALL_EXTRA_UNITS):
        return rate_limited_response(60)

    def build_scope():
        narrowed = scoped
        extra = {}
        if tag_ids:
            tagged_pks, extra['tag_unanalyzed_count'] = logs_with_tags(tag_ids, rule_set_key, narrowed)
            narrowed = narrowed.filter(pk__in=tagged_pks)
        hidden = non_canonical_pks(narrowed) if dedupe else set()
        extra['duplicates_hidden'] = len(hidden)
        return narrowed, hidden, extra

    found = cached_matching_logs(
        search, build_scope, scope_part=scope_part, dedupe=dedupe,
        needed=offset + limit + 1, count_all=count_all,
    )
    pks = found['pks']
    logs = _logs_in_id_order(pks[offset:offset + limit], with_content=True)
    matches = []
    for uploaded_log, entry in zip(logs, _uploads_metadata(request.user, logs)):
        result = search.evaluate(
            uploaded_log.pk, uploaded_log.content, uploaded_log.content_hash,
            max_hits=lines_per_log, with_verdicts=with_verdicts,
        )
        hits = [serialize_hit(hit, with_verdicts) for hit in (result or {}).get('hits', [])]
        entry['first_hit'] = (
            {'line_number': hits[0]['line_number'], 'untrusted_text': hits[0]['untrusted_text']} if hits else None
        )
        entry['hit_count'] = result['hit_count'] if result else 0
        entry['hits'] = hits
        if with_verdicts:
            entry['verdicts_from'] = result['verdicts_from'] if result else None
        matches.append(entry)

    has_more = len(pks) > offset + limit
    payload = {
        'truncated': has_more or found['timed_out'],
        'offset': offset,
        'limit': limit,
        'next_offset': offset + limit if has_more else None,
        'timed_out': found['timed_out'],
        'matches': matches,
    }
    if tag_ids:
        payload['tag_unanalyzed_count'] = found.get('tag_unanalyzed_count', 0)
    if statuses:
        # Logs whose text matched but that have no cached analysis to read verdicts from.
        payload['unanalyzed_count'] = found['unanalyzed_count']
    if dedupe:
        payload['duplicates_hidden'] = found.get('duplicates_hidden', 0)
    if count_all:
        payload['totals'] = found['totals']
    return JsonResponse(payload)


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


def _visible_library_items(model, user):
    """Snippets or speeches the caller can use in the browser: their own plus every shared one."""
    items = (
        model.objects.filter(Q(owner=user) | Q(is_shared=True))
        .select_related('owner')
        .order_by('category', 'name', 'pk')
    )
    # Both kinds name the rule tags the analyzer suggests them for.
    return items.prefetch_related('trigger_tags')


def _library_item_payload(item, user, id_key):
    payload = {
        id_key: item.pk,
        'name': item.name,
        'category': item.category,
        'owner': item.owner.username,
        'is_own': item.owner_id == user.id,
        'is_shared': item.is_shared,
        'updated_at': _iso(item.updated_at),
        'content': item.content,
    }
    # The rule tags the analyzer suggests the snippet or speech for.
    payload['trigger_tags'] = [{'tag_id': tag.pk, 'name': tag.name} for tag in item.trigger_tags.all()]
    if isinstance(item, Speech):
        payload['is_fix_message'] = item.is_fix_message
    return payload


def _library_list_response(request, model, id_key, list_key, extra=None):
    """Paged list of own and shared items. q matches name, content or owner; category filters exactly."""
    limit = _int_param(request, 'limit', LIBRARY_DEFAULT_LIMIT, 1, LIBRARY_MAX_LIMIT)
    offset = _int_param(request, 'offset', 0, 0, LIST_MAX_OFFSET)
    if limit is None or offset is None:
        return _error('limit and offset must be integers.')

    items = _visible_library_items(model, request.user)
    search_query = (request.GET.get('q') or '').strip()[:QUERY_MAX_CHARS]
    if search_query:
        items = items.filter(
            Q(name__icontains=search_query)
            | Q(content__icontains=search_query)
            | Q(owner__username__icontains=search_query)
        )
    category = (request.GET.get('category') or '').strip()
    if category:
        items = items.filter(category=category)

    payload = {
        'total': items.count(),
        'offset': offset,
        'limit': limit,
        'categories': sorted(set(
            _visible_library_items(model, request.user).values_list('category', flat=True)
        )),
        **(extra or {}),
        list_key: [
            _library_item_payload(item, request.user, id_key) for item in items[offset:offset + limit]
        ],
    }
    return JsonResponse(payload)


def _library_item_response(request, model, item_id, id_key, extra=None):
    item = _visible_library_items(model, request.user).filter(pk=item_id).first()
    if item is None:
        return _not_found()
    return JsonResponse({**_library_item_payload(item, request.user, id_key), **(extra or {})})


@api_token_required('api_v1_snippets')
def api_snippets(request):
    """Fixlist snippets, own and shared. Alert rules in an analysis often name the one to use."""
    return _library_list_response(request, FixlistSnippet, 'snippet_id', 'snippets')


@api_token_required('api_v1_snippet')
def api_snippet(request, snippet_id):
    """One fixlist snippet by id, if it is the caller's own or shared."""
    return _library_item_response(request, FixlistSnippet, snippet_id, 'snippet_id')


def _speech_placeholders(request):
    """Values for the speech placeholders the server can resolve.

    {USERNAME}, the *_PREFILLED links and {COUNTER} depend on the reply being
    written (forum user, step numbering), so the client resolves those itself,
    as the log analyzer does in applySpeechPlaceholders(). {FIXLISTLINK} and
    {FRSTPATH} have no value until a fixlist exists; they are filled when the
    fixlist carrying the response is saved, so a client leaves them as they are.
    """
    return {
        '{HELPERNAME}': request.user.username,
        '{UPLOADLINK_HELPER}': request.build_absolute_uri(
            reverse('upload_log_for_helper', args=[request.user.username])
        ),
        '{UPLOADLINK_GENERAL}': request.build_absolute_uri(reverse('upload_log')),
    }


@api_token_required('api_v1_speeches')
def api_speeches(request):
    """Speeches (canned reply paragraphs), own and shared, with the resolvable placeholder values."""
    return _library_list_response(
        request, Speech, 'speech_id', 'speeches',
        extra={'placeholders': _speech_placeholders(request)},
    )


@api_token_required('api_v1_speech')
def api_speech(request, speech_id):
    """One speech by id, if it is the caller's own or shared."""
    return _library_item_response(
        request, Speech, speech_id, 'speech_id',
        extra={'placeholders': _speech_placeholders(request)},
    )


def _recommended_speech(speech, user, found_tag_ids):
    payload = _library_item_payload(speech, user, 'speech_id')
    payload['for_tag_ids'] = sorted(tag.pk for tag in speech.trigger_tags.all() if tag.pk in found_tag_ids)
    return payload


@api_token_required('api_v1_upload_speeches')
def api_upload_speeches(request, upload_id):
    """The speeches the log analyzer recommends for one upload, or for one of its lines.

    Without `line`, for every rule tag found in the log (lines, warnings,
    whole-log rules); with `line=n` (numbered as in the analysis), for that
    line's tags only. `suggested` are the caller's selected speeches naming a
    found tag; `shared_fallback` are other helpers' shared speeches for tags
    none of the caller's selected speeches names - for a line only when
    nothing of the caller's own fits, as a click on the line in the analyzer.
    """
    line_number = _int_param(request, 'line', 0, 0, LINES_MAX_OFFSET)
    if line_number is None:
        return _error('line must be an integer.')

    uploaded_log = _get_live_upload(upload_id, with_content=True)
    if uploaded_log is None:
        return _not_found()

    analysis, rule_set_key, error = _served_analysis(request, uploaded_log)
    if error:
        return error

    found_tags = {tag['id']: tag for tag in analysis.get('rule_tags', [])}
    line_text = None
    if line_number:
        entry = next(
            (entry for number, entry in _numbered_entries(uploaded_log, analysis) if number == line_number),
            None,
        )
        if entry is None:
            return _error(f'Line {line_number} is blank or past the end of the log.')
        tag_ids = entry.get('tag_ids', [])
        line_text = entry.get('line', '')
    else:
        tag_ids = list(found_tags)

    suggested, shared_fallback = speeches_for_tags(request.user, tag_ids)
    if line_number and suggested:
        shared_fallback = []
    found = set(tag_ids)

    payload = {
        'upload_id': uploaded_log.upload_id,
        'rule_set': 'shared' if rule_set_key == SHARED_RULE_SET_KEY else 'private',
        'line_number': line_number or None,
        'tags': [
            {
                'tag_id': tag_id,
                'name': found_tags[tag_id]['name'],
                'line_count': found_tags[tag_id]['line_count'],
                'wholelog': found_tags[tag_id]['wholelog'],
            }
            for tag_id in tag_ids if tag_id in found_tags
        ],
        'suggested': [_recommended_speech(speech, request.user, found) for speech in suggested],
        'shared_fallback': [_recommended_speech(speech, request.user, found) for speech in shared_fallback],
        'placeholders': _speech_placeholders(request),
    }
    if line_number:
        payload['untrusted_line_text'] = line_text
    return JsonResponse(payload)


@api_token_required('api_v1_fixlist_template')
def api_fixlist_template(request):
    """The caller's log analyzer fixlist starter (profile setting, else the default).

    `insert_entries_at_line` is where the analyzer user would put the lines to
    fix: the template's first empty line, else the line holding End::.
    """
    # Saved from a textarea, so it may carry Windows line endings.
    template = effective_analyzer_fixlist_template(request.user).replace('\r\n', '\n')
    lines = template.split('\n')
    insert_at = next((index for index, line in enumerate(lines) if not line.strip()), None)
    if insert_at is None:
        insert_at = next(
            (index for index, line in enumerate(lines) if line.strip().lower() == 'end::'),
            len(lines),
        )
    return JsonResponse({
        'template': template,
        'is_default': template == DEFAULT_ANALYZER_FIXLIST_TEMPLATE,
        'insert_entries_at_line': insert_at + 1,
    })


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


def _timeline_entry(item, user, case_ids, duplicates=None):
    item_type = item['item_type']
    entry = {'type': item_type, 'created_at': _iso(item['created_at'])}
    if item_type == 'log':
        entry['upload'] = _upload_metadata(item['uploaded_log'], case_ids, duplicates)
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
    case_uploads = [item['uploaded_log'] for item in timeline if item['item_type'] == 'log']
    case_ids = _own_case_ids_by_upload(request.user, [uploaded_log.pk for uploaded_log in case_uploads])
    duplicates = duplicate_info_for(case_uploads, _live_upload_rows())

    payload = _case_summary(infection_case, request.user)
    payload.update({
        'untrusted_symptom_description': infection_case.symptom_description,
        'reference_url': infection_case.reference_url,
        'timeline': [_timeline_entry(item, request.user, case_ids, duplicates) for item in timeline],
    })
    return JsonResponse(payload)


# ---------------------------------------------------------------------------
# Rule tags. Reading is open to every token; writing needs a superuser's write
# token (api_token_required(write=True)) and goes through the same services as
# the tag editor (tagging.save_tag), so both validate the same way.
# ---------------------------------------------------------------------------

TAG_RULES_DEFAULT_LIMIT = 100
TAG_RULES_MAX_LIMIT = 500
APPLY_SAMPLE_SIZE = 50
APPLY_MODES = ('add_matching', 'remove_unmatched', 'add_rules', 'remove_rules')


def _tag_summary(tag):
    conditions = TagConditions.of(tag)
    return {
        **{('tag_id' if key == 'id' else key): value for key, value in serialize_tag(tag).items()},
        'conditions': describe_conditions(conditions),
        'builtin_code': tag.builtin_code,
        'rule_count': tag.rules.count(),
        'speech_count': tag.speeches.count(),
        'snippet_count': tag.snippets.count(),
    }


def _rule_row(rule):
    return {
        'rule_id': rule.pk,
        'status': rule.status,
        'match_type': rule.match_type,
        'entry_type': rule.entry_type,
        'source_text': rule.source_text,
        'description': rule.description,
        'owner': rule.owner.username if rule.owner_id else '',
    }


@api_token_required('api_v1_tags')
def api_tags(request):
    """All rule tags with their conditions and how many rules, speeches and snippets use them."""
    return JsonResponse({'tags': [_tag_summary(tag) for tag in RuleTag.objects.select_related('category').order_by('name')]})


@api_token_required('api_v1_tag')
def api_tag(request, tag_id):
    """One rule tag: its conditions, the speeches and snippets it suggests that the
    caller can see, and the rules carrying it (paged with limit/offset)."""
    tag = RuleTag.objects.filter(pk=tag_id).first()
    if tag is None:
        return _not_found()
    limit = _int_param(request, 'limit', TAG_RULES_DEFAULT_LIMIT, 1, TAG_RULES_MAX_LIMIT)
    offset = _int_param(request, 'offset', 0, 0, LIST_MAX_OFFSET)
    if limit is None or offset is None:
        return _error('limit and offset must be integers.')
    rules = tag.rules.select_related('owner').order_by('pk')
    speeches = tag.speeches.filter(Q(owner=request.user) | Q(is_shared=True)).select_related('owner')
    snippets = tag.snippets.filter(Q(owner=request.user) | Q(is_shared=True)).select_related('owner')
    return JsonResponse({
        **_tag_summary(tag),
        'speeches': [
            {'speech_id': speech.pk, 'name': speech.name, 'owner': speech.owner.username}
            for speech in speeches.order_by('name')
        ],
        'snippets': [
            {'snippet_id': snippet.pk, 'name': snippet.name, 'owner': snippet.owner.username}
            for snippet in snippets.order_by('name')
        ],
        'rules_total': rules.count(),
        'offset': offset,
        'limit': limit,
        'rules': [_rule_row(rule) for rule in rules[offset:offset + limit]],
    })


RULES_DEFAULT_LIMIT = 50
RULES_MAX_LIMIT = 200
# The orderings of the rules page (rules_view).
RULE_SORTS = {
    'recent': ('-updated_at',),
    'created': ('-created_at',),
    'status': ('status', 'match_type', 'source_text'),
    'priority': ('-priority', 'status', 'match_type', 'source_text'),
}


def _rule_list_row(rule):
    """`_rule_row` plus what decides when the rule applies, and its tags (prefetched)."""
    return {
        **_rule_row(rule),
        'priority': rule.priority,
        'is_enabled': rule.is_enabled,
        'whole_log': rule.whole_log,
        'updated_at': _iso(rule.updated_at),
        'tags': [{'tag_id': tag.pk, 'name': tag.name} for tag in rule.tags.all()],
    }


def _visible_rules():
    """Every rule: the rules page shows every helper's rules to anyone logged in."""
    return ClassificationRule.objects.select_related('owner').prefetch_related('tags')


@api_token_required('api_v1_rules')
def api_rules(request):
    """Classification rules, filtered like the rules page and paged with limit/offset."""
    limit = _int_param(request, 'limit', RULES_DEFAULT_LIMIT, 1, RULES_MAX_LIMIT)
    offset = _int_param(request, 'offset', 0, 0, LIST_MAX_OFFSET)
    if limit is None or offset is None:
        return _error('limit and offset must be integers.')

    rules = _visible_rules()
    search_query = (request.GET.get('q') or '').strip()[:QUERY_MAX_CHARS]
    if search_query:
        rules = rules.filter(Q(source_text__icontains=search_query) | Q(description__icontains=search_query))
    status = (request.GET.get('status') or '').strip()
    if status:
        if status not in dict(ClassificationRule.STATUS_CHOICES):
            return _error('status must be one letter of B P C A ! G S I J ?')
        rules = rules.filter(status=status)
    match_type = (request.GET.get('match_type') or '').strip()
    if match_type:
        if match_type not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
            choices = ', '.join(code for code, _label in ClassificationRule.MATCH_TYPE_CHOICES)
            return _error(f'match_type must be one of {choices}.')
        rules = rules.filter(match_type=match_type)
    tag = (request.GET.get('tag') or '').strip()
    if tag:
        if tag.isdigit():
            rule_tag = RuleTag.objects.filter(pk=int(tag)).first()
        else:
            rule_tag = RuleTag.objects.filter(name__iexact=tag).first()
        if rule_tag is None:
            return _error(f'Unknown tag: {tag}. list_tags shows the tags.')
        rules = rules.filter(tags=rule_tag)
    owner = (request.GET.get('owner') or '').strip()
    if owner:
        rules = rules.filter(owner__username__iexact=owner)
    enabled = (request.GET.get('enabled') or '').strip()
    if enabled:
        if enabled not in ('0', '1'):
            return _error('enabled must be 1, 0 or empty.')
        rules = rules.filter(is_enabled=enabled == '1')
    sort = (request.GET.get('sort') or 'recent').strip()
    if sort not in RULE_SORTS:
        return _error(f"sort must be one of {', '.join(RULE_SORTS)}.")
    rules = rules.order_by(*RULE_SORTS[sort], 'pk')

    return JsonResponse({
        'total': rules.count(),
        'offset': offset,
        'limit': limit,
        'rules': [_rule_list_row(rule) for rule in rules[offset:offset + limit]],
    })


@api_token_required('api_v1_rule')
def api_rule(request, rule_id):
    """One classification rule with every field, including its parsed metadata."""
    rule = _visible_rules().filter(pk=rule_id).first()
    if rule is None:
        return _not_found()
    return JsonResponse(_rule_detail(rule))


def _rule_detail(rule):
    """Every field of one rule (tags prefetched), as get_rule returns it."""
    return {
        **_rule_list_row(rule),
        'color_whole_line': rule.color_whole_line,
        'source_name': rule.source_name,
        'created_at': _iso(rule.created_at),
        'parsed': {
            'clsid': rule.clsid,
            'name': rule.name,
            'filepath': rule.filepath,
            'filename': rule.filename,
            'company': rule.company,
            'arguments': rule.arguments,
            'file_not_signed': rule.file_not_signed,
            'attributes': rule.attributes,
            'is_hidden': rule.is_hidden,
        },
    }


def _write_payload(request):
    """The JSON object of a write request, or (None, error response)."""
    try:
        payload = PayloadValidator.json_payload(request)
    except PayloadTooLargeError as exc:
        return None, _error(str(exc), 413)
    except BadJsonError:
        return None, _error('Invalid JSON payload.')
    if not isinstance(payload, dict):
        return None, _error('Invalid JSON payload.')
    return payload, None


@api_token_required('api_v1_tag_create', write=True)
def api_tag_create(request):
    """Create a rule tag. Same fields and checks as the tag editor."""
    payload, error = _write_payload(request)
    if error:
        return error
    tag, message = save_tag(request.user, None, payload)
    if message:
        return _error(message)
    return JsonResponse(_tag_summary(tag), status=201)


@api_token_required('api_v1_tag_update', write=True)
def api_tag_update(request, tag_id):
    """Change a rule tag; fields left out keep their values. Tags are never deleted here."""
    tag = RuleTag.objects.filter(pk=tag_id).first()
    if tag is None:
        return _not_found()
    payload, error = _write_payload(request)
    if error:
        return error
    tag, message = save_tag(request.user, tag, payload)
    if message:
        return _error(message)
    return JsonResponse(_tag_summary(tag))


@api_token_required('api_v1_tag_apply', write=True)
def api_tag_apply(request, tag_id):
    """Put a tag on rules or take it off. A dry run unless `confirm` is true.

    Body: {mode, rule_ids?, confirm?}. mode: add_matching (rules meeting the
    tag's conditions that lack it), remove_unmatched (tagged rules no longer
    meeting them), add_rules / remove_rules (the given rule_ids).
    """
    tag = RuleTag.objects.filter(pk=tag_id).first()
    if tag is None:
        return _not_found()
    payload, error = _write_payload(request)
    if error:
        return error
    mode = payload.get('mode')
    if mode not in APPLY_MODES:
        return _error(f'Field "mode" must be one of: {", ".join(APPLY_MODES)}.')
    confirm = payload.get('confirm', False)
    if not isinstance(confirm, bool):
        return _error('Field "confirm" must be a boolean.')
    rule_ids = payload.get('rule_ids', [])
    if not isinstance(rule_ids, list) or any(isinstance(item, bool) or not isinstance(item, int) for item in rule_ids):
        return _error('Field "rule_ids" must be a list of integers.')

    current = set(tag.rules.values_list('pk', flat=True))
    conditions = TagConditions.of(tag)
    if mode == 'add_matching':
        add_ids, remove_ids = [pk for pk in matching_rule_ids(conditions) if pk not in current], []
    elif mode == 'remove_unmatched':
        add_ids, remove_ids = [], unmatched_tagged_rule_ids(tag, conditions)
    elif mode == 'add_rules':
        existing = set(ClassificationRule.objects.filter(pk__in=rule_ids).values_list('pk', flat=True))
        add_ids, remove_ids = [pk for pk in rule_ids if pk in existing and pk not in current], []
    else:
        add_ids, remove_ids = [], [pk for pk in rule_ids if pk in current]

    if not confirm:
        sample_ids = (add_ids or remove_ids)[:APPLY_SAMPLE_SIZE]
        sample = ClassificationRule.objects.filter(pk__in=sample_ids).select_related('owner').order_by('pk')
        return JsonResponse({
            'dry_run': True,
            'tag_id': tag.pk,
            'mode': mode,
            'would_add': len(add_ids),
            'would_remove': len(remove_ids),
            'sample': [_rule_row(rule) for rule in sample],
            'note': 'Nothing changed. Call again with confirm=true to apply.',
        })
    added, removed = apply_tag(tag, add_ids, remove_ids)
    return JsonResponse({'dry_run': False, 'tag_id': tag.pk, 'mode': mode, 'added': added, 'removed': removed})


def _library_fields(payload, model, item=None):
    """(fields dict, error) from a speech or snippet write body; absent fields keep their values."""
    for field in ('name', 'content', 'category'):
        if field in payload and not isinstance(payload[field], str):
            return None, f'Field "{field}" must be a string.'
    if 'is_shared' in payload and not isinstance(payload['is_shared'], bool):
        return None, 'Field "is_shared" must be a boolean.'
    tag_ids = payload.get('trigger_tag_ids')
    if tag_ids is not None and (
        not isinstance(tag_ids, list) or any(isinstance(item, bool) or not isinstance(item, int) for item in tag_ids)
    ):
        return None, 'Field "trigger_tag_ids" must be a list of integers.'
    return {
        'name': payload.get('name', item.name if item else '').strip(),
        'content': payload.get('content', item.content if item else '').strip(),
        'category': payload.get('category', item.category if item else '').strip() or model.DEFAULT_CATEGORY,
        'is_shared': payload.get('is_shared', item.is_shared if item else False),
        'tag_ids': None if tag_ids is None else parse_tag_ids(tag_ids),
    }, None


def _own_library_item_payload(request, model, item, id_key):
    item = model.objects.select_related('owner').prefetch_related('trigger_tags').get(pk=item.pk)
    return _library_item_payload(item, request.user, id_key)


def _own_speech_payload(request, speech):
    return _own_library_item_payload(request, Speech, speech, 'speech_id')


@api_token_required('api_v1_speech_create', write=True)
def api_speech_create(request):
    """Create a speech owned by the caller. Body: {name, content, category?, is_shared?, trigger_tag_ids?}."""
    payload, error = _write_payload(request)
    if error:
        return error
    fields, message = _library_fields(payload, Speech)
    if not message:
        message = _speech_validation_error(request.user, fields['name'], fields['content'], fields['category'])
    if message:
        return _error(message)
    speech = Speech.objects.create(
        owner=request.user, name=fields['name'], content=fields['content'],
        category=fields['category'], is_shared=fields['is_shared'],
    )
    speech.analyzer_users.add(request.user)
    if fields['tag_ids'] is not None:
        speech.trigger_tags.set(fields['tag_ids'])
    return JsonResponse(_own_speech_payload(request, speech), status=201)


@api_token_required('api_v1_speech_update', write=True)
def api_speech_update(request, speech_id):
    """Change one of the caller's own speeches; fields left out keep their values.

    The FRST fix speech can be edited like any other - it is the profile's fix
    message too - and keeps its flag.
    """
    speech = Speech.objects.filter(pk=speech_id, owner=request.user).first()
    if speech is None:
        return _not_found()
    payload, error = _write_payload(request)
    if error:
        return error
    fields, message = _library_fields(payload, Speech, speech)
    if not message:
        message = _speech_validation_error(
            request.user, fields['name'], fields['content'], fields['category'], exclude_pk=speech.pk,
        )
    if message:
        return _error(message)
    speech.name = fields['name']
    speech.content = fields['content']
    speech.category = fields['category']
    speech.is_shared = fields['is_shared']
    speech.save(update_fields=['name', 'content', 'category', 'is_shared', 'updated_at'])
    if fields['tag_ids'] is not None:
        speech.trigger_tags.set(fields['tag_ids'])
    return JsonResponse(_own_speech_payload(request, speech))


def _snippet_validation_error(user, fields, exclude_pk=None):
    """The snippet editor's checks, on a parsed write body."""
    form = {key: fields[key] for key in ('name', 'content', 'category')}
    return _validate_snippet_form(user, form, exclude_pk=exclude_pk)


@api_token_required('api_v1_snippet_create', write=True)
def api_snippet_create(request):
    """Create a fixlist snippet owned by the caller. Body: {name, content, category?, is_shared?, trigger_tag_ids?}."""
    payload, error = _write_payload(request)
    if error:
        return error
    fields, message = _library_fields(payload, FixlistSnippet)
    if not message:
        message = _snippet_validation_error(request.user, fields)
    if message:
        return _error(message)
    snippet = FixlistSnippet.objects.create(
        owner=request.user, name=fields['name'], content=fields['content'],
        category=fields['category'], is_shared=fields['is_shared'],
    )
    # As on the add-snippet page: a new snippet is selected for the analyzer.
    snippet.analyzer_users.add(request.user)
    if fields['tag_ids'] is not None:
        snippet.trigger_tags.set(fields['tag_ids'])
    return JsonResponse(_own_library_item_payload(request, FixlistSnippet, snippet, 'snippet_id'), status=201)


@api_token_required('api_v1_snippet_update', write=True)
def api_snippet_update(request, snippet_id):
    """Change one of the caller's own fixlist snippets; fields left out keep their values."""
    snippet = FixlistSnippet.objects.filter(pk=snippet_id, owner=request.user).first()
    if snippet is None:
        return _not_found()
    payload, error = _write_payload(request)
    if error:
        return error
    fields, message = _library_fields(payload, FixlistSnippet, snippet)
    if not message:
        message = _snippet_validation_error(request.user, fields, exclude_pk=snippet.pk)
    if message:
        return _error(message)
    snippet.name = fields['name']
    snippet.content = fields['content']
    snippet.category = fields['category']
    snippet.is_shared = fields['is_shared']
    snippet.save(update_fields=['name', 'content', 'category', 'is_shared', 'updated_at'])
    if fields['tag_ids'] is not None:
        snippet.trigger_tags.set(fields['tag_ids'])
    return JsonResponse(_own_library_item_payload(request, FixlistSnippet, snippet, 'snippet_id'))


RULE_STRING_FIELDS = ('status', 'match_type', 'source_text', 'description')
RULE_BOOL_FIELDS = ('is_enabled', 'whole_log', 'color_whole_line')


def _rule_write_fields(payload):
    """(fields, error) from a rule write body: only the fields present, type-checked.

    `priority` comes back as the rule editor's string ('' for the match type's default).
    """
    fields = {}
    for field in RULE_STRING_FIELDS:
        if field in payload:
            if not isinstance(payload[field], str):
                return None, f'Field "{field}" must be a string.'
            fields[field] = payload[field].strip()
    for field in RULE_BOOL_FIELDS:
        if field in payload:
            if not isinstance(payload[field], bool):
                return None, f'Field "{field}" must be a boolean.'
            fields[field] = payload[field]
    if 'priority' in payload:
        priority = payload['priority']
        if priority is not None and (isinstance(priority, bool) or not isinstance(priority, int)):
            return None, 'Field "priority" must be an integer or null.'
        fields['priority'] = '' if priority is None else str(priority)
    if 'tag_ids' in payload:
        tag_ids = payload['tag_ids']
        if not isinstance(tag_ids, list) or any(isinstance(item, bool) or not isinstance(item, int) for item in tag_ids):
            return None, 'Field "tag_ids" must be a list of integers.'
        fields['tag_ids'] = parse_tag_ids(tag_ids)
    return fields, None


def _regex_check(match_type, patterns):
    """(warnings, error) for regex rule patterns: an error when one cannot compile at all.

    re2-incompatible and slow patterns are saved, with a warning, as on the rules page.
    """
    if match_type != ClassificationRule.MATCH_REGEX:
        return [], None
    warnings = []
    for pattern in patterns:
        result = evaluate_regex_pattern(pattern)
        if result['stdlib_error']:
            return [], f'Invalid regex {pattern!r}: {result["stdlib_error"]}'
        if result['re2_error']:
            warnings.append(
                f'Regex {pattern!r} is not supported by the fast matcher (re2) and runs slower: '
                f'{result["re2_error"]}'
            )
        if result['is_slow']:
            warnings.append(f'Regex {pattern!r} is slow on adversarial input ({result["worst_ms"]:.0f} ms).')
    return warnings, None


@api_token_required('api_v1_rule_create', write=True)
def api_rule_create(request):
    """Create rules owned by the caller, as the add-rule page does: one per line of source_text.

    Body: {status, match_type, source_text, description?, priority?, whole_log?,
    color_whole_line?, tag_ids?}. Without tag_ids the auto-apply tags decide.
    Patterns duplicating one of the caller's rules are skipped; 409 when all are.
    """
    payload, error = _write_payload(request)
    if error:
        return error
    fields, message = _rule_write_fields(payload)
    if message:
        return _error(message)
    for field in ('status', 'match_type', 'source_text'):
        if not fields.get(field):
            return _error(f'Field "{field}" is required.')
    patterns = _patterns_for(fields['match_type'], fields['source_text'])
    warnings, message = _regex_check(fields['match_type'], patterns)
    if message:
        return _error(message)
    created, skipped, message = create_rules(
        request.user,
        status=fields['status'],
        match_type=fields['match_type'],
        source_text=fields['source_text'],
        description=fields.get('description', ''),
        raw_priority=fields.get('priority', ''),
        whole_log=fields.get('whole_log', False),
        color_whole_line=fields.get('color_whole_line', False),
        tag_ids=fields.get('tag_ids'),
        source_name=f'api:{request.user.username}',
    )
    if message:
        return _error(message)
    if not created:
        return JsonResponse({
            'error': 'No rules created: every pattern duplicates one of your rules.',
            'skipped': skipped,
        }, status=409)
    rules = _visible_rules().filter(pk__in=[rule.pk for rule in created]).order_by('pk')
    return JsonResponse({
        'created': [_rule_detail(rule) for rule in rules],
        'skipped': skipped,
        'warnings': warnings,
    }, status=201)


@api_token_required('api_v1_rule_update', write=True)
def api_rule_update(request, rule_id):
    """Change a rule, as the rule editor does; fields left out keep their values.

    Body: any of {status, match_type, source_text, description, is_enabled,
    whole_log, color_whole_line, priority, tag_ids}. tag_ids replaces the
    rule's tags. A superuser may change any helper's rule; it keeps its owner,
    and duplicates are checked within that owner's rules.
    """
    rules = ClassificationRule.objects.filter(pk=rule_id)
    # Write tokens are superuser-only already; the check stays here in case that ever changes.
    if not request.user.is_superuser:
        rules = rules.filter(owner=request.user)
    rule = rules.select_related('owner').first()
    if rule is None:
        return _not_found()
    payload, error = _write_payload(request)
    if error:
        return error
    fields, message = _rule_write_fields(payload)
    if message:
        return _error(message)
    form = {**_rule_form_from_rule(rule), 'tag_ids': None, **fields}
    warnings, message = _regex_check(form['match_type'], [form['source_text']])
    if message:
        return _error(message)
    message = _apply_rule_edit(rule, form, request.user)
    if message:
        return _error(message)
    return JsonResponse({**_rule_detail(_visible_rules().get(pk=rule.pk)), 'warnings': warnings})


# ---------------------------------------------------------------------------
# Rule questions: what a candidate rule would do across the corpus (test_rule),
# and which rules decide given lines today (match_rules). Read-only: nothing
# is saved. They take a POST with a JSON body because their input (log lines,
# multi-line rule text) does not fit a URL.
# ---------------------------------------------------------------------------

RULE_TEST_DEFAULT_TYPES = ('FRST', 'Addition', 'FRST&Addition')
RULE_TEST_DEFAULT_MAX_LOGS = 500
RULE_TEST_MAX_LOGS = 3000
RULE_TEST_DEFAULT_SAMPLE = 50
RULE_TEST_MAX_SAMPLE = 200
RULE_TEST_TIME_BUDGET_S = 15.0
RULE_COMPARE_TIME_BUDGET_S = 10.0
RULE_COMPARE_EXTRA_UNITS = 10


def _rule_test_corpus(scope_pks, hidden, literals):
    """``(upload_id, content)`` of the logs in `scope_pks`, newest first, minus `hidden`.

    `literals` (or None) prefilter in the database: a log must contain one of
    them, case-insensitively - a superset of what a substring or exact rule
    can match, so nothing the rule would hit is skipped.
    """
    logs = UploadedLog.objects.filter(pk__in=scope_pks)
    if literals:
        contains_one = Q()
        for literal in literals:
            contains_one |= Q(content__icontains=literal)
        logs = logs.filter(contains_one)
    rows = logs.order_by('-created_at', '-pk').values_list('pk', 'upload_id', 'content').iterator(chunk_size=10)
    for pk, upload_id, content in rows:
        if pk not in hidden:
            yield upload_id, content


def _untrusted_samples(entries):
    return [
        {'untrusted_line': entry['line'], 'log_count': entry['log_count'], 'logs': entry['logs']}
        for entry in entries
    ]


def _rule_test_sample_row(result, entry):
    """One matched line of a dry run: where it occurs, its verdict today and with the new rule."""
    existing = result.get('existing_status', '?')
    row = {
        'untrusted_line': result['line'],
        'log_count': entry['log_count'],
        'logs': entry['logs'],
        'current_status': existing,
        'current_rule_ids': [
            match['id'] for match in result.get('existing_matches', []) if match['status'] == existing
        ],
        'current_priority': result.get('existing_priority'),
        'new_status': result.get('combined_status', '?'),
        'outcome': line_outcome(result),
    }
    if result.get('parsed'):
        row['parsed'] = result['parsed']
    if result.get('script_error'):
        row['script_error'] = result['script_error']
    return row


@api_token_required('api_v1_rule_test', cost=10, methods=('POST',))
def api_rule_test(request):
    """Dry run of a candidate rule against stored logs; nothing is saved.

    Body: the rule (source_text, match_type, status, priority?, whole_log?) as
    on the add-rule page, plus the scope (type / exclude_type, created_after /
    created_before, dedupe; FRST, Addition and FRST&Addition logs by default),
    max_logs (newest logs in scope to scan), sample_lines and compare_rule_id.

    Returns how many logs and lines the rule matches (counted past the sample),
    a sample of the distinct lines with their verdict today and with the rule,
    and a summary: outcome counts, verdict changes, and the existing rules
    deciding those lines with how many of them each would become redundant
    on. compare_rule_id also scans with that saved rule and counts the lines
    only one of the two matches; it is left out of the verdicts, as if the
    new rule replaced it. Verdicts use the caller's rule set.
    """
    payload, rule, error_response = _read_rule_test_payload(request)
    if error_response:
        return error_response
    try:
        max_logs = int_param(payload, 'max_logs', RULE_TEST_DEFAULT_MAX_LOGS, 1, RULE_TEST_MAX_LOGS)
        sample_lines = int_param(payload, 'sample_lines', RULE_TEST_DEFAULT_SAMPLE, 1, RULE_TEST_MAX_SAMPLE)
        dedupe = flag_param(payload, 'dedupe')
        compare_rule_id = optional_int_param(payload, 'compare_rule_id')
        scoped = apply_upload_scope(_live_upload_rows(), payload, default_types=RULE_TEST_DEFAULT_TYPES)
    except ParamError as exc:
        return _error(str(exc))

    patterns = rule['patterns']
    status = rule['status']
    match_type = rule['match_type']
    if match_type == ClassificationRule.MATCH_REGEX:
        for pattern in patterns:
            evaluation = evaluate_regex_pattern(pattern)
            if not evaluation['stdlib_ok']:
                return _error(f"Invalid regex {pattern!r}: {evaluation['stdlib_error']}")
            if evaluation['is_slow']:
                return _error(
                    f'This regex is too slow to run against stored logs '
                    f"({evaluation['worst_ms']:.0f} ms on a {evaluation['worst_input']} input)."
                )

    compare_rule = None
    if compare_rule_id is not None:
        compare_rule = ClassificationRule.objects.filter(pk=compare_rule_id).first()
        if compare_rule is None:
            return _error(f'compare_rule_id: no rule {compare_rule_id}.')
        if rule['whole_log'] or compare_rule.whole_log:
            return _error('compare_rule_id compares line rules; whole-log alert rules cannot be compared.')
        if compare_rule.match_type == ClassificationRule.MATCH_SCRIPT and not is_moderator(request.user):
            return _error('Script rules can only be tested by moderators.', 403)
        if not charge_api_units(request, RULE_COMPARE_EXTRA_UNITS):
            return rate_limited_response(60)

    hidden = non_canonical_pks(scoped) if dedupe else set()
    scope_pks = list(scoped.order_by('-created_at', '-pk').values_list('pk', flat=True)[:max_logs])
    logs_in_scope = len([pk for pk in scope_pks if pk not in hidden])
    rule_set_key = resolve_user_rule_set_key(request.user)
    deadline = time.monotonic() + RULE_TEST_TIME_BUDGET_S

    response = {
        'rule': {
            'match_type': match_type,
            'status': status,
            'patterns': len(patterns),
            'priority': (
                rule['priority'] if rule['priority'] is not None
                else ClassificationRule.default_priority_for(match_type)
            ),
            'whole_log': rule['whole_log'],
        },
        'rule_set': 'shared' if rule_set_key == SHARED_RULE_SET_KEY else 'private',
        'logs_in_scope': logs_in_scope,
        'max_logs': max_logs,
    }
    if dedupe:
        response['duplicates_hidden'] = len(hidden)

    try:
        if rule['whole_log']:
            scan = scan_logs_for_wholelog_matches(
                patterns, match_type, _rule_test_corpus(scope_pks, hidden, None), deadline=deadline,
            )
            response.update(scan)
            response['complete'] = not scan['timed_out']
            return JsonResponse(response)

        literals = literal_prefilter(patterns, match_type)
        scan = scan_logs_for_rule_matches(
            patterns, status, match_type, _rule_test_corpus(scope_pks, hidden, literals),
            max_lines=sample_lines, deadline=deadline, count_all=True,
        )
        matches = scan.pop('matches')
        built = build_rule_test_results(
            patterns=patterns,
            status=status,
            match_type=match_type,
            lines=[entry['line'] for entry in matches],
            priority=rule['priority'],
            exclude_rule_id=compare_rule_id,
            rule_set_key=rule_set_key,
            buckets=_get_cached_rule_buckets(rule_set_key),
        )
        results = built['results']
        response.update({
            'prefiltered': bool(literals),
            'logs_scanned': scan['logs_scanned'],
            'logs_matched': scan['logs_matched'],
            'line_hits': scan['line_hits'],
            'distinct_lines': scan['distinct_lines'],
            'sample_truncated': scan['truncated'],
            'timed_out': scan['timed_out'],
            'complete': not scan['timed_out'],
            'summary': summarize_rule_test(results, status),
            'untrusted_sample': [_rule_test_sample_row(result, entry) for result, entry in zip(results, matches)],
        })

        if compare_rule is not None:
            old_patterns = _patterns_for(compare_rule.match_type, compare_rule.source_text)
            old_literals = literal_prefilter(old_patterns, compare_rule.match_type)
            both_literals = literals + old_literals if literals and old_literals else None
            compared = compare_rule_scans(
                {'patterns': patterns, 'status': status, 'match_type': match_type},
                {'patterns': old_patterns, 'status': compare_rule.status, 'match_type': compare_rule.match_type},
                _rule_test_corpus(scope_pks, hidden, both_literals),
                deadline=time.monotonic() + RULE_COMPARE_TIME_BUDGET_S,
                sample_lines=sample_lines,
            )
            response['compare'] = {
                'rule': _rule_row(compare_rule),
                'both': compared['both'],
                'only_new': compared['only_new'],
                'only_old': compared['only_old'],
                'untrusted_only_new_sample': _untrusted_samples(compared['only_new_sample']),
                'untrusted_only_old_sample': _untrusted_samples(compared['only_old_sample']),
                'logs_scanned': compared['logs_scanned'],
                'complete': not compared['timed_out'],
            }
    except ValueError as exc:
        return _error(str(exc))
    return JsonResponse(response)


MATCH_LINES_MAX = 200
MATCH_LINE_MAX_CHARS = 4000
MATCH_LINES_PER_UNIT = 50


def _match_row(match):
    return {
        'rule_id': match['id'],
        'status': match['status'],
        'match_type': match['match_type'],
        'priority': match['priority'],
        'matcher': match['matcher'],
        'owner': match.get('owner_username', ''),
        'source_text': match['source_text'],
        'description': match['description'],
        'tags': [tag['name'] for tag in match.get('tags', [])],
    }


def _parsed_entry_payload(line):
    entry = ex.get_frst_entry(line)
    if entry is None:
        return None
    return {
        'entry_type': entry.entry_type,
        **{key: getattr(entry, key) for key in COMPONENT_KEYS if key != 'entry_type' and getattr(entry, key, '')},
    }


@api_token_required('api_v1_rule_match', methods=('POST',))
def api_rule_match(request):
    """Which rules fire on each given log line, under the caller's rule set.

    Body: {lines: [...], include_shadowed?}. For each line: its verdict, the
    winning priority tier (`winning`, each rule with `decides` when its status
    is the verdict) and the lower tiers it shadows (`shadowed`), plus the
    line's parsed FRST entry. Whole-log alert rules and disabled rules never
    match a line, so they are not listed.
    """
    payload, error = _write_payload(request)
    if error:
        return error
    lines = payload.get('lines')
    if (
        not isinstance(lines, list) or not lines or len(lines) > MATCH_LINES_MAX
        or any(not isinstance(line, str) or len(line) > MATCH_LINE_MAX_CHARS for line in lines)
    ):
        return _error(
            f'Field "lines" must be a list of 1 to {MATCH_LINES_MAX} strings '
            f'of at most {MATCH_LINE_MAX_CHARS} characters.'
        )
    try:
        include_shadowed = flag_param(payload, 'include_shadowed', default=True)
    except ParamError as exc:
        return _error(str(exc))
    extra_units = (len(lines) - 1) // MATCH_LINES_PER_UNIT
    if extra_units and not charge_api_units(request, extra_units):
        return rate_limited_response(60)

    rule_set_key = resolve_user_rule_set_key(request.user)
    buckets = _get_cached_rule_buckets(rule_set_key)
    results = []
    for line in lines:
        inspection = inspect_line_matches(line, buckets=buckets)
        attach_tags_to_matches(inspection['matches'], inspection.get('shadowed_matches'))
        verdict = inspection['dominant_status']
        winning = []
        for match in inspection['matches']:
            row = _match_row(match)
            row['decides'] = match['status'] == verdict
            winning.append(row)
        result = {
            'untrusted_line': inspection['line'],
            'status': verdict,
            'status_codes': inspection['status_codes'],
            'effective_priority': inspection.get('effective_priority'),
            'effective_matcher': inspection.get('effective_matcher'),
            'winning': winning,
            'entry': _parsed_entry_payload(inspection['line']) if inspection['line'] else None,
        }
        if include_shadowed:
            result['shadowed'] = [_match_row(match) for match in inspection.get('shadowed_matches', [])]
        results.append(result)

    return JsonResponse({
        'rule_set': 'shared' if rule_set_key == SHARED_RULE_SET_KEY else 'private',
        'status_legend': STATUS_LABELS,
        'results': results,
    })
