"""
Full-text search across uploaded log contents.

Reached from the profile menu rather than the main nav: looking up an indicator
across every stored log is an occasional task, not part of the daily uploads
workflow. Searches all non-trashed logs regardless of channel, mirroring the
existing detail/diff/download views which are also unscoped.
"""

import hashlib
import re

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods
from urllib.parse import urlencode

from ..analyzer import _re2, evaluate_regex_pattern
from ..models import UploadedLog
from .guest import deny_guests
from .utils import build_uploaded_logs_zip

# Regex mode scans log bodies in Python, so the result set is capped to keep a
# single request bounded. Substring mode is capped the same way for consistent
# pagination and an honest "showing the first N" notice.
SEARCH_MATCH_LIMIT = 500
ZIP_MATCH_LIMIT = 100
RESULTS_PER_PAGE = 10
# Paging re-runs the search, which in regex mode means rescanning every log body.
# The matched ids are cached briefly so page 2 is a lookup rather than a rescan;
# the trade-off is that logs uploaded within the window are missed by a repeated
# identical search.
SEARCH_CACHE_TIMEOUT = 300
PREVIEW_MAX_CHARS = 300
PREVIEW_LEAD_CHARS = 60
PREVIEW_HIT_MAX_CHARS = 200


def _build_matcher(query, use_regex, case_sensitive=False):
    """Return ``(matcher, error)`` where matcher(line) -> (start, end) or None.

    Matching is case-insensitive unless `case_sensitive` is set. Regex patterns are
    validated with the analyzer's shared evaluator so that only linear-time
    (re2-compatible) patterns reach the scan; constructs re2 rejects — lookaround,
    backreferences — would fall back to stdlib re and expose the scan to
    catastrophic backtracking.
    """
    if not use_regex:
        if case_sensitive:
            def match_substring(line):
                index = line.find(query)
                return (index, index + len(query)) if index >= 0 else None
        else:
            needle = query.lower()

            def match_substring(line):
                index = line.lower().find(needle)
                return (index, index + len(needle)) if index >= 0 else None

        return match_substring, None

    evaluation = evaluate_regex_pattern(query)
    if not evaluation['stdlib_ok']:
        return None, f"invalid regex: {evaluation['stdlib_error']}"

    if _re2 is not None:
        if not evaluation['re2_ok']:
            return None, (
                'this regex uses constructs the fast engine does not support '
                '(lookahead, lookbehind or backreferences). rewrite it without them, '
                f"or use substring search. details: {evaluation['re2_error']}"
            )
        compiled = _re2.compile(query if case_sensitive else f'(?i){query}')
    else:
        # No re2 binding: stdlib re is the only option, so refuse patterns that
        # benchmark slow on adversarial input rather than risk stalling a worker.
        if evaluation['is_slow']:
            return None, (
                'this regex is too slow to run against every log '
                f"({evaluation['worst_ms']:.0f} ms on a {evaluation['worst_input']} input). "
                'simplify it or use substring search.'
            )
        compiled = re.compile(query, 0 if case_sensitive else re.IGNORECASE)

    def match_regex(line):
        found = compiled.search(line)
        return (found.start(), found.end()) if found else None

    return match_regex, None


def _clip_preview(line, start, end):
    """Split a matched line into ``(before, hit, after)`` clipped for display.

    Returned separately so the template can escape each piece and highlight only
    the hit — user content is never marked safe.
    """
    hit = line[start:end]
    if len(hit) > PREVIEW_HIT_MAX_CHARS:
        hit = hit[:PREVIEW_HIT_MAX_CHARS] + '…'

    before = line[:start]
    after = line[end:]

    if len(before) + len(hit) + len(after) > PREVIEW_MAX_CHARS:
        if len(before) > PREVIEW_LEAD_CHARS:
            before = '…' + before[-PREVIEW_LEAD_CHARS:]
        remaining = max(0, PREVIEW_MAX_CHARS - len(before) - len(hit))
        if len(after) > remaining:
            after = after[:remaining] + '…'

    return before, hit, after


def _first_hit(content, matcher):
    """Return the first matching line as ``(line_number, before, hit, after)``."""
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.rstrip('\r')
        span = matcher(line)
        if span is None:
            continue
        before, hit, after = _clip_preview(line, span[0], span[1])
        return line_number, before, hit, after
    return None


def _base_queryset():
    return UploadedLog.objects.filter(deleted_at__isnull=True)


def _search_cache_key(query, use_regex, case_sensitive, log_type, limit):
    """Cache key for one search. Hashed because queries are arbitrary user text."""
    digest = hashlib.md5(
        f'{int(use_regex)}|{int(case_sensitive)}|{limit}|{log_type}|{query}'.encode('utf-8')
    ).hexdigest()
    return f'log-search-ids:{digest}'


def search_matching_log_ids(query, use_regex, limit, case_sensitive=False, log_type=''):
    """Find logs whose content matches `query`.

    Returns ``(log_ids, truncated, error, matcher)``. `log_ids` preserves the
    model's newest-first ordering and holds at most `limit` entries; `truncated`
    is True when more logs matched than the limit allows. The compiled `matcher`
    is handed back so callers can build previews without re-validating the
    pattern (regex validation benchmarks the pattern and is not free).

    An optional `log_type` narrows the search to one kind of log, which also
    shrinks the regex scan.
    """
    if not query:
        return [], False, None, None

    matcher, error = _build_matcher(query, use_regex, case_sensitive)
    if error:
        return [], False, error, None

    cache_key = _search_cache_key(query, use_regex, case_sensitive, log_type, limit)
    cached = cache.get(cache_key)
    if cached is not None:
        cached_ids, cached_truncated = cached
        return cached_ids, cached_truncated, None, matcher

    scoped = _base_queryset()
    if log_type:
        scoped = scoped.filter(log_type=log_type)

    if not use_regex and not case_sensitive:
        # Case-insensitive substring matching pushes down to the database; fetch
        # one extra id so a truncated result set is distinguishable from an
        # exactly-full one.
        log_ids = list(
            scoped.filter(content__icontains=query).values_list('id', flat=True)[: limit + 1]
        )
    else:
        # Everything else is verified in Python. Regex cannot be pushed down
        # safely (SQLite and PostgreSQL disagree on syntax, and SQLite would run
        # the pattern through stdlib re), and `contains` is not case-sensitive on
        # SQLite, so neither can be trusted to the database. Substring searches
        # still narrow the scan with a case-insensitive prefilter — every
        # case-sensitive hit is also a case-insensitive one. iterator() keeps
        # memory bounded either way.
        candidates = scoped
        if not use_regex:
            candidates = candidates.filter(content__icontains=query)

        log_ids = []
        rows = candidates.values_list('id', 'content').iterator(chunk_size=25)
        for log_id, content in rows:
            if _first_hit(content, matcher) is not None:
                log_ids.append(log_id)
                if len(log_ids) > limit:
                    break

    truncated = len(log_ids) > limit
    log_ids = log_ids[:limit]
    cache.set(cache_key, (log_ids, truncated), SEARCH_CACHE_TIMEOUT)
    return log_ids, truncated, None, matcher


def _logs_in_id_order(log_ids, *, with_content=False):
    """Fetch logs for `log_ids`, preserving the given order.

    Re-applies the not-trashed filter so ids from a cached result set can never
    resurrect a log that has been deleted since the search ran.
    """
    if not log_ids:
        return []
    logs = _base_queryset().filter(id__in=log_ids).select_related(
        'recipient_user', 'recipient_user__fenris_profile'
    )
    if not with_content:
        logs = logs.defer('content')
    by_id = {log.id: log for log in logs}
    return [by_id[log_id] for log_id in log_ids if log_id in by_id]


def _read_search_params(request):
    """Read the search term, its mode toggles, and the log type filter."""
    log_type = request.GET.get('type', '').strip()
    if log_type not in available_log_types():
        log_type = ''
    return (
        request.GET.get('q', '').strip(),
        request.GET.get('regex') == '1',
        request.GET.get('case') == '1',
        log_type,
    )


def _search_query_params(query, use_regex, case_sensitive, log_type):
    """Build the query-string params that carry a search across links."""
    params = {'q': query}
    if use_regex:
        params['regex'] = '1'
    if case_sensitive:
        params['case'] = '1'
    if log_type:
        params['type'] = log_type
    return params


def available_log_types():
    """Log types that actually occur among non-trashed logs, for the filter dropdown."""
    return list(
        _base_queryset()
        .values_list('log_type', flat=True)
        .distinct()
        .order_by('log_type')
    )


@deny_guests
@login_required
@require_http_methods(["GET"])
def log_search_view(request):
    """Search the contents of every uploaded log and preview the first hit."""
    query, use_regex, case_sensitive, log_type = _read_search_params(request)

    log_ids, truncated, error, matcher = search_matching_log_ids(
        query, use_regex, SEARCH_MATCH_LIMIT, case_sensitive, log_type
    )

    page_obj = Paginator(log_ids, RESULTS_PER_PAGE).get_page(request.GET.get('page'))
    results = []
    if page_obj.object_list and matcher:
        page_logs = _logs_in_id_order(list(page_obj.object_list), with_content=True)
        for uploaded_log in page_logs:
            hit = _first_hit(uploaded_log.content, matcher)
            results.append({
                'log': uploaded_log,
                'line_number': hit[0] if hit else None,
                'before': hit[1] if hit else '',
                'hit': hit[2] if hit else '',
                'after': hit[3] if hit else '',
            })

    query_params = _search_query_params(query, use_regex, case_sensitive, log_type)

    return render(request, 'log_search.html', {
        'search_query': query,
        'use_regex': use_regex,
        'case_sensitive': case_sensitive,
        'log_type_filter': log_type,
        'log_types': available_log_types(),
        'search_error': error,
        'results': results,
        'match_count': len(log_ids),
        'truncated': truncated,
        'over_zip_limit': len(log_ids) > ZIP_MATCH_LIMIT,
        'zip_limit': ZIP_MATCH_LIMIT,
        'search_limit': SEARCH_MATCH_LIMIT,
        'page_obj': page_obj,
        'pagination_query': urlencode(query_params),
        'download_query': urlencode(query_params),
    })


@deny_guests
@login_required
@require_http_methods(["GET"])
def log_search_download_view(request):
    """Download matching logs as a single zip archive.

    Without a selection this bundles the whole result set (capped); with
    `selected_upload_ids` it bundles exactly those logs, so the user can cherry-pick
    across result pages.
    """
    query, use_regex, case_sensitive, log_type = _read_search_params(request)
    selected_upload_ids = [
        value.strip() for value in request.GET.getlist('selected_upload_ids') if value.strip()
    ]

    error = None
    if selected_upload_ids:
        logs = list(
            _base_queryset()
            .filter(upload_id__in=selected_upload_ids[:ZIP_MATCH_LIMIT])
            .order_by('-created_at')
        )
    else:
        log_ids, _, error, _matcher = search_matching_log_ids(
            query, use_regex, ZIP_MATCH_LIMIT, case_sensitive, log_type
        )
        logs = _logs_in_id_order(log_ids, with_content=True) if log_ids else []

    if error or not logs:
        if error:
            fallback_message = error
        elif selected_upload_ids:
            fallback_message = 'None of the selected logs are available for download.'
        else:
            fallback_message = 'No logs matched this search.'
        messages.error(request, fallback_message)
        params = _search_query_params(query, use_regex, case_sensitive, log_type)
        return redirect(f"{reverse('log_search')}?{urlencode(params)}")

    response = HttpResponse(build_uploaded_logs_zip(logs), content_type='application/zip')
    response['Content-Disposition'] = 'attachment; filename="fenris_search_logs.zip"'
    return response
