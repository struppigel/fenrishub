"""
Line-level content search for the token API (/api/v1/search/).

The browser search (views/log_search.py) finds logs and previews their first
matching line. An LLM client looking for rule candidates needs more: every
matching line of a log with the verdict it has today, only the lines that are
not yet a given status, exact case like a rule regex, parsed-entry fields
rather than path regexes, and honest totals. This module does that over the
same corpus (non-trashed logs), reusing the browser search's matcher, so a
regex that works here is validated exactly like one that works there.

A search runs in two passes. The first finds which logs match, newest first,
and is cached for a few minutes so paging does not rescan; it stops once it
has enough logs for the requested page, unless totals were asked for. The
second reads only the logs of the page and collects their hits.

Verdicts come from each log's cached analysis under the caller's rule set,
else the shared one (the analysis a tag search reads); a log never analyzed
has none, and is counted rather than analyzed here.
"""

import hashlib
import json
import time

from django.core.cache import cache

from . import frst_extractors as ex
from .models import UploadedLog
from .tagging import attach_rule_tags
from .upload_utils import get_fresh_cached_analysis
from .rule_sets import SHARED_RULE_SET_KEY

SEARCH_TIME_BUDGET_S = 10.0
# Matching logs remembered per search; offsets past it are not served.
SEARCH_MAX_MATCHES = 2000
SEARCH_CACHE_TIMEOUT = 300
LINES_PER_LOG_MAX = 50

COMPONENT_KEYS = ('entry_type', 'filename', 'filepath', 'company', 'name', 'clsid', 'arguments')
COMPONENT_VALUE_MAX_CHARS = 500


def non_blank_line_numbers(content):
    """1-based numbers of the lines the analyzer looks at (it skips blank ones)."""
    return [
        number
        for number, raw_line in enumerate((content or '').splitlines(), start=1)
        if raw_line.strip()
    ]


def _basename(path):
    return path.replace('/', '\\').rstrip('\\').rsplit('\\', 1)[-1]


class ComponentFilter:
    """Lines whose parsed FRST entry has the given field values (case-insensitive).

    `filepath` (and a path-like `name`) are compared normalized the way rules
    compare them, so C:\\Users\\bob\\... equals the rule's C:\\Users\\username\\...
    """

    def __init__(self, components):
        self.wanted = {}
        for key, value in components.items():
            value = value.strip()
            if not value:
                continue
            if key == 'filepath':
                self.wanted[key] = ex.normalize_path(value).lower()
            elif key == 'entry_type':
                self.wanted[key] = value
            else:
                self.wanted[key] = value.lower()
        # Text every matching line contains, for cheap prefilters.
        self.literals = []
        for key, value in components.items():
            value = value.strip()
            if not value or key == 'entry_type':
                continue
            literal = _basename(value) if key in ('filepath', 'name') else value
            if literal:
                self.literals.append(literal.lower())

    def __bool__(self):
        return bool(self.wanted)

    def matches(self, line):
        lowered = line.lower()
        if any(literal not in lowered for literal in self.literals):
            return False
        entry = ex.get_frst_entry(line.strip())
        if entry is None:
            return False
        for key, value in self.wanted.items():
            actual = getattr(entry, key, '') or ''
            if key == 'entry_type':
                if actual != value:
                    return False
            elif key == 'filepath':
                if ex.normalize_path(actual).lower() != value:
                    return False
            elif key == 'name':
                if actual.lower() not in (value, ex.normalize_path(value).lower()):
                    return False
            elif actual.lower() != value:
                return False
        return True


def parse_components(raw):
    """``(components dict, error)`` from the `components` parameter (a JSON object or its text)."""
    if raw in (None, '', {}):
        return {}, None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return None, 'components must be a JSON object, e.g. {"filename": "evil.exe"}.'
    if not isinstance(raw, dict):
        return None, 'components must be a JSON object, e.g. {"filename": "evil.exe"}.'
    unknown = sorted(set(raw) - set(COMPONENT_KEYS))
    if unknown:
        return None, f"Unknown component(s): {', '.join(unknown)}. Known: {', '.join(COMPONENT_KEYS)}."
    components = {}
    for key, value in raw.items():
        if not isinstance(value, str) or len(value) > COMPONENT_VALUE_MAX_CHARS:
            return None, f'Component "{key}" must be a string of at most {COMPONENT_VALUE_MAX_CHARS} characters.'
        if value.strip():
            components[key] = value
    return components, None


class LineSearch:
    """One search: what a line must match, which verdicts to keep, and over which logs."""

    def __init__(
        self, *, query='', use_regex=False, case_sensitive=False, components=None,
        statuses=(), tag_ids=(), rule_set_key=SHARED_RULE_SET_KEY,
    ):
        self.query = query
        self.use_regex = use_regex
        self.case_sensitive = case_sensitive
        self.components = ComponentFilter(components or {})
        self.statuses = set(statuses)
        self.tag_ids = list(tag_ids)
        self.rule_set_key = rule_set_key
        self.matcher = None
        self.error = None
        if query:
            # Imported here: fixlist.views imports the API views, which import this module.
            from .views.log_search import _build_matcher

            self.matcher, self.error = _build_matcher(query, use_regex, case_sensitive)

    @property
    def matches_text(self):
        """Whether lines are chosen by their text (query or components) rather than by tags alone."""
        return bool(self.matcher) or bool(self.components)

    def content_literals(self):
        """Text every matching log contains, for a case-insensitive database prefilter."""
        literals = list(self.components.literals)
        if self.query and not self.use_regex:
            literals.append(self.query)
        return literals

    def cache_key(self, scope_part, dedupe):
        components = json.dumps(self.components.wanted, sort_keys=True)
        raw = '|'.join([
            '2', self.query, str(int(self.use_regex)), str(int(self.case_sensitive)), components,
            ','.join(sorted(self.statuses)), ','.join(str(t) for t in sorted(self.tag_ids)),
            self.rule_set_key, scope_part, str(int(dedupe)),
        ])
        return 'api-line-search:' + hashlib.md5(raw.encode('utf-8')).hexdigest()

    # -- per log ---------------------------------------------------------------

    def _analysis(self, upload_pk, content_hash):
        """``(payload, 'private'|'shared')`` of the cached analysis a search reads, or ``(None, None)``."""
        upload = UploadedLog(pk=upload_pk, content_hash=content_hash)
        keys = [self.rule_set_key]
        if self.rule_set_key != SHARED_RULE_SET_KEY:
            keys.append(SHARED_RULE_SET_KEY)
        for key in keys:
            payload = get_fresh_cached_analysis(upload, key)
            if payload is not None:
                return payload, 'shared' if key == SHARED_RULE_SET_KEY else 'private'
        return None, None

    def evaluate(self, upload_pk, content, content_hash, *, max_hits, with_verdicts):
        """The hits of one log, or None when it has none.

        Returns ``{'hit_count', 'hits', 'verdicts_from', 'unanalyzed'}``: every
        line that matches (and has a wanted verdict), the first `max_hits` of
        them as ``(line_number, text, span, entry)``. `entry` is the line's
        analysis entry when verdicts were read. A log whose verdicts were
        needed but never computed comes back with ``unanalyzed`` set and no hits.
        """
        lines = (content or '').splitlines()
        text_hits = []
        if self.matches_text:
            for number, raw_line in enumerate(lines, start=1):
                line = raw_line.rstrip('\r')
                span = (0, 0)
                if self.matcher:
                    span = self.matcher(line)
                    if span is None:
                        continue
                if self.components and not self.components.matches(line):
                    continue
                text_hits.append((number, line, span))
            if not text_hits:
                return None

        tags_pick_lines = not self.matches_text and bool(self.tag_ids)
        need_analysis = with_verdicts or bool(self.statuses) or tags_pick_lines
        entries = {}
        verdicts_from = None
        if need_analysis:
            payload, verdicts_from = self._analysis(upload_pk, content_hash)
            if payload is not None:
                if with_verdicts or tags_pick_lines:
                    attach_rule_tags(payload)
                numbers = non_blank_line_numbers(content)
                payload_lines = payload.get('lines') or []
                if len(numbers) == len(payload_lines):
                    entries = dict(zip(numbers, payload_lines))
                    tag_names = {tag['id']: tag['name'] for tag in payload.get('rule_tags', [])}
                    for entry in payload_lines:
                        entry['_tag_names'] = [
                            tag_names[tag_id] for tag_id in entry.get('tag_ids', []) if tag_id in tag_names
                        ]
                else:
                    verdicts_from = None
            if verdicts_from is None and self.statuses:
                return {'hit_count': 0, 'hits': [], 'verdicts_from': None, 'unanalyzed': True}

        if tags_pick_lines:
            wanted = set(self.tag_ids)
            text_hits = [
                (number, lines[number - 1].rstrip('\r'), (0, 0))
                for number, entry in sorted(entries.items())
                if wanted.intersection(entry.get('tag_ids', []))
            ]
        if self.statuses:
            text_hits = [
                hit for hit in text_hits
                if (entries.get(hit[0]) or {}).get('dominant_status') in self.statuses
            ]
            if not text_hits:
                return None

        return {
            'hit_count': len(text_hits),
            'hits': [(number, line, span, entries.get(number)) for number, line, span in text_hits[:max_hits]],
            'verdicts_from': verdicts_from,
            'unanalyzed': need_analysis and verdicts_from is None,
        }


def serialize_hit(hit, with_verdicts):
    from .views.log_search import _clip_preview

    number, line, span, entry = hit
    before, matched, after = _clip_preview(line, span[0], span[1])
    payload = {'line_number': number, 'untrusted_text': before + matched + after}
    if with_verdicts:
        payload.update({
            'status': entry.get('dominant_status', '?') if entry else None,
            'rule_ids': entry.get('rule_ids', []) if entry else [],
            'tags': entry.get('_tag_names', []) if entry else [],
        })
    return payload


def find_matching_logs(search, scoped, *, needed, count_all, hidden_pks=()):
    """First pass: the matching logs of `scoped`, newest first.

    Returns ``{'pks', 'exhausted', 'timed_out', 'unanalyzed_count', 'totals'}``.
    `pks` holds at most SEARCH_MAX_MATCHES + 1 logs; the scan stops once it
    has `needed` of them, unless `count_all` asks it to count every matching
    log and line (`totals`) within the time budget. `hidden_pks` are skipped
    (duplicates when deduplicating). `exhausted` says the scan reached the end.
    """
    deadline = time.monotonic() + SEARCH_TIME_BUDGET_S
    hidden_pks = set(hidden_pks)
    ordered = scoped.order_by('-created_at', '-pk')
    for literal in search.content_literals():
        ordered = ordered.filter(content__icontains=literal)

    pks = []
    unanalyzed_count = 0
    timed_out = False
    exhausted = True
    total_logs = 0
    total_lines = 0
    usernames = set()

    # The database decides alone when tags alone pick the logs (applied to
    # `scoped` already), or when its case-insensitive substring prefilter is
    # the whole test - as in the browser search. Anything more reads the lines.
    plain_substring = (
        bool(search.query) and not search.use_regex and not search.case_sensitive
        and not search.components
    )
    needs_lines = (search.matches_text and not plain_substring) or search.statuses or count_all
    if not needs_lines:
        for pk, username in ordered.values_list('pk', 'forum_username').iterator(chunk_size=500):
            if pk in hidden_pks:
                continue
            pks.append(pk)
            if len(pks) >= max(needed, 1) or len(pks) > SEARCH_MAX_MATCHES:
                exhausted = False
                break
        return {
            'pks': pks, 'exhausted': exhausted, 'timed_out': False,
            'unanalyzed_count': 0, 'totals': None,
        }

    rows = ordered.values_list('pk', 'content', 'content_hash', 'forum_username').iterator(chunk_size=25)
    for pk, content, content_hash, username in rows:
        if time.monotonic() > deadline:
            timed_out = True
            exhausted = False
            break
        if pk in hidden_pks:
            continue
        result = search.evaluate(pk, content, content_hash, max_hits=0, with_verdicts=False)
        if result is None:
            continue
        if result['unanalyzed'] and search.statuses:
            unanalyzed_count += 1
            continue
        total_logs += 1
        total_lines += result['hit_count']
        usernames.add((username or '').lower())
        if len(pks) <= SEARCH_MAX_MATCHES:
            pks.append(pk)
        if not count_all and len(pks) >= needed:
            exhausted = False
            break

    totals = None
    if count_all:
        totals = {
            'logs': total_logs,
            'lines': total_lines,
            'distinct_usernames': len(usernames),
            'complete': not timed_out,
        }
    return {
        'pks': pks, 'exhausted': exhausted, 'timed_out': timed_out,
        'unanalyzed_count': unanalyzed_count, 'totals': totals,
    }


def cached_matching_logs(search, build_scope, *, scope_part, dedupe, needed, count_all):
    """find_matching_logs, served from a short-lived cache when an earlier scan already covers the request.

    `build_scope()` returns ``(scoped queryset, hidden pks, extra)`` and runs
    only on a cache miss, since narrowing by tags or finding duplicates reads
    every candidate. `extra` (e.g. tag_unanalyzed_count) is cached with the result.
    """
    key = search.cache_key(scope_part, dedupe)
    cached = cache.get(key)
    if cached is not None:
        enough = cached['exhausted'] or len(cached['pks']) >= needed or len(cached['pks']) > SEARCH_MAX_MATCHES
        if enough and (cached['totals'] is not None or not count_all):
            return cached
    scoped, hidden_pks, extra = build_scope()
    result = find_matching_logs(search, scoped, needed=needed, count_all=count_all, hidden_pks=hidden_pks)
    result.update(extra)
    cache.set(key, result, SEARCH_CACHE_TIMEOUT)
    return result
