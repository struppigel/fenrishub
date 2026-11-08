"""Service helpers for rule-testing endpoint logic."""

import re
import time

from . import frst_extractors as ex
from . import script_matcher
from .analyzer import (
    STATUS_LABELS,
    STATUS_PRECEDENCE,
    _FILEPATH_FALLBACK_EFFECTIVE_PRIORITY,
    _load_rule_buckets,
    find_substring_ranges,
    inspect_line_matches,
    parse_rule_line,
)
from .models import ClassificationRule, PRIORITY_MAX, PRIORITY_MIN
from .rule_sets import SHARED_RULE_SET_KEY


def _merge_ranges(ranges: list) -> list:
    """Collapse overlapping/adjacent highlight spans into a clean, ordered set.

    Several patterns can match the same region, and a line can be matched by more
    than one of them, so the spans they produce have to be unioned before the
    client renders them.
    """
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def build_wholelog_rule_test_result(
    patterns: list,
    match_type: str,
    log_text: str,
) -> dict:
    """Preview a whole-log alert rule against the entire pasted log at once.

    Mirrors the analyzer's whole-log path: regex patterns search the full text,
    and script snippets run once with the log bound to the ``log`` variable. The
    result is a single log-level verdict rather than per-line rows.
    """
    if match_type == ClassificationRule.MATCH_REGEX:
        ranges = []
        for pattern in patterns:
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                raise ValueError(f'Invalid regex: {exc}') from exc
            ranges.extend(
                [m.start(), m.end()] for m in compiled.finditer(log_text) if m.end() > m.start()
            )
        merged = _merge_ranges(ranges)
        return {
            'whole_log': True,
            'log': log_text,
            'matched': bool(merged),
            'match_ranges': merged or None,
        }

    if match_type == ClassificationRule.MATCH_SCRIPT:
        # One snippet for the whole log (patterns is the single-element script blob).
        code = script_matcher.compile_script(patterns[0])  # ValueError -> HTTP 400 in the view.
        matched, error = script_matcher.run_script(code, log_text, var_name='log')
        result = {
            'whole_log': True,
            'log': log_text,
            'matched': matched,
            'match_ranges': None,
        }
        if error:
            result['script_error'] = error
        return result

    raise ValueError('Whole-log preview supports only regex and script match types.')


def _compile_pattern(source_text: str, status: str, match_type: str) -> dict:
    """Pre-compute the per-pattern state needed to test lines against it."""
    parsed_rule = parse_rule_line(source_text, status=status)

    if match_type == 'regex':
        try:
            compiled = re.compile(source_text)
        except re.error as exc:
            raise ValueError(f'Invalid regex: {exc}') from exc
    else:
        compiled = None

    script_code = None
    if match_type == 'script':
        # Raises ValueError on syntax/restriction errors -> HTTP 400 in the view.
        script_code = script_matcher.compile_script(source_text)

    rule_entry = None
    rule_norm_path = ''
    if match_type == 'parsed':
        if parsed_rule and parsed_rule.get('match_type') == ClassificationRule.MATCH_PARSED_ENTRY:
            rule_entry = ex.FrstEntry(
                entry_type=parsed_rule.get('entry_type', ''),
                clsid=parsed_rule.get('clsid', ''),
                name=parsed_rule.get('name', ''),
                filepath=parsed_rule.get('filepath', ''),
                filename=parsed_rule.get('filename', ''),
                company=parsed_rule.get('company', ''),
                arguments=parsed_rule.get('arguments', ''),
                file_not_signed=parsed_rule.get('file_not_signed', False),
            )
    elif match_type == 'filepath':
        if parsed_rule and parsed_rule.get('normalized_filepath'):
            rule_norm_path = parsed_rule['normalized_filepath']
        elif parsed_rule and parsed_rule.get('filepath'):
            rule_norm_path = ex.normalize_path(parsed_rule['filepath']).lower().strip()
        else:
            rule_norm_path = ex.normalize_path(source_text).lower().strip()
    elif match_type not in ('exact', 'substring', 'regex', 'script'):
        raise ValueError(f'Unsupported match_type: {match_type}')

    return {
        'source_text': source_text,
        'parsed_rule': parsed_rule,
        'compiled': compiled,
        'script_code': script_code,
        'rule_entry': rule_entry,
        'rule_norm_path': rule_norm_path,
    }


def _match_line(pattern: dict, match_type: str, line: str) -> dict:
    """Test one line against one pattern.

    Returns ``matched`` plus, where the match type provides them, the highlight
    ``ranges``, the line's ``parsed`` breakdown, and any ``script_error``.
    """
    outcome = {'matched': False, 'ranges': [], 'parsed': None, 'script_error': None}
    source_text = pattern['source_text']

    if match_type == 'exact':
        outcome['matched'] = line == source_text.strip()

    elif match_type == 'substring':
        outcome['ranges'] = find_substring_ranges(line, source_text)
        outcome['matched'] = bool(outcome['ranges'])

    elif match_type == 'regex':
        outcome['ranges'] = [
            [m.start(), m.end()]
            for m in pattern['compiled'].finditer(line)
            if m.end() > m.start()
        ]
        outcome['matched'] = bool(outcome['ranges'])

    elif match_type == 'parsed':
        if line:
            line_entry = ex.get_frst_entry(line)
            if line_entry:
                outcome['parsed'] = {
                    'entry_type': line_entry.entry_type,
                    'clsid': line_entry.clsid,
                    'name': line_entry.name,
                    'filepath': line_entry.filepath,
                    'filename': line_entry.filename,
                    'company': line_entry.company,
                    'arguments': line_entry.arguments,
                }
            rule_entry = pattern['rule_entry']
            outcome['matched'] = bool(rule_entry and line_entry and line_entry == rule_entry)

    elif match_type == 'filepath':
        line_path = ex.extract_any_frst_path(line)
        if line_path:
            line_norm = ex.normalize_path(line_path).lower().strip()
            rule_norm_path = pattern['rule_norm_path']
            outcome['matched'] = line_norm == rule_norm_path and bool(rule_norm_path)
            outcome['parsed'] = {'filepath': line_path, 'normalized_filepath': line_norm}

    elif match_type == 'script':
        matched, error = script_matcher.run_script(pattern['script_code'], line)
        outcome['matched'] = matched
        outcome['script_error'] = error

    return outcome


def build_rule_test_results(
    patterns: list,
    status: str,
    match_type: str,
    lines: list,
    priority: int | None = None,
    exclude_rule_id=None,
    rule_set_key: str = SHARED_RULE_SET_KEY,
    buckets=None,
) -> dict:
    """Build per-line rule test results for the rules test API.

    ``patterns`` is the list the add page's textarea produces -- one rule per line,
    or a single element for the editor and for script rules. Every pattern is tested
    against every line in one pass so a line matched by several of them reports the
    union of their highlights, and so the (pattern-independent) existing-rule lookup
    runs once per line rather than once per line per pattern.

    ``exclude_rule_id`` hides one saved rule from the "existing matches" side of the
    report. The rule editor passes the rule being edited so it is not listed as an
    existing match of itself, nor reported as shadowing its own pending edit.

    ``rule_set_key`` picks the rules the existing verdicts come from; the token
    API passes the caller's, so they agree with that caller's analyses, along
    with the cached ``buckets`` of that rule set; without them the rules are
    loaded fresh, as the browser preview has always done.
    """
    compiled_patterns = [
        _compile_pattern(pattern, status, match_type) for pattern in patterns
    ]

    if priority is None:
        new_priority = ClassificationRule.default_priority_for(match_type)
    else:
        new_priority = max(PRIORITY_MIN, min(PRIORITY_MAX, int(priority)))

    # Load existing rule buckets once for inspect_line_matches.
    if buckets is None:
        buckets = _load_rule_buckets(rule_set_key)

    results = []
    for raw_line in lines:
        line = (raw_line or '').strip() if match_type in ('exact', 'parsed', 'filepath') else (raw_line or '')
        result = {'line': line, 'matched': False, 'parsed': None, 'match_ranges': None}

        ranges = []
        for pattern in compiled_patterns:
            outcome = _match_line(pattern, match_type, line)
            if outcome['matched']:
                result['matched'] = True
            ranges.extend(outcome['ranges'])
            if result['parsed'] is None and outcome['parsed'] is not None:
                result['parsed'] = outcome['parsed']
            if outcome['script_error'] and 'script_error' not in result:
                result['script_error'] = outcome['script_error']
        result['match_ranges'] = _merge_ranges(ranges) or None

        # Inspect existing rule matches for this line.
        stripped = line.strip()
        if stripped:
            inspection = inspect_line_matches(
                stripped, buckets=buckets, exclude_rule_id=exclude_rule_id
            )
            result['existing_status'] = inspection['dominant_status']
            result['existing_status_label'] = STATUS_LABELS.get(inspection['dominant_status'], 'unknown')
            result['existing_matches'] = inspection['matches']
            result['existing_shadowed'] = inspection['shadowed_matches']

            # Compute combined status respecting numeric priority.
            # The analyzer picks the highest-priority match group; lower
            # priorities are shadowed entirely. Within the winning priority,
            # all statuses combine and STATUS_PRECEDENCE picks the dominant.
            existing_priority = inspection.get('effective_priority')

            new_rule_shadowed = False
            if result['matched']:
                if existing_priority is None or new_priority > existing_priority:
                    # No existing matches, or new rule wins on priority.
                    effective_statuses = [status]
                elif new_priority == existing_priority:
                    # Tie -> combine statuses.
                    effective_statuses = [m['status'] for m in inspection['matches']] + [status]
                else:
                    # New rule's priority is lower -> shadowed by existing.
                    effective_statuses = [m['status'] for m in inspection['matches']]
                    new_rule_shadowed = True
            else:
                effective_statuses = [m['status'] for m in inspection['matches']]
            result['new_rule_priority'] = new_priority
            result['existing_priority'] = existing_priority
            result['new_rule_shadowed'] = new_rule_shadowed
            result['new_rule_shadowed_by'] = (
                f'priority {existing_priority}' if new_rule_shadowed else None
            )

            combined = '?'
            for status_code in STATUS_PRECEDENCE:
                if status_code in effective_statuses:
                    combined = status_code
                    break
            result['combined_status'] = combined
            result['combined_status_label'] = STATUS_LABELS.get(combined, 'unknown')

            # Detect when new rule matched at the same tier but is outranked by status precedence.
            new_rule_outranked = (
                result['matched']
                and not new_rule_shadowed
                and combined != status
                and combined != '?'
            )
            result['new_rule_outranked'] = new_rule_outranked
            if new_rule_outranked:
                result['new_rule_outranked_by'] = STATUS_LABELS.get(combined, combined)
            else:
                result['new_rule_outranked_by'] = None
        else:
            result['existing_status'] = '?'
            result['existing_status_label'] = 'unknown'
            result['existing_matches'] = []
            result['existing_shadowed'] = []
            result['combined_status'] = '?'
            result['combined_status_label'] = 'unknown'
            result['new_rule_priority'] = new_priority
            result['existing_priority'] = None
            result['new_rule_shadowed'] = False
            result['new_rule_shadowed_by'] = None
            result['new_rule_outranked'] = False
            result['new_rule_outranked_by'] = None

        results.append(result)

    return {
        # The first pattern's parse, kept for API compatibility. With several
        # patterns there is no single rule to describe; the client renders from
        # the per-line results instead.
        'rule': compiled_patterns[0]['parsed_rule'] if compiled_patterns else None,
        'results': results,
        'status_labels': STATUS_LABELS,
        'status_precedence': STATUS_PRECEDENCE,
    }


# A line seen in many logs lists only the first few; `log_count` has the total.
LOG_REFS_PER_LINE = 5


def _may_contain_match(compiled_patterns: list, match_type: str, content: str) -> bool:
    """Cheap whole-log check that lets the scan skip logs that cannot match.

    Only exact and substring rules have a literal that must appear verbatim in
    any matching line; every other type has to look at the lines themselves.
    """
    if match_type == 'substring':
        return any(p['source_text'] in content for p in compiled_patterns)
    if match_type == 'exact':
        return any(p['source_text'].strip() in content for p in compiled_patterns)
    return True


def scan_logs_for_rule_matches(
    patterns: list,
    status: str,
    match_type: str,
    logs,
    *,
    max_lines: int,
    deadline: float,
    count_all: bool = False,
) -> dict:
    """Find the distinct lines a rule matches across stored logs.

    ``logs`` yields ``(upload_id, content)`` pairs. Identical lines from different
    logs collapse into one entry recording the logs it occurs in, so a line common
    to many machines is reviewed once; entries come back most widespread first.
    Scanning stops after ``max_lines`` distinct lines (``truncated``) or once
    ``time.monotonic()`` passes ``deadline`` (``timed_out``).

    With ``count_all`` a full ``truncated`` sample does not stop the scan: it
    goes on counting, so ``logs_matched``, ``line_hits`` (matching lines, repeats
    within a log included) and ``distinct_lines`` cover every log scanned, while
    ``matches`` keeps only the first ``max_lines`` distinct lines.
    """
    compiled_patterns = [
        _compile_pattern(pattern, status, match_type) for pattern in patterns
    ]
    strip = match_type in ('exact', 'parsed', 'filepath')

    found = {}
    # Distinct lines past the sample, kept only to count them (count_all).
    overflow = set()
    line_hits = 0
    logs_scanned = 0
    logs_matched = 0
    truncated = False
    timed_out = False

    for upload_id, content in logs:
        if time.monotonic() > deadline:
            timed_out = True
            break
        logs_scanned += 1
        if not _may_contain_match(compiled_patterns, match_type, content):
            continue

        matched_here = set()
        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            if time.monotonic() > deadline:
                timed_out = True
                break
            # Normalised exactly as build_rule_test_results does, so the lines
            # handed back to it produce the same verdicts the scan found.
            line = raw_line.strip() if strip else raw_line
            if not line.strip():
                continue
            if line in matched_here:
                line_hits += 1
                continue
            if not any(_match_line(p, match_type, line)['matched'] for p in compiled_patterns):
                continue

            entry = found.get(line)
            if entry is None:
                if len(found) >= max_lines:
                    truncated = True
                    if not count_all:
                        break
                    overflow.add(line)
                    matched_here.add(line)
                    line_hits += 1
                    continue
                entry = found[line] = {'line': line, 'logs': [], 'log_count': 0}
            matched_here.add(line)
            line_hits += 1
            entry['log_count'] += 1
            if len(entry['logs']) < LOG_REFS_PER_LINE:
                entry['logs'].append({'upload_id': upload_id, 'line_number': line_number})

        if matched_here:
            logs_matched += 1
        if (truncated and not count_all) or timed_out:
            break

    return {
        'matches': sorted(found.values(), key=lambda entry: -entry['log_count']),
        'logs_scanned': logs_scanned,
        'logs_matched': logs_matched,
        'line_hits': line_hits,
        'distinct_lines': len(found) + len(overflow),
        'truncated': truncated,
        'timed_out': timed_out,
    }


def scan_logs_for_wholelog_matches(patterns: list, match_type: str, logs, *, deadline: float) -> dict:
    """Run a whole-log alert rule over stored logs and list the ones it fires on."""
    matched_logs = []
    logs_scanned = 0
    timed_out = False
    script_error = None

    for upload_id, content in logs:
        if time.monotonic() > deadline:
            timed_out = True
            break
        logs_scanned += 1
        result = build_wholelog_rule_test_result(patterns, match_type, content)
        if result.get('script_error') and script_error is None:
            script_error = result['script_error']
        if result['matched']:
            matched_logs.append({
                'upload_id': upload_id,
                'match_count': len(result['match_ranges'] or []),
            })

    return {
        'whole_log': True,
        'logs': matched_logs,
        'logs_scanned': logs_scanned,
        'logs_matched': len(matched_logs),
        'timed_out': timed_out,
        'script_error': script_error,
    }


def _effective_priority_of_match(match: dict) -> int:
    """The priority a serialized existing match competes with (see analyzer._effective_match_priority)."""
    if match.get('matcher') == 'filepath' and match.get('match_type') != ClassificationRule.MATCH_FILEPATH:
        return _FILEPATH_FALLBACK_EFFECTIVE_PRIORITY
    return match.get('priority') or 0


def _verdict_of(entries) -> str:
    """The analyzer's verdict for ``(effective priority, status)`` matches: the top tier, by precedence."""
    entries = list(entries)
    if not entries:
        return '?'
    top = max(priority for priority, _status in entries)
    statuses = {status for priority, status in entries if priority == top}
    for status in STATUS_PRECEDENCE:
        if status in statuses:
            return status
    return '?'


def line_outcome(result: dict) -> str:
    """How a candidate rule fares on one matched line of build_rule_test_results."""
    if result.get('new_rule_shadowed'):
        return 'shadowed'
    if result.get('new_rule_outranked'):
        return 'outranked'
    if result.get('existing_priority') is None:
        return 'new_verdict'
    if result['new_rule_priority'] > result['existing_priority']:
        return 'wins'
    return 'ties'


def summarize_rule_test(results: list, status: str) -> dict:
    """Roll the per-line results of build_rule_test_results up for a dry run.

    Over the matched lines: how the new rule fares on each (``outcome_counts``),
    how verdicts would change (``verdict_changes``, ``"?->B": n``), and every
    existing rule in the winning tier of those lines today (``existing_rules``).
    For each such rule, ``redundant_lines`` counts the lines where removing it
    would no longer change the verdict once the new rule exists - a rule
    redundant on all its sample lines is a candidate to retire, though it may
    still decide lines the new rule never matches (compare_rule_scans shows those).
    """
    outcome_counts = {'new_verdict': 0, 'wins': 0, 'ties': 0, 'outranked': 0, 'shadowed': 0}
    verdict_changes = {}
    unchanged = 0
    rules = {}

    for result in results:
        if not result.get('matched'):
            continue
        existing = result.get('existing_status', '?')
        combined = result.get('combined_status', '?')
        outcome_counts[line_outcome(result)] += 1
        if combined != existing:
            key = f'{existing}->{combined}'
            verdict_changes[key] = verdict_changes.get(key, 0) + 1
        else:
            unchanged += 1

        effective = result.get('existing_matches') or []
        shadowed = result.get('existing_shadowed') or []
        tier_priority = result.get('existing_priority')
        new_entry = (result['new_rule_priority'], status)
        # Every competing match, with the priority it really competes at.
        competing = (
            [(match['id'], (tier_priority, match['status'])) for match in effective]
            + [(match['id'], (_effective_priority_of_match(match), match['status'])) for match in shadowed]
        )
        verdict_with_all = _verdict_of([entry for _rule_id, entry in competing] + [new_entry])

        for match in effective:
            row = rules.get(match['id'])
            if row is None:
                row = rules[match['id']] = {
                    'rule_id': match['id'],
                    'status': match['status'],
                    'match_type': match['match_type'],
                    'priority': match['priority'],
                    'owner': match.get('owner_username', ''),
                    'source_text': match['source_text'],
                    'description': match.get('description', ''),
                    'lines': 0,
                    'decided_lines': 0,
                    'redundant_lines': 0,
                }
            row['lines'] += 1
            if match['status'] == existing:
                row['decided_lines'] += 1
            without = [entry for rule_id, entry in competing if rule_id != match['id']] + [new_entry]
            if _verdict_of(without) == verdict_with_all:
                row['redundant_lines'] += 1

    existing_rules = sorted(rules.values(), key=lambda row: (-row['lines'], row['rule_id']))
    for row in existing_rules:
        row['redundant_on_all_sample_lines'] = row['redundant_lines'] == row['lines']
    return {
        'outcome_counts': outcome_counts,
        'verdict_changes': dict(sorted(verdict_changes.items(), key=lambda item: -item[1])),
        'unchanged_lines': unchanged,
        'existing_rules': existing_rules,
    }


def literal_prefilter(patterns: list, match_type: str):
    """Literals of which every matching log must contain one, for a database prefilter, or None.

    Only exact and substring rules have such a literal (see _may_contain_match).
    """
    if match_type == 'substring':
        literals = [pattern for pattern in patterns if pattern]
    elif match_type == 'exact':
        literals = [pattern.strip() for pattern in patterns if pattern.strip()]
    else:
        return None
    return literals or None


def compare_rule_scans(new_rule: dict, old_rule: dict, logs, *, deadline: float, sample_lines: int) -> dict:
    """Which distinct lines a candidate rule and an existing rule match, in one pass over `logs`.

    Each rule is ``{'patterns', 'status', 'match_type'}``. Returns the counts of
    distinct lines only the new rule matches, only the old one, or both, with a
    sample of each one-sided kind (most widespread first): whether a new rule
    covers everything an old per-case rule caught, and what else it catches.
    """
    sides = []
    for rule in (new_rule, old_rule):
        sides.append({
            'compiled': [_compile_pattern(p, rule['status'], rule['match_type']) for p in rule['patterns']],
            'match_type': rule['match_type'],
            'strip': rule['match_type'] in ('exact', 'parsed', 'filepath'),
        })

    seen = {'both': set(), 'only_new': set(), 'only_old': set()}
    samples = {'only_new': {}, 'only_old': {}}
    logs_scanned = 0
    timed_out = False

    for upload_id, content in logs:
        if time.monotonic() > deadline:
            timed_out = True
            break
        logs_scanned += 1
        may_match = [_may_contain_match(side['compiled'], side['match_type'], content) for side in sides]
        if not any(may_match):
            continue
        tested_here = set()
        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            if time.monotonic() > deadline:
                timed_out = True
                break
            if not raw_line.strip() or raw_line in tested_here:
                continue
            tested_here.add(raw_line)
            hits = []
            for side, may in zip(sides, may_match):
                line = raw_line.strip() if side['strip'] else raw_line
                hits.append(may and any(
                    _match_line(p, side['match_type'], line)['matched'] for p in side['compiled']
                ))
            if not any(hits):
                continue
            kind = 'both' if all(hits) else ('only_new' if hits[0] else 'only_old')
            key = raw_line.strip()
            seen[kind].add(key)
            if kind in samples:
                entry = samples[kind].get(key)
                if entry is None and len(samples[kind]) < sample_lines:
                    entry = samples[kind][key] = {'line': key, 'logs': [], 'log_count': 0}
                if entry is not None:
                    entry['log_count'] += 1
                    if len(entry['logs']) < LOG_REFS_PER_LINE:
                        entry['logs'].append({'upload_id': upload_id, 'line_number': line_number})
        if timed_out:
            break

    return {
        'both': len(seen['both']),
        'only_new': len(seen['only_new']),
        'only_old': len(seen['only_old']),
        'only_new_sample': sorted(samples['only_new'].values(), key=lambda entry: -entry['log_count']),
        'only_old_sample': sorted(samples['only_old'].values(), key=lambda entry: -entry['log_count']),
        'logs_scanned': logs_scanned,
        'timed_out': timed_out,
    }
