"""Service helpers for rule-testing endpoint logic."""

import re

from . import frst_extractors as ex
from . import script_matcher
from .analyzer import STATUS_LABELS, STATUS_PRECEDENCE, _load_rule_buckets, inspect_line_matches, parse_rule_line
from .models import ClassificationRule, PRIORITY_MAX, PRIORITY_MIN


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
        # Merge overlapping spans (multiple patterns can match the same region) so
        # the client renders a clean, non-overlapping set of highlights.
        merged = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
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


def build_rule_test_results(
    source_text: str,
    status: str,
    match_type: str,
    lines: list,
    priority: int | None = None,
) -> dict:
    """Build per-line rule test results for the rules test API."""
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

    # Pre-compute match-type-specific state once.
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

    if priority is None:
        new_priority = ClassificationRule.default_priority_for(match_type)
    else:
        new_priority = max(PRIORITY_MIN, min(PRIORITY_MAX, int(priority)))

    # Load existing rule buckets once for inspect_line_matches.
    buckets = _load_rule_buckets()

    results = []
    for raw_line in lines:
        line = (raw_line or '').strip() if match_type in ('exact', 'parsed', 'filepath') else (raw_line or '')
        result = {'line': line, 'matched': False, 'parsed': None, 'match_ranges': None}

        if match_type == 'exact':
            result['matched'] = line == source_text.strip()

        elif match_type == 'substring':
            # Case-sensitive, mirroring the analyzer's `rule.source_text in line`.
            ranges = []
            if source_text:
                idx = 0
                while idx < len(line):
                    pos = line.find(source_text, idx)
                    if pos == -1:
                        break
                    ranges.append([pos, pos + len(source_text)])
                    idx = pos + len(source_text)
            result['matched'] = len(ranges) > 0
            result['match_ranges'] = ranges or None

        elif match_type == 'regex':
            ranges = [[m.start(), m.end()] for m in compiled.finditer(line) if m.end() > m.start()]
            result['matched'] = len(ranges) > 0
            result['match_ranges'] = ranges or None

        elif match_type == 'parsed':
            if line:
                line_entry = ex.get_frst_entry(line)
                if line_entry:
                    result['parsed'] = {
                        'entry_type': line_entry.entry_type,
                        'clsid': line_entry.clsid,
                        'name': line_entry.name,
                        'filepath': line_entry.filepath,
                        'filename': line_entry.filename,
                        'company': line_entry.company,
                        'arguments': line_entry.arguments,
                    }
                result['matched'] = bool(rule_entry and line_entry and line_entry == rule_entry)

        elif match_type == 'filepath':
            line_path = ex.extract_any_frst_path(line)
            if line_path:
                line_norm = ex.normalize_path(line_path).lower().strip()
                result['matched'] = line_norm == rule_norm_path and bool(rule_norm_path)
                result['parsed'] = {'filepath': line_path, 'normalized_filepath': line_norm}

        elif match_type == 'script':
            matched, error = script_matcher.run_script(script_code, line)
            result['matched'] = matched
            if error:
                result['script_error'] = error

        # Inspect existing rule matches for this line.
        stripped = line.strip()
        if stripped:
            inspection = inspect_line_matches(stripped, buckets=buckets)
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
        'rule': parsed_rule,
        'results': results,
        'status_labels': STATUS_LABELS,
        'status_precedence': STATUS_PRECEDENCE,
    }