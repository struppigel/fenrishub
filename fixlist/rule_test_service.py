"""Service helpers for rule-testing endpoint logic."""

import re

from . import frst_extractors as ex
from .analyzer import STATUS_LABELS, STATUS_PRECEDENCE, _load_rule_buckets, inspect_line_matches, parse_rule_line
from .models import ClassificationRule


def build_rule_test_results(source_text: str, status: str, match_type: str, lines: list) -> dict:
    """Build per-line rule test results for the rules test API."""
    parsed_rule = parse_rule_line(source_text, status=status)

    if match_type == 'regex':
        try:
            compiled = re.compile(source_text)
        except re.error as exc:
            raise ValueError(f'Invalid regex: {exc}') from exc
    else:
        compiled = None

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
    elif match_type not in ('exact', 'substring', 'regex'):
        raise ValueError(f'Unsupported match_type: {match_type}')

    # Matcher type precedence (same order as _analyze_single_line in analyzer.py).
    matcher_order = ['exact', 'parsed_entry', 'filepath', 'substring', 'regex']
    match_type_to_matcher = {
        'exact': 'exact',
        'parsed': 'parsed_entry',
        'filepath': 'filepath',
        'substring': 'substring',
        'regex': 'regex',
    }
    new_matcher = match_type_to_matcher.get(match_type, 'unknown')
    try:
        new_matcher_idx = matcher_order.index(new_matcher)
    except ValueError:
        new_matcher_idx = len(matcher_order)

    # Load existing rule buckets once for inspect_line_matches.
    buckets = _load_rule_buckets()

    results = []
    for raw_line in lines:
        line = (raw_line or '').strip() if match_type in ('exact', 'parsed', 'filepath') else (raw_line or '')
        result = {'line': line, 'matched': False, 'parsed': None, 'match_ranges': None}

        if match_type == 'exact':
            result['matched'] = line == source_text.strip()

        elif match_type == 'substring':
            ranges = []
            lower_line = line.lower()
            lower_pat = source_text.lower()
            idx = 0
            while idx < len(lower_line):
                pos = lower_line.find(lower_pat, idx)
                if pos == -1:
                    break
                ranges.append([pos, pos + len(lower_pat)])
                idx = pos + len(lower_pat)
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

        # Inspect existing rule matches for this line.
        stripped = line.strip()
        if stripped:
            inspection = inspect_line_matches(stripped, buckets=buckets)
            result['existing_status'] = inspection['dominant_status']
            result['existing_status_label'] = STATUS_LABELS.get(inspection['dominant_status'], 'unknown')
            result['existing_matches'] = inspection['matches']
            result['existing_shadowed'] = inspection['shadowed_matches']

            # Compute combined status respecting matcher type precedence.
            # The analyzer picks the first matcher tier that has any matches;
            # lower tiers are shadowed entirely.
            existing_matcher = inspection.get('effective_matcher', 'unknown')
            try:
                existing_matcher_idx = matcher_order.index(existing_matcher)
            except ValueError:
                existing_matcher_idx = len(matcher_order)

            new_rule_shadowed = False
            if result['matched']:
                if new_matcher_idx < existing_matcher_idx:
                    # New rule's matcher tier is higher -> it shadows existing.
                    effective_statuses = [status]
                elif new_matcher_idx == existing_matcher_idx:
                    # Same tier -> combine statuses.
                    effective_statuses = [m['status'] for m in inspection['matches']] + [status]
                else:
                    # New rule's matcher tier is lower -> shadowed by existing.
                    effective_statuses = [m['status'] for m in inspection['matches']]
                    new_rule_shadowed = True
            else:
                effective_statuses = [m['status'] for m in inspection['matches']]
            result['new_rule_shadowed'] = new_rule_shadowed
            result['new_rule_shadowed_by'] = existing_matcher if new_rule_shadowed else None

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