"""Service helpers for rule-testing endpoint logic."""

import re
import time

from . import frst_extractors as ex
from . import log_layout, regex_engine, script_matcher
from django.db.models import Max

from .analyzer import (
    ANALYSIS_PAYLOAD_FORMAT,
    RULE_ENTRY_FIELDS,
    STATUS_LABELS,
    STATUS_PRECEDENCE,
    _BLOCK_REGEX_FLAGS,
    _FILEPATH_FALLBACK_EFFECTIVE_PRIORITY,
    _get_cached_rule_buckets,
    condition_report,
    conditions_for_specs,
    entry_types_allow,
    find_facts,
    find_substring_ranges,
    inspect_line_matches,
    line_features,
    log_inputs,
    parse_rule_line,
    rule_frst_entry,
    single_block_inputs,
)
from .fact_index import FactIndex
from .log_types import ANALYZED_LOG_TYPES, LOG_TYPE_SPOR, rule_scope_log_type
from .models import (
    ClassificationRule, Fact, FactRule, FactTagSource, PRIORITY_MAX, PRIORITY_MIN, RuleCondition,
    UploadedLogAnalysis,
)
from .status_types import dominant_status
from .rule_sets import SHARED_RULE_SET_KEY


# ---------------------------------------------------------------------------
# Conditions of a candidate rule in the previews
# ---------------------------------------------------------------------------

def _needs_layout(specs) -> bool:
    return any(spec.scope != RuleCondition.SCOPE_LOG for spec in specs)


def pasted_condition_check(log_text, line_count, specs, buckets, log_type):
    """The `condition_check` of build_rule_test_results for pasted text: the
    text is one small log, its facts found as the analyzer would find them.
    Lines are checked by their position among the non-blank lines; when that
    count differs from the preview's `line_count`, nothing is checked."""
    facts, walked = find_facts(log_text, buckets, log_type)
    if len(walked) != line_count:
        return lambda _index: None
    conditions = conditions_for_specs(specs)
    structure = log_layout.layout(log_text, log_type) if _needs_layout(specs) else None
    line_nos = [item.line_no for item in walked]
    return lambda index: condition_report(conditions, facts, index, structure, line_nos)


def wholelog_condition_report(log_text, specs, buckets, log_type=None):
    """`(holds, explanation)` of a whole-log rule's conditions on a text."""
    facts, walked = find_facts(log_text, buckets, log_type)
    return condition_report(conditions_for_specs(specs), facts, None, None, [item.line_no for item in walked])


class CachedFactCheck:
    """The `line_check` of scan_logs_for_rule_matches: a candidate rule's
    conditions checked against the facts saved with each log's cached
    analysis (rule set `rule_set_key`).

    A log counts only when its analysis is fresh (same content, format and
    log type, like upload_utils.get_fresh_cached_analysis) and was written
    after the last change to the facts the conditions name (their fact rules
    and tag sources included). Changes of which rules carry a tag have no
    timestamp, so they are not noticed. Other logs are 'unchecked'.
    """

    def __init__(self, specs, rule_set_key):
        self.conditions = conditions_for_specs(specs)
        self.needs_layout = _needs_layout(specs)
        self.rule_set_key = rule_set_key
        fact_ids = [spec.fact_id for spec in specs]
        stamps = [
            Fact.objects.filter(pk__in=fact_ids).aggregate(last=Max('updated_at'))['last'],
            FactRule.objects.filter(fact_id__in=fact_ids).aggregate(last=Max('updated_at'))['last'],
            FactTagSource.objects.filter(fact_id__in=fact_ids).aggregate(last=Max('updated_at'))['last'],
        ]
        self.since = max((stamp for stamp in stamps if stamp is not None), default=None)
        self.logs = {}  # upload_id -> (FactIndex, layout or None, line numbers)

    def prepare(self, upload_pk, upload_id, content, content_hash, log_type):
        """Read one log's cached facts, before the scan reaches its lines."""
        row = UploadedLogAnalysis.objects.filter(upload_id=upload_pk, rule_set_key=self.rule_set_key).values_list(
            'payload__facts', 'payload__format', 'payload__log_type', 'source_content_hash', 'updated_at',
        ).first()
        if row is None:
            return
        facts, payload_format, payload_type, source_hash, updated_at = row
        if source_hash != content_hash or payload_format != ANALYSIS_PAYLOAD_FORMAT:
            return
        if payload_type is None:
            if log_type not in ANALYZED_LOG_TYPES and rule_scope_log_type(log_type):
                return
        elif payload_type != log_type:
            return
        if self.since is not None and updated_at < self.since:
            return
        walked = log_layout.analyzed_lines(content)
        self.logs[upload_id] = (
            FactIndex.from_payload(facts if isinstance(facts, list) else []),
            log_layout.layout(content, log_type) if self.needs_layout else None,
            [item.line_no for item in walked],
        )

    def __call__(self, upload_id, index):
        state = self.logs.get(upload_id)
        if state is None:
            return 'unchecked'
        facts, structure, line_nos = state
        holds, _explanation = condition_report(self.conditions, facts, index, structure, line_nos)
        return 'hold' if holds else 'fail'


def _compile_regex(pattern: str):
    """Compile a rule regex like the analyzer does (re2 first, stdlib re for what
    re2 refuses), so the preview highlights the spans the analyzer paints.
    Raises ValueError with stdlib re's message for an invalid pattern."""
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f'Invalid regex: {exc}') from exc
    return regex_engine.compile(pattern)


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
            ranges.extend(regex_engine.match_ranges(_compile_regex(pattern), log_text))
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


_LINE = ClassificationRule.MATCH_UNIT_LINE
_BLOCK = ClassificationRule.MATCH_UNIT_BLOCK


def _compile_pattern(source_text: str, status: str, match_type: str, match_unit: str = _LINE) -> dict:
    """Pre-compute the per-pattern state needed to test lines (or, for a block
    rule, blocks) against it."""
    block = match_unit == _BLOCK
    parsed_rule = parse_rule_line(source_text, status=status, match_unit=match_unit)

    compiled = None
    if match_type == 'regex':
        compiled = _compile_regex(_BLOCK_REGEX_FLAGS + source_text if block else source_text)

    script_code = None
    if match_type == 'script':
        # Raises ValueError on syntax/restriction errors -> HTTP 400 in the view.
        script_code = script_matcher.compile_script(source_text)

    rule_entry = None
    rule_norm_path = ''
    if match_type == 'parsed':
        if parsed_rule and parsed_rule.get('match_type') == ClassificationRule.MATCH_PARSED_ENTRY:
            rule_entry = rule_frst_entry(parsed_rule)
    elif match_type == 'filepath':
        if parsed_rule and parsed_rule.get('normalized_filepath'):
            rule_norm_path = parsed_rule['normalized_filepath']
        elif parsed_rule and parsed_rule.get('filepath'):
            rule_norm_path = ex.path_key(parsed_rule['filepath'])
        else:
            rule_norm_path = ex.path_key(source_text)
    elif match_type not in ('exact', 'substring', 'regex', 'script'):
        raise ValueError(f'Unsupported match_type: {match_type}')

    return {
        'source_text': source_text,
        'block_text': log_layout.normalize_block_text(source_text) if block else '',
        'parsed_rule': parsed_rule,
        'compiled': compiled,
        'script_code': script_code,
        'rule_entry': rule_entry,
        'rule_norm_path': rule_norm_path,
    }


def _match_block(pattern: dict, match_type: str, block) -> bool:
    """Whether one block (analyzer.BlockFeatures) matches one block-rule pattern,
    as analyzer._flat_block_matches tests it."""
    if match_type == 'exact':
        return bool(pattern['block_text']) and block.text == pattern['block_text']
    if match_type == 'substring':
        return bool(pattern['source_text']) and pattern['source_text'] in block.text
    if match_type == 'regex':
        return bool(regex_engine.match_ranges(pattern['compiled'], block.text))
    if match_type == 'parsed':
        return pattern['rule_entry'] is not None and pattern['rule_entry'] in block.entries
    if match_type == 'filepath':
        return bool(pattern['rule_norm_path']) and pattern['rule_norm_path'] in block.paths
    return False


def _match_line(pattern: dict, match_type: str, line: str, features=None) -> dict:
    """Test one line against one pattern. `features` (analyzer.LineFeatures,
    e.g. a Spor line's path) default to the line read on its own.

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
        outcome['ranges'] = regex_engine.match_ranges(pattern['compiled'], line)
        outcome['matched'] = bool(outcome['ranges'])

    elif match_type == 'parsed':
        if line:
            entries = features.parsed_entries if features is not None else tuple(ex.iter_frst_entries(line))
            line_entry = entries[0] if entries else None
            if line_entry:
                outcome['parsed'] = {field: getattr(line_entry, field) for field in RULE_ENTRY_FIELDS}
            rule_entry = pattern['rule_entry']
            outcome['matched'] = bool(rule_entry and rule_entry in entries)

    elif match_type == 'filepath':
        line_path = features.filepath if features is not None else ex.extract_any_frst_path(line)
        if line_path:
            line_norm = ex.path_key(line_path)
            rule_norm_path = pattern['rule_norm_path']
            outcome['matched'] = line_norm == rule_norm_path and bool(rule_norm_path)
            outcome['parsed'] = {'filepath': line_path, 'normalized_filepath': line_norm}

    elif match_type == 'script':
        matched, error = script_matcher.run_script(pattern['script_code'], line)
        outcome['matched'] = matched
        outcome['script_error'] = error

    return outcome


def _line_types_allow(only_entry_types, line: str, features=None) -> bool:
    """Whether a rule restricted to `only_entry_types` may match `line` (its
    parsed types: of `features` when given, e.g. a Spor block's)."""
    if not only_entry_types:
        return True
    if features is None:
        features = line_features(line.strip())
    return entry_types_allow(only_entry_types, features.entry_types)


class _LogView:
    """A log's lines as the analyzer reads them (analyzer.LogInputs): every
    analyzed line with its features, and, when `blocks`, their blocks."""

    def __init__(self, content, log_type, blocks):
        self.inputs = log_inputs(content, log_type, {"__block": {} if blocks else None})

    def lines(self):
        """(index, line number, raw piece, stripped text, the line's features)
        per analyzed line; the features are read only when used (a lazy
        lookup: `self.inputs.features[index]`)."""
        for item in self.inputs.walked:
            yield item.index, item.line_no, item.raw, item.text, None

    def block_at(self, index, reads='all'):
        """(BlockFeatures, analyzed-line indexes) of the block line `index` is
        in, with what a block rule reads: 'text' just its text, 'spor' its
        text and Spor entry (LogInputs.block_text_at / block_entry_at)."""
        if reads == 'text':
            return self.inputs.block_text_at(index)
        if reads == 'spor':
            return self.inputs.block_entry_at(index)
        return self.inputs.block_at(index)


def _block_reads(compiled_patterns, match_type, only_entry_types):
    """What of a block the block-rule patterns need (see _LogView.block_at)."""
    if match_type in _TEXT_MATCH_TYPES and not only_entry_types:
        return 'text'
    if match_type == 'parsed' and _spor_only(compiled_patterns) and all(
        name.startswith('spor_') for name in only_entry_types or ()
    ):
        return 'spor'
    return 'all'


def _spor_only(compiled_patterns) -> bool:
    """Every pattern is a Spor parsed entry: they can only match Spor blocks."""
    return all(
        pattern['rule_entry'] is not None and pattern['rule_entry'].entry_type.startswith('spor_')
        for pattern in compiled_patterns
    )


# Block rules of these match types read only the block's text.
_TEXT_MATCH_TYPES = frozenset({'exact', 'substring', 'regex'})
# Line rules of these match types read the line's features (its parsed
# entries, its path). The others read only its text, so a log view's features
# (an FRST parse of the line, the most costly part of a Spor scan) are read
# for them only to check `only_entry_types`, and only on lines they matched.
_FEATURE_MATCH_TYPES = frozenset({'parsed', 'filepath'})


def _is_spor(log_type) -> bool:
    return rule_scope_log_type(log_type) == LOG_TYPE_SPOR


def _pasted_view(lines, log_type, blocks):
    """`(view, index of each line)` for pasted `lines` read as one log, or
    (None, None) when they need no more than reading each line on its own
    (no Spor log, no block rule)."""
    if not blocks and not _is_spor(log_type):
        return None, None
    view = _LogView('\n'.join(str(line or '') for line in lines), log_type, blocks)
    index_of = {}
    for index, line_no, _raw, _text, _features in view.lines():
        index_of.setdefault(line_no - 1, index)
    return view, index_of


def build_rule_test_results(
    patterns: list,
    status: str,
    match_type: str,
    lines: list,
    priority: int | None = None,
    exclude_rule_id=None,
    rule_set_key: str = SHARED_RULE_SET_KEY,
    buckets=None,
    line_log_types=None,
    only_entry_types=None,
    condition_check=None,
    match_unit: str = _LINE,
    log_type=None,
    blocks: bool = False,
    line_inputs=None,
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
    with the cached ``buckets`` of that rule set; without them the cached
    buckets of ``rule_set_key`` are used.

    ``line_log_types`` (aligned with ``lines``) names the log type each line
    came from, so its existing verdict uses only the rules scoped to that type,
    as the analyzer does. Without it, or for a line of no type, every rule counts.

    ``only_entry_types`` restricts the candidate rule to lines parsed as one of
    those entry types, as the analyzer does (analyzer.entry_types_allow).

    ``condition_check(line_index)`` (a candidate rule with conditions) gives
    ``(holds, explanation)`` for a line, or None when they cannot be checked.
    A matched line whose conditions fail is treated as not matched; each
    matched line says why in ``condition_note``.

    ``match_unit`` "block" tests the candidate on blocks: the pasted ``lines``
    are laid out as one log (``log_type``, e.g. Spor) and every line of a
    matching block is matched. With ``blocks`` each entry of ``lines`` is a
    block's text already (the stored-log scan), one result per block.
    ``log_type`` also reads Spor lines as the analyzer does (their paths,
    their block's parsed type).

    ``line_inputs`` (aligned with ``lines``, line rules) gives a line's
    ``(features, block lines)`` as read in its own log, or None: the stored-log
    scan passes them for Spor lines, which read alone lose their Spor path and
    parsed type.
    """
    block_rule = match_unit == _BLOCK
    compiled_patterns = [
        _compile_pattern(pattern, status, match_type, match_unit) for pattern in patterns
    ]
    view, index_of = (None, None) if blocks else _pasted_view(lines, log_type, block_rule)

    if priority is None:
        new_priority = ClassificationRule.default_priority_for(match_type)
    else:
        new_priority = max(PRIORITY_MIN, min(PRIORITY_MAX, int(priority)))

    # Existing rule buckets for inspect_line_matches, from the cache: indexing
    # every rule takes seconds, and the previews run on each edit. A rule saved
    # a moment ago still shows, as saving bumps the rules version.
    if buckets is None:
        buckets = _get_cached_rule_buckets(rule_set_key)
    buckets_by_type = {}

    def buckets_for(index):
        log_type = rule_scope_log_type(line_log_types[index]) if line_log_types else None
        if log_type is None:
            return buckets
        if log_type not in buckets_by_type:
            buckets_by_type[log_type] = _get_cached_rule_buckets(rule_set_key, log_type)
        return buckets_by_type[log_type]

    block_hits = {}

    def block_matched(block):
        # By content: blocks read for one line at a time are not kept alive,
        # so their ids can repeat.
        key = (block.text, block.entries, block.paths)
        if key not in block_hits:
            block_hits[key] = (
                any(_match_block(pattern, match_type, block) for pattern in compiled_patterns)
                and entry_types_allow(only_entry_types, block.entry_types)
            )
        return block_hits[key]

    results = []
    for line_index, raw_line in enumerate(lines):
        line_log_type = (line_log_types[line_index] if line_log_types else None) or log_type
        block_lines = None
        features = None
        block = None
        index = None
        if blocks:
            line = log_layout.normalize_block_text(raw_line or '')
            block_lines = line.split('\n') if line else []
            if block_lines:
                features, block = single_block_inputs(block_lines[0], line_log_type, block_lines)
        else:
            line = (raw_line or '').strip() if match_type in ('exact', 'parsed', 'filepath') or block_rule else (raw_line or '')
            index = index_of.get(line_index) if index_of is not None else None
            if index is not None:
                if not block_rule and match_type in _FEATURE_MATCH_TYPES:
                    features = view.inputs.features[index]
                if block_rule:
                    block, members = view.block_at(index)
                    block_lines = [view.inputs.walked[member].text for member in members]
                elif _is_spor(log_type):
                    _block, members = view.block_at(index)
                    block_lines = [view.inputs.walked[member].text for member in members]
            elif not block_rule and line_inputs and line_inputs[line_index] is not None:
                features, block_lines = line_inputs[line_index]
        result = {'line': line, 'matched': False, 'parsed': None, 'match_ranges': None}

        ranges = []
        if block_rule:
            if block is None and line.strip():
                features, block = single_block_inputs(line.strip(), line_log_type)
            if block is not None and block_matched(block):
                result['matched'] = True
                ranges = [[0, len(line)]]
        else:
            for pattern in compiled_patterns:
                outcome = _match_line(pattern, match_type, line, features)
                if outcome['matched']:
                    result['matched'] = True
                ranges.extend(outcome['ranges'])
                if result['parsed'] is None and outcome['parsed'] is not None:
                    result['parsed'] = outcome['parsed']
                if outcome['script_error'] and 'script_error' not in result:
                    result['script_error'] = outcome['script_error']
            if result['matched'] and only_entry_types and features is None and index is not None:
                features = view.inputs.features[index]
            if result['matched'] and not _line_types_allow(only_entry_types, line, features):
                result['matched'] = False
                ranges = []
        if result['matched'] and condition_check is not None:
            report = condition_check(line_index)
            if report is None:
                result['condition_note'] = 'conditions not checked'
            elif report[0]:
                result['condition_note'] = f'conditions hold: {report[1]}'
            else:
                result['matched'] = False
                ranges = []
                result['condition_note'] = f'not applied: {report[1]}'
        result['match_ranges'] = _merge_ranges(ranges) or None

        # Inspect existing rule matches for this line.
        stripped = (block_lines[0] if blocks and block_lines else line).strip()
        if stripped:
            inspection = inspect_line_matches(
                stripped, buckets=buckets_for(line_index), exclude_rule_id=exclude_rule_id,
                log_type=line_log_type, block_lines=block_lines,
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

            combined = dominant_status(effective_statuses)
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
    A block rule's text spans lines (indented in the log): only its first
    line is looked for.
    """
    if match_type == 'substring':
        return any(p['source_text'].split('\n', 1)[0].strip() in content for p in compiled_patterns)
    if match_type == 'exact':
        return any(p['source_text'].split('\n', 1)[0].strip() in content for p in compiled_patterns)
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
    only_entry_types=None,
    line_check=None,
    match_unit: str = _LINE,
    log_type_for=None,
) -> dict:
    """Find the distinct lines a rule matches across stored logs.

    ``match_unit`` "block": the distinct blocks instead, each entry's ``line``
    being the block's text (its lines joined by "\n"). ``log_type_for(upload_id)``
    names each log's type, so Spor logs are read as the analyzer reads them.

    ``line_check(upload_id, index)`` (a rule with conditions) answers 'hold',
    'fail' or 'unchecked' for the analyzed line ``index`` of a log: failing
    occurrences are not counted, unchecked ones are counted with their log
    ref flagged, and ``conditions_unchecked_logs`` counts the logs concerned.
    The lines are then walked like the analyzer walks them
    (log_layout.analyzed_lines), so the indexes and line numbers agree.

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
    block_rule = match_unit == _BLOCK
    compiled_patterns = [
        _compile_pattern(pattern, status, match_type, match_unit) for pattern in patterns
    ]
    strip = match_type in ('exact', 'parsed', 'filepath') or block_rule
    reads_features = match_type in _FEATURE_MATCH_TYPES

    found = {}
    # Distinct lines past the sample, kept only to count them (count_all).
    overflow = set()
    line_hits = 0
    logs_scanned = 0
    logs_matched = 0
    truncated = False
    timed_out = False
    unchecked_logs = set()

    for upload_id, content in logs:
        if time.monotonic() > deadline:
            timed_out = True
            break
        logs_scanned += 1
        if not _may_contain_match(compiled_patterns, match_type, content):
            continue

        log_type = log_type_for(upload_id) if log_type_for is not None else None
        if block_rule and match_type == 'parsed' and _spor_only(compiled_patterns) and not _is_spor(log_type):
            continue   # Spor entries are only read in Spor logs
        view = None
        if block_rule or _is_spor(log_type):
            view = _LogView(content, log_type, block_rule)
            walk = ((line_no, raw, index) for index, line_no, raw, _text, _features in view.lines())
        elif line_check is None:
            walk = ((number, raw, None) for number, raw in enumerate(content.splitlines(), start=1))
        else:
            walk = ((item.line_no, item.raw, item.index) for item in log_layout.analyzed_lines(content))
        matched_here = set()
        blocks_seen = set()
        reads = _block_reads(compiled_patterns, match_type, only_entry_types)
        for line_number, raw_line, index in walk:
            if time.monotonic() > deadline:
                timed_out = True
                break
            if block_rule:
                block, members = view.block_at(index, reads)
                if members[0] in blocks_seen:
                    continue
                blocks_seen.add(members[0])
                line = block.text
                if line in matched_here:
                    line_hits += 1
                    continue
                if not any(_match_block(p, match_type, block) for p in compiled_patterns):
                    continue
                if not entry_types_allow(only_entry_types, block.entry_types):
                    continue
            else:
                # Normalised exactly as build_rule_test_results does, so the lines
                # handed back to it produce the same verdicts the scan found.
                line = raw_line.strip() if strip else raw_line
                if not line.strip():
                    continue
                if line in matched_here:
                    line_hits += 1
                    continue
                features = view.inputs.features[index] if view is not None and reads_features else None
                if not any(_match_line(p, match_type, line, features)['matched'] for p in compiled_patterns):
                    continue
                if only_entry_types and features is None and view is not None:
                    features = view.inputs.features[index]
                if not _line_types_allow(only_entry_types, line, features):
                    continue
            check = line_check(upload_id, index) if line_check is not None else 'hold'
            if check == 'fail':
                continue
            if check == 'unchecked':
                unchecked_logs.add(upload_id)

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
                if view is not None and not block_rule:
                    # A line read in its log view (Spor): its features and
                    # block there, so the verdict rebuilt from the line alone
                    # (build_rule_test_results `line_inputs`) agrees with the scan.
                    _block, members = view.block_at(index, 'text')
                    entry['line_inputs'] = (
                        view.inputs.features[index], [view.inputs.walked[member].text for member in members],
                    )
            matched_here.add(line)
            line_hits += 1
            entry['log_count'] += 1
            if len(entry['logs']) < LOG_REFS_PER_LINE:
                ref = {'upload_id': upload_id, 'line_number': line_number}
                if check == 'unchecked':
                    ref['conditions'] = 'unchecked'
                entry['logs'].append(ref)

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
        'conditions_unchecked_logs': len(unchecked_logs),
    }


def scan_logs_for_wholelog_matches(patterns: list, match_type: str, logs, *, deadline: float,
                                   line_check=None) -> dict:
    """Run a whole-log alert rule over stored logs and list the ones it fires on.
    ``line_check`` (see scan_logs_for_rule_matches, index None: the whole log)
    leaves out the logs where the rule's conditions fail."""
    matched_logs = []
    logs_scanned = 0
    timed_out = False
    script_error = None
    unchecked_logs = 0

    for upload_id, content in logs:
        if time.monotonic() > deadline:
            timed_out = True
            break
        logs_scanned += 1
        result = build_wholelog_rule_test_result(patterns, match_type, content)
        if result.get('script_error') and script_error is None:
            script_error = result['script_error']
        if result['matched']:
            check = line_check(upload_id, None) if line_check is not None else 'hold'
            if check == 'fail':
                continue
            entry = {'upload_id': upload_id, 'match_count': len(result['match_ranges'] or [])}
            if check == 'unchecked':
                entry['conditions'] = 'unchecked'
                unchecked_logs += 1
            matched_logs.append(entry)

    return {
        'whole_log': True,
        'logs': matched_logs,
        'logs_scanned': logs_scanned,
        'logs_matched': len(matched_logs),
        'timed_out': timed_out,
        'script_error': script_error,
        'conditions_unchecked_logs': unchecked_logs,
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
    return dominant_status(status for priority, status in entries if priority == top)


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
    # A block rule's text spans lines: its first line stands for it.
    if match_type == 'substring':
        literals = [pattern.split('\n', 1)[0] for pattern in patterns if pattern]
    elif match_type == 'exact':
        literals = [pattern.split('\n', 1)[0].strip() for pattern in patterns if pattern.strip()]
    else:
        return None
    literals = [literal for literal in literals if literal.strip()]
    return literals or None


def compare_rule_scans(new_rule: dict, old_rule: dict, logs, *, deadline: float, sample_lines: int,
                       log_type_for=None) -> dict:
    """Which distinct lines a candidate rule and an existing rule match, in one pass over `logs`.

    Each rule is ``{'patterns', 'status', 'match_type'}`` and optionally
    ``only_entry_types`` and ``match_unit`` (see build_rule_test_results); a
    block rule matches every line of a block it matches. Returns the counts of
    distinct lines only the new rule matches, only the old one, or both, with a
    sample of each one-sided kind (most widespread first): whether a new rule
    covers everything an old per-case rule caught, and what else it catches.
    """
    sides = []
    for rule in (new_rule, old_rule):
        unit = rule.get('match_unit') or _LINE
        sides.append({
            'compiled': [_compile_pattern(p, rule['status'], rule['match_type'], unit) for p in rule['patterns']],
            'match_type': rule['match_type'],
            'strip': rule['match_type'] in ('exact', 'parsed', 'filepath'),
            'only_entry_types': rule.get('only_entry_types') or [],
            'block': unit == _BLOCK,
        })
    any_block = any(side['block'] for side in sides)

    def side_hits(side, line, features_of, block):
        """`features_of()`: the line's features in its log view (None without one)."""
        if side['block']:
            return block is not None and any(
                _match_block(p, side['match_type'], block) for p in side['compiled']
            ) and entry_types_allow(side['only_entry_types'], block.entry_types)
        features = features_of() if side['match_type'] in _FEATURE_MATCH_TYPES else None
        if not any(_match_line(p, side['match_type'], line, features)['matched'] for p in side['compiled']):
            return False
        if side['only_entry_types'] and features is None:
            features = features_of()
        return _line_types_allow(side['only_entry_types'], line, features)

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
        counted_here = set()   # (kind, key): a line counts once per log
        log_type = log_type_for(upload_id) if log_type_for is not None else None
        view = _LogView(content, log_type, any_block) if any_block or _is_spor(log_type) else None
        if view is not None:
            walk = ((line_no, raw, index) for index, line_no, raw, _text, _features in view.lines())
        else:
            walk = ((number, raw, None) for number, raw in enumerate(content.splitlines(), start=1))
        for line_number, raw_line, index in walk:
            if time.monotonic() > deadline:
                timed_out = True
                break
            if not raw_line.strip() or (raw_line in tested_here and not any_block):
                continue
            tested_here.add(raw_line)
            def features_of(index=index):
                return view.inputs.features[index] if view is not None else None
            block = view.block_at(index)[0] if any_block else None
            hits = []
            for side, may in zip(sides, may_match):
                line = raw_line.strip() if side['strip'] else raw_line
                hits.append(may and side_hits(side, line, features_of, block))
            if not any(hits):
                continue
            kind = 'both' if all(hits) else ('only_new' if hits[0] else 'only_old')
            key = raw_line.strip()
            seen[kind].add(key)
            if (kind, key) in counted_here:
                continue
            counted_here.add((kind, key))
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
