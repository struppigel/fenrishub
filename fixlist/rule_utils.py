"""
Rule management utilities and helpers for classification rule operations.
"""

from django.contrib.auth.models import User
from django.db import transaction

from .analyzer import (
    EMPTY_RULE_FIELDS, VALID_STATUSES, _load_rule_buckets, inspect_line_matches, parse_rule_for_line,
    parse_rule_line, rule_defaults, upsert_parsed_rule,
)
from .log_layout import normalize_block_text
from .log_types import default_rule_scope, normalize_log_type_selection, rule_scope_log_type, scope_payload
from .models import ClassificationRule, known_log_type_names
from .tagging import parse_tag_ids


# Conflict resolution action constants
CONFLICT_ACTION_UPDATE_EXISTING = 'update_existing_status'
CONFLICT_ACTION_KEEP_BOTH = 'keep_both'
CONFLICT_ACTION_KEEP_NEW_DISABLE_OTHER = 'keep_new_disable_other'
CONFLICT_ACTION_DISCARD_NEW = 'discard_new'

VALID_CONFLICT_ACTIONS = {
    CONFLICT_ACTION_UPDATE_EXISTING,
    CONFLICT_ACTION_KEEP_BOTH,
    CONFLICT_ACTION_KEEP_NEW_DISABLE_OTHER,
    CONFLICT_ACTION_DISCARD_NEW,
}


# Kept under its old name: tests import it from here.
_rule_defaults_from_parsed = rule_defaults


def _upsert_classification_rule(parsed: dict, owner: User) -> tuple[ClassificationRule, bool]:
    """Create or update a classification rule. Returns (rule, is_created)."""
    return upsert_parsed_rule(parsed, owner.pk)


def _pending_rule_scope(change: dict, match_type: str, existing_rule, log_type) -> tuple | None:
    """The `(all_log_types, log_types)` a pending change's rule ends up with.

    The review's picker wins (`log_scope`). A new rule gets its match type's
    default for the open log (`log_type`, see log_types.default_rule_scope). An
    existing scoped rule gains the open log's type, since the user classified
    the line in that log. None: an existing rule keeps its scope.
    """
    if change.get('log_scope') is not None:
        return change['log_scope']
    if existing_rule is None:
        return default_rule_scope(match_type, log_type, entry_type=change.get('entry_type', ''))
    context = rule_scope_log_type(log_type)
    if context and not existing_rule.all_log_types and context not in (existing_rule.log_types or []):
        return False, [*(existing_rule.log_types or []), context]
    return None


# The block a pending change's line is in (the analyzer sends it for Spor
# blocks): at most this many lines and characters.
MAX_BLOCK_LINES = 200
MAX_BLOCK_CHARS = 20000


def _clean_block_text(raw, line):
    """The block text of a pending change, normalized, or None when it is
    missing, too long, or does not hold the change's line."""
    if not isinstance(raw, str) or not raw.strip() or len(raw) > MAX_BLOCK_CHARS:
        return None
    text = normalize_block_text(raw)
    lines = text.split('\n')
    if len(lines) > MAX_BLOCK_LINES or line not in lines:
        return None
    return text


def _normalize_pending_changes(raw_changes) -> tuple[list[dict], list[dict]]:
    """
    Normalize pending rule changes from request data.
    
    Returns: (normalized_changes, invalid_changes)
    """
    normalized = []
    invalid = []

    if raw_changes is None:
        return normalized, invalid
    if not isinstance(raw_changes, list):
        return normalized, [{'index': None, 'error': 'Field "pending_changes" must be a list.'}]

    for index, raw in enumerate(raw_changes):
        if not isinstance(raw, dict):
            invalid.append({'index': index, 'error': 'Each pending change must be an object.'})
            continue

        line = raw.get('line', '')
        new_status = raw.get('new_status', '')
        original_status = raw.get('original_status', '')
        description = raw.get('description', None)
        # None: the review's picker never touched this change.
        tag_ids = raw.get('tag_ids')
        # None: the rule gets the default log type scope (see _pending_rule_scope).
        log_scope = None
        if raw.get('log_types') is not None:
            log_scope, scope_error = normalize_log_type_selection(raw.get('log_types'))
            if scope_error:
                invalid.append({'index': index, 'error': f'Field "log_types": {scope_error}.'})
                continue

        if not isinstance(line, str):
            invalid.append({'index': index, 'error': 'Field "line" must be a string.'})
            continue
        if not isinstance(new_status, str):
            invalid.append({'index': index, 'error': 'Field "new_status" must be a string.'})
            continue
        if original_status and not isinstance(original_status, str):
            invalid.append({'index': index, 'error': 'Field "original_status" must be a string when provided.'})
            continue
        if description is not None and not isinstance(description, str):
            invalid.append({'index': index, 'error': 'Field "description" must be a string when provided.'})
            continue
        if tag_ids is not None and (not isinstance(tag_ids, list) or any(
            isinstance(value, bool) or not isinstance(value, int) for value in tag_ids
        )):
            invalid.append({'index': index, 'error': 'Field "tag_ids" must be a list of integers when provided.'})
            continue

        line = line.strip()
        new_status = new_status.strip()
        original_status = (original_status or '').strip() or '?'
        description = description if description is None else description.strip()

        if not line:
            invalid.append({'index': index, 'error': 'Field "line" cannot be empty.'})
            continue
        if new_status not in VALID_STATUSES:
            invalid.append({'index': index, 'error': f'Invalid status: {new_status}'})
            continue
        if new_status == ClassificationRule.STATUS_INFO:
            invalid.append({'index': index, 'error': 'Informational status cannot be set from analyzer overrides.'})
            continue

        normalized.append(
            {
                'id': str(raw.get('id', index)),
                'line': line,
                'original_status': original_status,
                'new_status': new_status,
                'order': int(raw.get('order', index)) if isinstance(raw.get('order', index), int) else index,
                'description': description,
                'tag_ids': tag_ids,
                'log_scope': log_scope,
                'block_text': _clean_block_text(raw.get('block_text'), line),
            }
        )

    return normalized, invalid


def _parse_pending_change(change, source_name, log_type):
    """The rule a pending change becomes (analyzer.parse_rule_for_line): a
    Spor block's parsed block rule, or the line's rule."""
    parsed = parse_rule_for_line(
        change['line'], change['new_status'], source_name, log_type=log_type, block_text=change.get('block_text'),
    )
    if parsed:
        change['entry_type'] = parsed.get('entry_type', '')
    return parsed


def _normalize_conflict_resolutions(raw_resolutions) -> list[dict]:
    """Normalize conflict resolution directives from request data."""
    normalized = []
    if raw_resolutions is None or not isinstance(raw_resolutions, list):
        return normalized

    for raw in raw_resolutions:
        if not isinstance(raw, dict):
            continue

        action = str(raw.get('action', '')).strip().lower()
        change_id = str(raw.get('change_id', '')).strip()
        contradiction_type = str(raw.get('contradiction_type', '')).strip().lower()
        conflict_key = str(raw.get('conflict_key', '')).strip()
        existing_rule_id = raw.get('existing_rule_id', None)

        if action not in VALID_CONFLICT_ACTIONS or not change_id:
            continue

        parsed_rule_id = None
        if isinstance(existing_rule_id, int):
            parsed_rule_id = existing_rule_id
        elif isinstance(existing_rule_id, str) and existing_rule_id.strip().isdigit():
            parsed_rule_id = int(existing_rule_id.strip())

        normalized.append(
            {
                'action': action,
                'change_id': change_id,
                'contradiction_type': contradiction_type,
                'existing_rule_id': parsed_rule_id,
                'conflict_key': conflict_key,
            }
        )

    return normalized


def _apply_conflict_resolutions(
    normalized_changes: list[dict],
    selected_ids: set[str],
    conflict_resolutions: list[dict],
    owner: User,
) -> set[str]:
    """
    Apply conflict resolution directives to pending changes.
    
    Returns: set of effective selected change IDs after applying conflict resolutions.
    """
    selected_change_map = {
        change['id']: change
        for change in normalized_changes
        if change['id'] in selected_ids
    }
    discarded_change_ids = {
        resolution['change_id']
        for resolution in conflict_resolutions
        if resolution['action'] in {CONFLICT_ACTION_DISCARD_NEW, CONFLICT_ACTION_UPDATE_EXISTING}
        and resolution['change_id'] in selected_change_map
    }
    effective_selected_ids = {
        change_id
        for change_id in selected_ids
        if change_id not in discarded_change_ids
    }

    for resolution in conflict_resolutions:
        change_id = resolution['change_id']
        if change_id not in selected_change_map:
            continue

        existing_rule_id = resolution['existing_rule_id']
        if existing_rule_id is None:
            continue

        existing_rule = ClassificationRule.objects.filter(pk=existing_rule_id, owner=owner).first()
        if not existing_rule:
            continue

        action = resolution['action']
        if action == CONFLICT_ACTION_UPDATE_EXISTING:
            target_change = selected_change_map.get(change_id)
            if not target_change:
                continue

            target_status = target_change['new_status']
            duplicate_rule = (
                ClassificationRule.objects.filter(
                    owner=owner,
                    status=target_status,
                    match_type=existing_rule.match_type,
                    source_text=existing_rule.source_text,
                    # Its twin: a rule with other conditions (or of the other
                    # match unit) is another rule.
                    condition_key=existing_rule.condition_key,
                    match_unit=existing_rule.match_unit,
                )
                .exclude(pk=existing_rule.pk)
                .first()
            )

            if duplicate_rule:
                if not duplicate_rule.is_enabled:
                    duplicate_rule.is_enabled = True
                    duplicate_rule.save(update_fields=['is_enabled', 'updated_at'])
                if existing_rule.is_enabled:
                    existing_rule.is_enabled = False
                    existing_rule.save(update_fields=['is_enabled', 'updated_at'])
                continue

            update_fields = []
            if existing_rule.status != target_status:
                existing_rule.status = target_status
                update_fields.append('status')
            if not existing_rule.is_enabled:
                existing_rule.is_enabled = True
                update_fields.append('is_enabled')
            if update_fields:
                update_fields.append('updated_at')
                existing_rule.save(update_fields=update_fields)
            continue

        if change_id not in effective_selected_ids:
            continue

        if action == CONFLICT_ACTION_KEEP_NEW_DISABLE_OTHER:
            if existing_rule.is_enabled:
                existing_rule.is_enabled = False
                existing_rule.save(update_fields=['is_enabled', 'updated_at'])
            continue

    return effective_selected_ids


def _build_pending_rule_preview(
    pending_changes: list[dict], username: str, owner: User, log_type: str | None = None,
) -> dict:
    """
    Build preview of pending rule changes including conflict detection.

    `log_type` is the type of the log the changes were made in: conflicts are
    looked up among the rules that apply to it, and it decides the default log
    type scope of each candidate.

    Returns: dict with manual_changes, rule_changes, contradictions, summary,
    and the log types a candidate's scope can be picked from.
    """
    manual_changes = []
    rule_changes = []
    override_conflicts = []
    overlap_conflicts = []

    create_count = 0
    update_count = 0

    buckets = _load_rule_buckets(log_type=log_type)
    # The review saves rules without conditions (upsert_parsed_rule), so only
    # those can be the rule a change updates.
    user_rules_index = {
        (r.status, r.match_type, r.source_text, r.match_unit): r
        for r in ClassificationRule.objects.filter(owner=owner, condition_key='', whole_log=False)
    }

    for change in sorted(pending_changes, key=lambda item: item['order']):
        line = change['line']
        new_status = change['new_status']
        original_status = change['original_status']

        manual_changes.append(
            {
                'id': change['id'],
                'line': line,
                'original_status': original_status,
                'new_status': new_status,
            }
        )

        # Unknown (?) is the absence of a classification, not a meaningful one.
        # A rule with status '?' would have no effect, so skip it.
        if new_status == ClassificationRule.STATUS_UNKNOWN:
            continue

        source_name = f'analyzer-review:{username}'
        parsed = _parse_pending_change(change, source_name, log_type)
        if not parsed:
            continue

        key = (parsed['status'], parsed['match_type'], parsed['source_text'], parsed['match_unit'])
        existing_rule = user_rules_index.get(key)
        action = 'update' if existing_rule else 'create'
        if action == 'create':
            create_count += 1
        else:
            update_count += 1

        block_text = change.get('block_text')
        inspection = inspect_line_matches(
            line, buckets=buckets, log_type=log_type, block_lines=block_text.split('\n') if block_text else None,
        )
        scope = _pending_rule_scope(change, parsed['match_type'], existing_rule, log_type)
        if scope is None:
            scope = (existing_rule.all_log_types, existing_rule.log_types)
        dominant_existing = inspection['dominant_status']
        status_codes = inspection['status_codes']
        existing_top_priority = inspection.get('effective_priority')
        new_priority = (
            existing_rule.priority
            if existing_rule
            else ClassificationRule.default_priority_for(parsed['match_type'])
        )

        # If the new rule's priority strictly exceeds every existing match's priority,
        # it shadows all of them and there is nothing for the user to resolve.
        new_rule_shadows_existing = (
            existing_top_priority is not None and new_priority > existing_top_priority
        )

        dominant_matching_rules = [
            match
            for match in inspection['matches']
            if match['status'] == dominant_existing and match['status'] != new_status
        ]
        overlapping_matches = [
            match
            for match in inspection['matches']
            if match['status'] != new_status and match['status'] != dominant_existing
        ]

        if not new_rule_shadows_existing and dominant_existing not in ('?', new_status):
            override_conflicts.append(
                {
                    'id': change['id'],
                    'line': line,
                    'selected_status': new_status,
                    'existing_dominant_status': dominant_existing,
                    'existing_status_codes': status_codes,
                    'matching_rules': dominant_matching_rules,
                }
            )

        if not new_rule_shadows_existing and overlapping_matches:
            overlap_conflicts.append(
                {
                    'id': change['id'],
                    'line': line,
                    'selected_status': new_status,
                    'overlap_statuses': sorted({match['status'] for match in overlapping_matches}),
                    'matching_rules': overlapping_matches,
                }
            )

        rule_changes.append(
            {
                'id': change['id'],
                'line': line,
                'from_status': original_status,
                'to_status': new_status,
                'action': action,
                'match_type': parsed['match_type'],
                'priority': new_priority,
                'source_text': parsed['source_text'],
                'description': parsed['description'],
                'existing_rule_id': existing_rule.id if existing_rule else None,
                'log_types': scope_payload(*scope),
                'match_unit': parsed['match_unit'],
                'block_text': block_text,
                **{field: parsed.get(field, empty) for field, empty in EMPTY_RULE_FIELDS.items()},
            }
        )

    log_type_choices = known_log_type_names()
    context = rule_scope_log_type(log_type)
    if context and context not in log_type_choices:
        log_type_choices.append(context)
    return {
        'log_type': context,
        'log_type_choices': log_type_choices,
        'manual_changes': manual_changes,
        'rule_changes': rule_changes,
        'contradictions': {
            'override_vs_existing_dominant': override_conflicts,
            'overlaps_other_status_rules': overlap_conflicts,
        },
        'summary': {
            'pending_changes': len(manual_changes),
            'rule_candidates': len(rule_changes),
            'create_candidates': create_count,
            'update_candidates': update_count,
            'override_conflicts': len(override_conflicts),
            'overlap_conflicts': len(overlap_conflicts),
        },
    }


def _persist_selected_pending_rules(
    *,
    raw_pending_changes,
    raw_selected_ids,
    raw_conflict_resolutions,
    username: str,
    source_prefix: str,
    owner: User,
    log_type: str | None = None,
) -> dict:
    """
    Persist selected pending rule changes to database.

    Applies conflict resolutions and creates/updates classification rules.
    `log_type` is the type of the log the changes were made in (see
    _pending_rule_scope).
    
    Returns: dict with created/updated/skipped rule counts and change summaries.
    """
    selected_ids = {
        str(value)
        for value in (raw_selected_ids if isinstance(raw_selected_ids, list) else [])
    }
    normalized_changes, invalid_changes = _normalize_pending_changes(raw_pending_changes)
    conflict_resolutions = _normalize_conflict_resolutions(raw_conflict_resolutions)

    created_rules = 0
    updated_rules = 0
    skipped_changes = 0

    with transaction.atomic():
        effective_selected_ids = _apply_conflict_resolutions(
            normalized_changes,
            selected_ids,
            conflict_resolutions,
            owner,
        )

        source_name = f'{source_prefix}:{username}'
        for change in normalized_changes:
            if change['id'] not in effective_selected_ids:
                continue

            # Skip "Unknown" rule candidates — they would have no classification effect.
            if change['new_status'] == ClassificationRule.STATUS_UNKNOWN:
                skipped_changes += 1
                continue

            parsed = _parse_pending_change(change, source_name, log_type)
            if not parsed:
                skipped_changes += 1
                continue

            if change.get('description') is not None:
                parsed['description'] = change['description']

            rule, is_created = upsert_parsed_rule(
                parsed, owner.pk,
                log_scope=_pending_rule_scope(change, parsed['match_type'], None, log_type),
            )
            if not is_created:
                scope = _pending_rule_scope(change, parsed['match_type'], rule, log_type)
                if scope is not None and (rule.all_log_types, rule.log_types) != (scope[0], list(scope[1])):
                    rule.all_log_types, rule.log_types = scope[0], list(scope[1])
                    rule.save(update_fields=['all_log_types', 'log_types', 'updated_at'])
            # The review's picker shows auto tags filled in, so a new rule gets
            # exactly its tags (a removed auto tag stays off). An existing rule
            # only gains them and keeps the tags it already had.
            if change.get('tag_ids') is not None:
                tag_ids = parse_tag_ids(change['tag_ids'])
                if is_created:
                    rule.tags.set(tag_ids)
                elif tag_ids:
                    rule.tags.add(*tag_ids)
            if is_created:
                created_rules += 1
            else:
                updated_rules += 1

    return {
        'created_rules': created_rules,
        'updated_rules': updated_rules,
        'skipped_changes': skipped_changes,
        'invalid_changes_count': len(invalid_changes),
        'selected_candidates': len(selected_ids),
        'effective_selected_candidates': len(
            [change for change in normalized_changes if change['id'] in effective_selected_ids]
        ),
    }
