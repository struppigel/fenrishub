"""
Rule management utilities and helpers for classification rule operations.
"""

from django.contrib.auth.models import User
from django.db import transaction

from .analyzer import parse_rule_line, inspect_line_matches, VALID_STATUSES, _load_rule_buckets
from .models import ClassificationRule


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


def _rule_defaults_from_parsed(parsed: dict) -> dict:
    """Extract default values for ClassificationRule from parsed rule data."""
    return {
        'description': parsed['description'],
        'source_name': parsed['source_name'],
        'entry_type': parsed['entry_type'],
        'clsid': parsed['clsid'],
        'name': parsed['name'],
        'filepath': parsed['filepath'],
        'normalized_filepath': parsed['normalized_filepath'],
        'filename': parsed['filename'],
        'company': parsed['company'],
        'arguments': parsed['arguments'],
        'file_not_signed': parsed['file_not_signed'],
        'is_enabled': True,
    }


def _upsert_classification_rule(parsed: dict, owner: User) -> tuple[ClassificationRule, bool]:
    """Create or update a classification rule. Returns (rule, is_created)."""
    lookup = {
        'owner': owner,
        'status': parsed['status'],
        'match_type': parsed['match_type'],
        'source_text': parsed['source_text'],
    }
    defaults = _rule_defaults_from_parsed(parsed)
    return ClassificationRule.objects.update_or_create(**lookup, defaults=defaults)


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
            }
        )

    return normalized, invalid


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


def _build_pending_rule_preview(pending_changes: list[dict], username: str, owner: User) -> dict:
    """
    Build preview of pending rule changes including conflict detection.
    
    Returns: dict with manual_changes, rule_changes, contradictions, and summary.
    """
    manual_changes = []
    rule_changes = []
    override_conflicts = []
    overlap_conflicts = []

    create_count = 0
    update_count = 0

    buckets = _load_rule_buckets()
    user_rules_index = {
        (r.status, r.match_type, r.source_text): r
        for r in ClassificationRule.objects.filter(owner=owner)
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

        source_name = f'analyzer-review:{username}'
        parsed = parse_rule_line(line, status=new_status, source_name=source_name)
        if not parsed:
            continue

        key = (parsed['status'], parsed['match_type'], parsed['source_text'])
        existing_rule = user_rules_index.get(key)
        action = 'update' if existing_rule else 'create'
        if action == 'create':
            create_count += 1
        else:
            update_count += 1

        inspection = inspect_line_matches(line, buckets=buckets)
        dominant_existing = inspection['dominant_status']
        status_codes = inspection['status_codes']
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

        if dominant_existing not in ('?', new_status):
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

        if overlapping_matches:
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
                'source_text': parsed['source_text'],
                'description': parsed['description'],
                'existing_rule_id': existing_rule.id if existing_rule else None,
                'entry_type': parsed.get('entry_type', ''),
                'clsid': parsed.get('clsid', ''),
                'name': parsed.get('name', ''),
                'filepath': parsed.get('filepath', ''),
                'normalized_filepath': parsed.get('normalized_filepath', ''),
                'filename': parsed.get('filename', ''),
                'company': parsed.get('company', ''),
                'arguments': parsed.get('arguments', ''),
                'file_not_signed': parsed.get('file_not_signed', False),
            }
        )

    return {
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
) -> dict:
    """
    Persist selected pending rule changes to database.
    
    Applies conflict resolutions and creates/updates classification rules.
    
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

            parsed = parse_rule_line(change['line'], status=change['new_status'], source_name=source_name)
            if not parsed:
                skipped_changes += 1
                continue

            if change.get('description') is not None:
                parsed['description'] = change['description']

            _, is_created = _upsert_classification_rule(parsed, owner=owner)
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
