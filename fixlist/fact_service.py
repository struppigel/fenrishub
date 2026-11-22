"""Facts outside the analyzer: their names in served analyses, keeping the
rule bucket cache in step with what finds them, and the checks behind
editing and deleting them.

Not to be confused with tool_log_facts (text parsing of FRST Search,
Shortcut and Fixlog logs for correlations).
"""

import json

from django.db import IntegrityError, transaction

from .models import Fact, FactRule, FactTagSource, RuleCondition

DUPLICATE_CONDITIONS_ERROR = (
    'A rule with this status, match type, source text and the same conditions already exists.'
)


class ConditionSpec(tuple):
    """(fact_id, polarity, scope) of one condition."""
    __slots__ = ()

    def __new__(cls, fact_id, polarity, scope):
        return super().__new__(cls, (fact_id, polarity, scope))

    fact_id = property(lambda self: self[0])
    polarity = property(lambda self: self[1])
    scope = property(lambda self: self[2])


def condition_key_for(specs) -> str:
    """The fixed text form of a set of conditions: "r12l,f7b" (polarity,
    fact id, scope), sorted; '' for none. ClassificationRule.condition_key."""
    return ','.join(sorted(f'{spec.polarity[0]}{spec.fact_id}{spec.scope[0]}' for spec in specs))


def conditions_from_payload(raw):
    """(specs, error) from the rule editor's JSON list of conditions:
    [{fact_id, polarity, scope}]. Validates shape and values, not the rule."""
    try:
        items = json.loads(raw or '[]') if isinstance(raw, str) else raw
    except ValueError:
        return None, 'The conditions could not be read.'
    if not isinstance(items, list):
        return None, 'The conditions could not be read.'
    polarities = dict(RuleCondition.POLARITY_CHOICES)
    scopes = dict(RuleCondition.SCOPE_CHOICES)
    specs = []
    for item in items:
        if not isinstance(item, dict):
            return None, 'The conditions could not be read.'
        fact_id = item.get('fact_id')
        if isinstance(fact_id, str) and fact_id.isdigit():
            fact_id = int(fact_id)
        if not isinstance(fact_id, int) or isinstance(fact_id, bool):
            return None, 'Choose a fact for every condition.'
        polarity = item.get('polarity') or RuleCondition.POLARITY_REQUIRE
        scope = item.get('scope') or RuleCondition.SCOPE_LOG
        if polarity not in polarities or scope not in scopes:
            return None, 'Unknown polarity or scope in a condition.'
        specs.append(ConditionSpec(fact_id, polarity, scope))
    return specs, None


def conditions_error(specs, *, whole_log: bool) -> str | None:
    """Why a rule cannot have these conditions, or None."""
    if len(specs) > RuleCondition.MAX_PER_RULE:
        return f'A rule can have at most {RuleCondition.MAX_PER_RULE} conditions.'
    fact_ids = [spec.fact_id for spec in specs]
    if len(set(fact_ids)) != len(fact_ids):
        return 'A fact can be in only one condition of a rule.'
    if whole_log and any(spec.scope != RuleCondition.SCOPE_LOG for spec in specs):
        return 'A whole-log rule has no line: its conditions can only look anywhere in the log.'
    if fact_ids and Fact.objects.filter(pk__in=fact_ids).count() != len(set(fact_ids)):
        return 'A condition names a fact that no longer exists.'
    return None


def rule_condition_specs(rule):
    return [ConditionSpec(c.fact_id, c.polarity, c.scope) for c in rule.conditions.all()]


def set_rule_conditions(rule, specs):
    """Replace a saved rule's conditions and its condition_key.

    Raises ValueError(DUPLICATE_CONDITIONS_ERROR) when another rule of the
    owner already has the same identity with these conditions."""
    from .analyzer import invalidate_rule_buckets_cache

    key = condition_key_for(specs)
    try:
        with transaction.atomic():
            if rule.condition_key != key:
                rule.condition_key = key
                rule.save(update_fields=['condition_key', 'updated_at'])
            RuleCondition.objects.filter(rule=rule).delete()
            RuleCondition.objects.bulk_create([
                RuleCondition(rule=rule, fact_id=spec.fact_id, polarity=spec.polarity, scope=spec.scope)
                for spec in specs
            ])
    except IntegrityError:
        raise ValueError(DUPLICATE_CONDITIONS_ERROR) from None
    invalidate_rule_buckets_cache(None)


def attach_fact_info(payload):
    """The analysis payload with each found fact's name and description added
    (a shallow copy; the payload itself is not changed). The stored payload
    holds only fact ids, so a renamed fact shows its new name without
    re-analysis; a deleted one is left out."""
    if not isinstance(payload, dict):
        return payload
    found = payload.get('facts')
    if not found:
        return payload
    by_id = {
        fact.pk: fact
        for fact in Fact.objects.filter(pk__in=[item.get('id') for item in found if isinstance(item, dict)])
    }
    served = []
    for item in found:
        fact = by_id.get(item.get('id')) if isinstance(item, dict) else None
        if fact is None:
            continue
        served.append({**item, 'name': fact.name, 'description': fact.description})
    return {**payload, 'facts': served}


def invalidate_if_tags_referenced(tag_ids):
    """Rule tag membership changed for `tag_ids`. When a fact counts one of
    these tags, the rules feeding it changed, so drop the rule buckets.

    Needed because tags are put on rules with bulk_create, which sends no
    m2m_changed signal."""
    tag_ids = {tag_id for tag_id in (tag_ids or ()) if tag_id is not None}
    if not tag_ids:
        return False
    if not FactTagSource.objects.filter(tag_id__in=tag_ids).exists():
        return False
    from .analyzer import invalidate_rule_buckets_cache

    invalidate_rule_buckets_cache(None)
    return True


def facts_blocking_tag_delete(tag):
    """The facts whose tag sources use `tag` (FactTagSource.tag is PROTECT)."""
    return list(Fact.objects.filter(tag_sources__tag=tag).distinct().order_by('name'))


def fact_delete_error(fact, user):
    """Why `user` may not delete `fact`, or '' if they may.

    A fact can only go once no rule condition uses it; then its owner-less
    parts (tag sources) and its fact rules go with it, so the user must own
    all of those rules (superusers may delete any unused fact)."""
    if RuleCondition.objects.filter(fact=fact).exists():
        return 'Rules have conditions on this fact; remove those conditions first.'
    if user.is_superuser:
        return ''
    if FactRule.objects.filter(fact=fact).exclude(owner=user).exists():
        return 'Other helpers have fact rules for this fact; only they or a superuser can delete it.'
    return ''
