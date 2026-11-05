"""Rule tags: shared labels for groups of rules - a family, a source, a vendor.

A tag's conditions decide which rules it matches; every condition that is set
must hold:

- regex (`match_pattern`), searched case-insensitively in the rule's
  description, its source line, or either (`match_scope`);
- exclude regex (`exclude_pattern`), same scope, which must NOT match;
- statuses (`match_statuses`), the rule's own status;
- entry types (`match_entry_types`), the rule's parsed entry type.

A tag with no regex, statuses or entry types matches nothing and is applied
by hand only. Matching feeds the bulk preview in the tag editor, where the
analyst unticks false positives before applying, the suggestions on the rule
forms, and the pending and unmatched counts. Only a tag with `auto_apply`
tags rules by itself, and only new rules or rules whose matched fields change
(see auto_tag_rules). Adding a tag by hand is never restricted.

Conditions run over every rule on each preview and count, so only regexes the
linear-time re2 engine accepts are allowed, and nothing the slow-pattern
benchmark flags.

Built-in tags stand for the analyzer's hardcoded log warnings: besides being
ordinary tags (on rules, with conditions, applied automatically), they are
"found" in a log whenever their warning fires. They cannot be deleted.
"""

import re
from collections import Counter
from dataclasses import dataclass

from .analyzer import ANALYSIS_PAYLOAD_FORMAT, _re2, evaluate_regex_pattern
from django.db.models import F, Q

from .models import (
    TAG_CATEGORY_COLOR_RE, ClassificationRule, FixlistSnippet, RuleTag, Speech, TagCategory, UploadedLog,
    UploadedLogAnalysis,
)
from .rule_sets import SHARED_RULE_SET_KEY

TAG_NAME_RE = re.compile(r'^\w[\w .+&-]*$')
ENTRY_TYPE_RE = re.compile(r'^[a-z_]{1,64}$')
PATTERN_MAX_LENGTH = 1000
DESCRIPTION_MAX_LENGTH = 5000

# Statuses a tag condition may name: every assignable status plus alert.
CONDITION_STATUSES = [code for code, _label in ClassificationRule.CREATABLE_STATUS_CHOICES]
SCOPES = [code for code, _label in RuleTag.SCOPE_CHOICES]

# Caps what a preview sends back per group; conditions matching more than this
# are almost certainly too broad, and the page says so instead of rendering it all.
PREVIEW_GROUP_LIMIT = 2000

# The hardcoded warnings of analyzer._build_log_warnings, each a built-in tag.
# Migration 0079 seeds them from a frozen copy of this list.
BUILTIN_TAGS = [
    ('incomplete_logs', 'incomplete logs', 'The FRST or Addition log is cut off before its end marker.'),
    ('low_memory', 'low memory', 'Little RAM, high RAM usage or little free space on the Windows drive.'),
    ('multiple_enabled_av', 'multiple enabled AVs', 'More than one antivirus product is enabled.'),
    ('recent_restore_operation', 'recent system restore', 'A system restore was run recently.'),
    ('recent_os_install', 'recent Windows install', 'Windows was installed or feature-updated recently.'),
]

_compiled_cache = {}


def compile_pattern(pattern):
    """Compile a tag regex for case-insensitive search, or None if it is empty or invalid."""
    if not pattern:
        return None
    cached = _compiled_cache.get(pattern)
    if cached is not None:
        return cached
    try:
        if _re2 is not None:
            compiled = _re2.compile(f'(?i){pattern}')
        else:
            compiled = re.compile(pattern, re.IGNORECASE)
    except Exception:
        return None
    if len(_compiled_cache) > 500:
        _compiled_cache.clear()
    _compiled_cache[pattern] = compiled
    return compiled


def pattern_error(pattern, label='Regex'):
    """Return why a tag regex cannot be stored, or None if it is fine."""
    if not pattern:
        return None
    if len(pattern) > PATTERN_MAX_LENGTH:
        return f'{label} must be at most {PATTERN_MAX_LENGTH} characters.'
    evaluation = evaluate_regex_pattern(pattern)
    if evaluation['stdlib_error']:
        return f'Invalid {label.lower()}: {evaluation["stdlib_error"]}'
    if _re2 is not None and not evaluation['re2_ok']:
        return (
            f'{label} uses a feature the fast regex engine does not support '
            '(lookarounds and backreferences are not allowed).'
        )
    if evaluation['is_slow']:
        return f'{label} is too slow on adversarial input; simplify it.'
    compiled = compile_pattern(pattern)
    if compiled is None:
        return f'Invalid {label.lower()}.'
    if compiled.search(''):
        return f'{label} matches empty text, so it would match every rule.'
    return None


@dataclass(frozen=True)
class TagConditions:
    """What a rule must meet to match a tag. Built from a saved tag or from the
    tag editor's unsaved fields, so the preview and the save agree."""

    pattern: str = ''
    exclude_pattern: str = ''
    scope: str = RuleTag.SCOPE_ANY
    statuses: tuple = ()
    entry_types: tuple = ()

    @classmethod
    def of(cls, tag):
        return cls(
            pattern=tag.match_pattern or '',
            exclude_pattern=tag.exclude_pattern or '',
            scope=tag.match_scope or RuleTag.SCOPE_ANY,
            statuses=tuple(tag.match_statuses or ()),
            entry_types=tuple(tag.match_entry_types or ()),
        )

    @property
    def is_empty(self):
        """No regex, statuses or entry types: matches nothing. An exclude regex
        alone narrows nothing down, so it does not count."""
        return not (self.pattern or self.statuses or self.entry_types)

    def _texts(self, description, source_text):
        if self.scope == RuleTag.SCOPE_SOURCE:
            return [('source_text', source_text or '')]
        if self.scope == RuleTag.SCOPE_ANY:
            return [('description', description or ''), ('source_text', source_text or '')]
        return [('description', description or '')]

    def match(self, *, description, source_text, status, entry_type):
        """(matched, field, span): `field`/`span` locate the regex hit for highlighting."""
        if self.is_empty:
            return False, None, None
        if self.statuses and status not in self.statuses:
            return False, None, None
        if self.entry_types and (entry_type or '') not in self.entry_types:
            return False, None, None
        texts = self._texts(description, source_text)
        if self.exclude_pattern:
            exclude = compile_pattern(self.exclude_pattern)
            if exclude is not None and any(exclude.search(text) for _field, text in texts):
                return False, None, None
        if not self.pattern:
            return True, None, None
        compiled = compile_pattern(self.pattern)
        if compiled is None:
            return False, None, None
        for field, text in texts:
            hit = compiled.search(text)
            if hit is not None:
                return True, field, [hit.start(), hit.end()]
        return False, None, None

    def matches_rule(self, rule):
        return self.match(
            description=rule.description, source_text=rule.source_text,
            status=rule.status, entry_type=rule.entry_type,
        )[0]


def describe_conditions(conditions):
    """A short reading of the conditions for the tag list, e.g.
    'status P, installed software, regex "renpy" in source line'."""
    if conditions.is_empty:
        return 'no conditions - added by hand only'
    parts = []
    if conditions.statuses:
        parts.append('status ' + ' or '.join(conditions.statuses))
    if conditions.entry_types:
        parts.append(' or '.join(value.replace('_', ' ') for value in conditions.entry_types))
    scope = dict(RuleTag.SCOPE_CHOICES).get(conditions.scope, conditions.scope)
    if conditions.pattern:
        parts.append(f'regex "{conditions.pattern}" in {scope}')
    if conditions.exclude_pattern:
        parts.append(f'not "{conditions.exclude_pattern}" in {scope}')
    return ', '.join(parts)


def conditions_error(conditions):
    """Return why a set of tag conditions cannot be stored, or None."""
    if conditions.scope not in SCOPES:
        return 'Invalid regex scope.'
    bad_statuses = [status for status in conditions.statuses if status not in CONDITION_STATUSES]
    if bad_statuses:
        return f'Invalid status: {", ".join(bad_statuses)}.'
    if any(not isinstance(value, str) or not ENTRY_TYPE_RE.match(value) for value in conditions.entry_types):
        return 'Invalid entry type.'
    return pattern_error(conditions.pattern) or pattern_error(conditions.exclude_pattern, 'Exclude regex')


def tag_fields_error(name, conditions, description, exclude_pk=None):
    """Return an error message for invalid tag fields, or None.

    Shared by the tag editor and the JSON API so both accept the same tags.
    `conditions` may also be a bare regex string, meaning a description regex.
    """
    if isinstance(conditions, str):
        conditions = TagConditions(pattern=conditions)
    if not name:
        return 'Tag name is required.'
    if len(name) > RuleTag.NAME_MAX_LENGTH:
        return f'Tag name must be at most {RuleTag.NAME_MAX_LENGTH} characters.'
    if not TAG_NAME_RE.match(name):
        return 'Tag name may contain letters, digits, spaces and . + & - _ only.'
    if len(description) > DESCRIPTION_MAX_LENGTH:
        return f'Description must be at most {DESCRIPTION_MAX_LENGTH} characters.'
    duplicates = RuleTag.objects.filter(name__iexact=name)
    if exclude_pk is not None:
        duplicates = duplicates.exclude(pk=exclude_pk)
    if duplicates.exists():
        return f'A tag named "{name}" already exists.'
    return conditions_error(conditions)


def tag_category_error(name, color, exclude_pk=None):
    """Return an error message for invalid tag category fields, or None."""
    if not name:
        return 'Category name is required.'
    if len(name) > TagCategory.NAME_MAX_LENGTH:
        return f'Category name must be at most {TagCategory.NAME_MAX_LENGTH} characters.'
    if not TAG_NAME_RE.match(name):
        return 'Category name may contain letters, digits, spaces and . + & - _ only.'
    if not TAG_CATEGORY_COLOR_RE.match(color or ''):
        return 'Color must be a 6-digit hex like #aabbcc.'
    duplicates = TagCategory.objects.filter(name__iexact=name)
    if exclude_pk is not None:
        duplicates = duplicates.exclude(pk=exclude_pk)
    if duplicates.exists():
        return f'A category named "{name}" already exists.'
    return None


def parse_tag_category_priority(raw, current):
    """``(priority, error)`` from a posted priority; blank keeps `current`."""
    raw = (raw or '').strip()
    if not raw:
        return current, None
    try:
        priority = int(raw)
    except ValueError:
        priority = None
    if priority is None or not TagCategory.PRIORITY_MIN <= priority <= TagCategory.PRIORITY_MAX:
        return None, (
            f'Priority must be a whole number from {TagCategory.PRIORITY_MIN} to {TagCategory.PRIORITY_MAX}.'
        )
    return priority, None


_RULE_FIELDS = ('pk', 'status', 'entry_type', 'match_type', 'source_text', 'description', 'owner__username')


def preview_conditions(conditions, tag=None):
    """Sort every rule into the groups the tag editor shows.

    - new: matches the conditions, does not carry the tag yet
    - tagged: matches and already carries the tag
    - stale: carries the tag but no longer matches

    `suggested_description` is the most common description among the matches,
    offered as a starting point for the tag's own description.
    """
    tagged_ids = set(tag.rules.values_list('pk', flat=True)) if tag is not None else set()

    groups = {'new': [], 'tagged': [], 'stale': []}
    counts = {'new': 0, 'tagged': 0, 'stale': 0}
    descriptions = Counter()
    matched_ids = set()

    if not conditions.is_empty:
        for row in ClassificationRule.objects.values(*_RULE_FIELDS).iterator():
            matched, field, span = conditions.match(
                description=row['description'], source_text=row['source_text'],
                status=row['status'], entry_type=row['entry_type'],
            )
            if not matched:
                continue
            matched_ids.add(row['pk'])
            if row['description'].strip():
                descriptions[row['description'].strip()] += 1
            key = 'tagged' if row['pk'] in tagged_ids else 'new'
            counts[key] += 1
            if len(groups[key]) < PREVIEW_GROUP_LIMIT:
                groups[key].append(_preview_row(row, field, span))

    stale_ids = tagged_ids - matched_ids
    if stale_ids:
        for row in ClassificationRule.objects.filter(pk__in=stale_ids).values(*_RULE_FIELDS):
            counts['stale'] += 1
            if len(groups['stale']) < PREVIEW_GROUP_LIMIT:
                groups['stale'].append(_preview_row(row, None, None))

    suggested = descriptions.most_common(1)[0][0] if descriptions else ''
    return {
        'groups': groups,
        'counts': counts,
        'limit': PREVIEW_GROUP_LIMIT,
        'suggested_description': suggested,
    }


def preview_pattern(pattern, tag=None):
    """preview_conditions for a plain description regex."""
    return preview_conditions(TagConditions(pattern=pattern), tag=tag)


def _preview_row(row, field, span):
    return {
        'id': row['pk'],
        'status': row['status'],
        'match_type': row['match_type'],
        'entry_type': row['entry_type'],
        'source_text': row['source_text'][:300],
        'description': row['description'],
        'owner': row['owner__username'],
        # Which text the regex hit, so the editor highlights the right one;
        # spans in the source line only count while it is shown uncut.
        'span_field': field if not (field == 'source_text' and span and span[1] > 300) else None,
        'span': span,
    }


def matching_rule_ids(conditions):
    """Every rule that meets `conditions`, for applying an auto tag to existing rules."""
    if conditions.is_empty:
        return []
    fields = ('pk', 'description', 'source_text', 'status', 'entry_type')
    return [
        row['pk']
        for row in ClassificationRule.objects.values(*fields).iterator()
        if conditions.match(
            description=row['description'], source_text=row['source_text'],
            status=row['status'], entry_type=row['entry_type'],
        )[0]
    ]


def unmatched_tagged_rule_ids(tag, conditions):
    """Every rule carrying `tag` that `conditions` do not match - all of them,
    not only the rows a capped preview showed."""
    return [
        rule.pk
        for rule in tag.rules.only('pk', 'description', 'source_text', 'status', 'entry_type')
        if not conditions.matches_rule(rule)
    ]


def apply_tag(tag, add_ids, remove_ids):
    """Add `tag` to the rules in `add_ids` and take it off those in `remove_ids`.

    Unknown ids are ignored. Returns (added, removed) counts of actual changes.
    """
    through = ClassificationRule.tags.through
    current = set(tag.rules.values_list('pk', flat=True))

    wanted = set(
        ClassificationRule.objects.filter(pk__in=add_ids).values_list('pk', flat=True)
    ) - current
    if wanted:
        through.objects.bulk_create(
            [through(classificationrule_id=pk, ruletag_id=tag.pk) for pk in wanted],
            ignore_conflicts=True,
        )

    unwanted = current & set(remove_ids)
    if unwanted:
        through.objects.filter(ruletag_id=tag.pk, classificationrule_id__in=unwanted).delete()
    return len(wanted), len(unwanted)


def auto_tag_rules(rules):
    """Add every auto-apply tag whose conditions a rule meets.

    Called for new rules and for rules whose matched fields changed: from the
    rule post_save signal, and explicitly after bulk_create, which sends none.
    Never removes a tag.
    """
    rules = [rule for rule in rules if rule.pk]
    if not rules:
        return
    auto_tags = [(tag.pk, TagConditions.of(tag)) for tag in RuleTag.objects.filter(auto_apply=True)]
    auto_tags = [(pk, conditions) for pk, conditions in auto_tags if not conditions.is_empty]
    if not auto_tags:
        return
    through = ClassificationRule.tags.through
    links = [
        through(classificationrule_id=rule.pk, ruletag_id=tag_pk)
        for rule in rules
        for tag_pk, conditions in auto_tags
        if conditions.matches_rule(rule)
    ]
    if links:
        through.objects.bulk_create(links, ignore_conflicts=True)


def tag_rule_counts(tags):
    """{tag pk: (pending, unmatched)} for the tag list.

    pending: rules meeting the conditions that lack the tag - it catches rules
    from paths that show no suggestions, so the backlog stays visible.
    unmatched: rules carrying the tag that no longer meet them.
    """
    conditions_by_pk = {tag.pk: TagConditions.of(tag) for tag in tags}
    active = {pk: conditions for pk, conditions in conditions_by_pk.items() if not conditions.is_empty}
    pending = {pk: 0 for pk in conditions_by_pk}
    unmatched = {pk: 0 for pk in conditions_by_pk}
    if not active:
        return {pk: (0, 0) for pk in conditions_by_pk}

    tagged = set(
        ClassificationRule.tags.through.objects.filter(
            ruletag_id__in=active.keys(),
        ).values_list('classificationrule_id', 'ruletag_id')
    )
    matched = set()
    fields = ('pk', 'description', 'source_text', 'status', 'entry_type')
    for row in ClassificationRule.objects.values(*fields).iterator():
        for tag_pk, conditions in active.items():
            if conditions.match(
                description=row['description'], source_text=row['source_text'],
                status=row['status'], entry_type=row['entry_type'],
            )[0]:
                matched.add((row['pk'], tag_pk))
                if (row['pk'], tag_pk) not in tagged:
                    pending[tag_pk] += 1
    for pair in tagged - matched:
        unmatched[pair[1]] += 1
    return {pk: (pending[pk], unmatched[pk]) for pk in conditions_by_pk}


def suggest_tags(*, description='', source_text='', status='', entry_type='', exclude_ids=()):
    """Tags whose conditions a rule with these fields meets, for the rule forms."""
    excluded = set(exclude_ids)
    suggestions = []
    for tag in RuleTag.objects.select_related('category'):
        if tag.pk in excluded:
            continue
        if TagConditions.of(tag).match(
            description=description, source_text=source_text, status=status, entry_type=entry_type,
        )[0]:
            suggestions.append(tag)
    return suggestions


def serialize_tag(tag):
    return {
        'id': tag.pk,
        'name': tag.name,
        'description': tag.description,
        'match_pattern': tag.match_pattern,
        'exclude_pattern': tag.exclude_pattern,
        'match_scope': tag.match_scope,
        'match_statuses': list(tag.match_statuses or []),
        'match_entry_types': list(tag.match_entry_types or []),
        'auto_apply': tag.auto_apply,
        'builtin': tag.builtin_code is not None,
        # The category sets the badge colour (see tag_category_class).
        'category_id': tag.category_id,
        'category': {'id': tag.category.pk, 'name': tag.category.name, 'color': tag.category.color},
    }


def conditions_from_payload(payload, tag=None):
    """(TagConditions, error) from a JSON body; absent fields keep the tag's values.

    A partial update keeps what it does not send, so the analyzer's popover can
    save a description without knowing the conditions.
    """
    base = TagConditions.of(tag) if tag is not None else TagConditions()
    values = {}
    for field, attr in (('match_pattern', 'pattern'), ('exclude_pattern', 'exclude_pattern'), ('match_scope', 'scope')):
        if field in payload:
            if not isinstance(payload[field], str):
                return None, f'Field "{field}" must be a string.'
            values[attr] = payload[field].strip()
        else:
            values[attr] = getattr(base, attr)
    for field, attr in (('match_statuses', 'statuses'), ('match_entry_types', 'entry_types')):
        if field in payload:
            raw = payload[field]
            if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
                return None, f'Field "{field}" must be a list of strings.'
            values[attr] = tuple(dict.fromkeys(item.strip() for item in raw if item.strip()))
        else:
            values[attr] = getattr(base, attr)
    return TagConditions(**values), None


def linkable_speeches(user):
    """The speeches a helper can link to a tag: their own and every speech they
    selected for the analyzer, shared ones by other helpers included.

    A link belongs to the speech, so linking someone else's shared speech makes
    it suggested for the tag for everyone who uses that speech.
    """
    return Speech.objects.filter(Q(owner=user) | Q(analyzer_users=user)).distinct()


def set_speech_links(tag, user, speech_ids):
    """Make exactly the linkable speeches in `speech_ids` suggest `tag`.

    Speeches the user cannot link (not theirs and not selected by them) keep
    their links untouched.
    """
    through = Speech.trigger_tags.through
    linkable_ids = set(linkable_speeches(user).values_list('pk', flat=True))
    wanted = linkable_ids & set(speech_ids)
    through.objects.filter(ruletag_id=tag.pk, speech_id__in=linkable_ids - wanted).delete()
    through.objects.bulk_create(
        [through(speech_id=pk, ruletag_id=tag.pk) for pk in wanted],
        ignore_conflicts=True,
    )


def linkable_snippets(user):
    """The snippets a helper can link to a tag: their own and every snippet they
    selected for the analyzer, shared ones by other helpers included.

    As with speeches, a link belongs to the snippet, so linking someone else's
    shared snippet makes it suggested for the tag for everyone who uses it.
    """
    return FixlistSnippet.objects.filter(Q(owner=user) | Q(analyzer_users=user)).distinct()


def set_snippet_links(tag, user, snippet_ids):
    """Make exactly the linkable snippets in `snippet_ids` suggest `tag`.

    Snippets the user cannot link (not theirs and not selected by them) keep
    their links untouched.
    """
    through = FixlistSnippet.trigger_tags.through
    linkable_ids = set(linkable_snippets(user).values_list('pk', flat=True))
    wanted = linkable_ids & set(snippet_ids)
    through.objects.filter(ruletag_id=tag.pk, fixlistsnippet_id__in=linkable_ids - wanted).delete()
    through.objects.bulk_create(
        [through(fixlistsnippet_id=pk, ruletag_id=tag.pk) for pk in wanted],
        ignore_conflicts=True,
    )


def save_tag(user, tag, payload):
    """Create (`tag` None) or update a tag from a JSON-style payload: (tag, error).

    The one place tag fields are validated and stored, shared by the tag editor
    and the token API. Payload fields: name, description, match_pattern,
    exclude_pattern, match_scope, match_statuses, match_entry_types, auto_apply,
    category_id (null for the default category), speech_ids, snippet_ids. Absent fields keep the tag's values. Applying the tag to rules
    is left to the caller.
    """
    for field in ('name', 'description'):
        if field in payload and not isinstance(payload[field], str):
            return None, f'Field "{field}" must be a string.'
    if 'auto_apply' in payload and not isinstance(payload['auto_apply'], bool):
        return None, 'Field "auto_apply" must be a boolean.'
    speech_ids = payload.get('speech_ids')
    if speech_ids is not None and (
        not isinstance(speech_ids, list)
        or any(isinstance(item, bool) or not isinstance(item, int) for item in speech_ids)
    ):
        return None, 'Field "speech_ids" must contain integers.'
    snippet_ids = payload.get('snippet_ids')
    if snippet_ids is not None and (
        not isinstance(snippet_ids, list)
        or any(isinstance(item, bool) or not isinstance(item, int) for item in snippet_ids)
    ):
        return None, 'Field "snippet_ids" must contain integers.'
    # Every tag has a category: null, or a new tag without one, means the default.
    if 'category_id' in payload:
        category_id = payload['category_id']
    else:
        category_id = tag.category_id if tag else None
    if category_id is None:
        category_id = TagCategory.get_default().pk
    elif isinstance(category_id, bool) or not isinstance(category_id, int):
        return None, 'Field "category_id" must be an integer or null.'
    elif not TagCategory.objects.filter(pk=category_id).exists():
        return None, 'That tag category does not exist.'

    conditions, message = conditions_from_payload(payload, tag)
    if message:
        return None, message
    name = payload.get('name', tag.name if tag else '').strip()
    description = payload.get('description', tag.description if tag else '').strip()
    auto_apply = payload.get('auto_apply', tag.auto_apply if tag else False)
    message = tag_fields_error(name, conditions, description, exclude_pk=tag.pk if tag else None)
    if message:
        return None, message
    if auto_apply and conditions.is_empty:
        return None, 'Applying automatically needs a condition: a regex, a status or an entry type.'

    if tag is None:
        tag = RuleTag(created_by=user)
    tag.name = name
    tag.description = description
    tag.match_pattern = conditions.pattern
    tag.exclude_pattern = conditions.exclude_pattern
    tag.match_scope = conditions.scope
    tag.match_statuses = list(conditions.statuses)
    tag.match_entry_types = list(conditions.entry_types)
    tag.auto_apply = auto_apply
    tag.category_id = category_id
    tag.updated_by = user
    tag.save()
    if speech_ids is not None:
        set_speech_links(tag, user, speech_ids)
    if snippet_ids is not None:
        set_snippet_links(tag, user, snippet_ids)
    return tag, None


def parse_tag_ids(values):
    """Ids of existing tags among `values` (strings or ints), in their given order."""
    ids = []
    for value in values or []:
        try:
            ids.append(int(value))
        except (TypeError, ValueError):
            continue
    existing = set(RuleTag.objects.filter(pk__in=ids).values_list('pk', flat=True))
    seen = set()
    result = []
    for pk in ids:
        if pk in existing and pk not in seen:
            seen.add(pk)
            result.append(pk)
    return result


def payload_rule_ids(payload):
    """Every rule id an analysis credits: lines' deciding rules, alert warnings', whole-log."""
    rule_ids = set(payload.get('wholelog_rule_ids') or [])
    for line in payload.get('lines') or []:
        rule_ids.update(line.get('rule_ids') or [])
    for warning in payload.get('warnings') or []:
        rule_ids.update(warning.get('rule_ids') or [])
    return rule_ids


def attach_rule_tags(payload):
    """Add the rule tags behind an analysis to its payload, in place.

    Each line gets `tag_ids` from its deciding `rule_ids`; each warning gets
    `tag_ids` from its alert rules' tags plus the built-in tag of its code; and
    the payload gets `rule_tags`: every tag found, with the number of lines it
    covers. Done when the analysis is served rather than when it is computed,
    so tagging a rule shows up at once without invalidating any cached analysis.
    """
    lines = payload.get('lines') or []
    warnings = payload.get('warnings') or []
    wholelog_rule_ids = payload.get('wholelog_rule_ids') or []
    rule_ids = payload_rule_ids(payload)

    tags_by_rule = {}
    if rule_ids:
        links = ClassificationRule.tags.through.objects.filter(
            classificationrule_id__in=rule_ids,
        ).values_list('classificationrule_id', 'ruletag_id')
        for rule_id, tag_id in links:
            tags_by_rule.setdefault(rule_id, []).append(tag_id)

    def tags_of(ids):
        return {tag_id for rule_id in ids or [] for tag_id in tags_by_rule.get(rule_id, [])}

    line_counts = Counter()
    for line in lines:
        tag_ids = sorted(tags_of(line.get('rule_ids')))
        line['tag_ids'] = tag_ids
        line_counts.update(tag_ids)

    builtin_by_code = dict(
        RuleTag.objects.filter(builtin_code__isnull=False).values_list('builtin_code', 'pk')
    )
    warning_tag_ids = set()
    for warning in warnings:
        tag_ids = tags_of(warning.get('rule_ids'))
        builtin = builtin_by_code.get(warning.get('code'))
        if builtin is not None:
            tag_ids.add(builtin)
        warning['tag_ids'] = sorted(tag_ids)
        warning_tag_ids.update(tag_ids)

    wholelog_tag_ids = tags_of(wholelog_rule_ids) | warning_tag_ids
    found = set(line_counts) | wholelog_tag_ids
    tags = RuleTag.objects.filter(pk__in=found) if found else []
    payload['rule_tags'] = sorted(
        (
            {
                'id': tag.pk,
                'name': tag.name,
                'description': tag.description,
                'line_count': line_counts.get(tag.pk, 0),
                'wholelog': tag.pk in wholelog_tag_ids,
                'builtin': tag.builtin_code is not None,
                'category_id': tag.category_id,
            }
            for tag in tags
        ),
        key=lambda entry: (-entry['line_count'], entry['name'].lower()),
    )
    return payload


def _fresh_analyses(candidates, rule_set_key):
    """Cached analyses of `candidates` under one rule set that are still usable.

    The same test as upload_utils.get_fresh_cached_analysis, done in the query:
    written for the upload's current content, in the current payload format.
    """
    return UploadedLogAnalysis.objects.filter(
        upload__in=candidates,
        rule_set_key=rule_set_key,
        source_content_hash=F('upload__content_hash'),
        payload__format=ANALYSIS_PAYLOAD_FORMAT,
    )


def logs_with_tags(tag_ids, rule_set_key, candidates):
    """The uploads among `candidates` that contain every tag in `tag_ids`.

    Returns ``(upload_pks, unanalyzed_count)``: the matching primary keys in
    the order of `candidates`, and how many analyzable candidates had no
    usable cached analysis and so could not be searched. A log contains a tag the way
    attach_rule_tags finds one: a rule carrying it decided a line, raised an
    alert or matched the whole log, or the tag's built-in warning fired.

    Reads cached analyses only, never analyzing a log, so the result follows
    the analyses as they were last computed. The viewer's rule set is read
    first; logs it has no fresh analysis for fall back to the shared one.
    """
    tag_ids = list(dict.fromkeys(tag_ids))
    candidate_pks = list(candidates.values_list('pk', flat=True))
    if not tag_ids:
        return candidate_pks, 0

    rules_by_tag = {tag_id: set() for tag_id in tag_ids}
    links = ClassificationRule.tags.through.objects.filter(
        ruletag_id__in=tag_ids,
    ).values_list('ruletag_id', 'classificationrule_id')
    for tag_id, rule_id in links:
        rules_by_tag[tag_id].add(rule_id)
    builtin_codes = dict(
        RuleTag.objects.filter(pk__in=tag_ids, builtin_code__isnull=False)
        .values_list('pk', 'builtin_code')
    )
    # A tag on no rule and without a warning of its own is in no log.
    if any(not rules_by_tag[tag_id] and tag_id not in builtin_codes for tag_id in tag_ids):
        return [], 0

    def has_all_tags(payload):
        rule_ids = payload_rule_ids(payload)
        codes = {warning.get('code') for warning in payload.get('warnings') or []}
        return all(
            rules_by_tag[tag_id] & rule_ids or builtin_codes.get(tag_id) in codes
            for tag_id in tag_ids
        )

    row_sets = [_fresh_analyses(candidates, rule_set_key)]
    if rule_set_key != SHARED_RULE_SET_KEY:
        row_sets.append(
            _fresh_analyses(candidates, SHARED_RULE_SET_KEY)
            .exclude(upload__in=row_sets[0].values('upload'))
        )

    analyzed = set()
    matched = set()
    for rows in row_sets:
        for upload_pk, payload in rows.values_list('upload_id', 'payload').iterator(chunk_size=25):
            analyzed.add(upload_pk)
            if has_all_tags(payload):
                matched.add(upload_pk)

    # Logs of a type the analyzer skips never have an analysis and hold no
    # tags; only analyzable ones are worth reporting as missed.
    analyzable = candidates.filter(log_type__in=UploadedLog.ANALYZED_LOG_TYPES).values_list('pk', flat=True)
    unanalyzed_count = sum(1 for pk in analyzable if pk not in analyzed)
    return [pk for pk in candidate_pks if pk in matched], unanalyzed_count


def tag_ids_by_key(rule_ids_by_key, codes_by_key):
    """``{key: set(tag_ids)}``: the tags found from each key's credited rules and warning codes.

    A tag is found the way attach_rule_tags finds one: a rule carrying it was
    credited, or the tag's built-in warning fired. Two queries for any number
    of keys.
    """
    tags_by_rule = {}
    all_rule_ids = set().union(*rule_ids_by_key.values()) if rule_ids_by_key else set()
    if all_rule_ids:
        links = ClassificationRule.tags.through.objects.filter(
            classificationrule_id__in=all_rule_ids,
        ).values_list('classificationrule_id', 'ruletag_id')
        for rule_id, tag_id in links:
            tags_by_rule.setdefault(rule_id, set()).add(tag_id)
    builtin_by_code = dict(
        RuleTag.objects.filter(builtin_code__isnull=False).values_list('builtin_code', 'pk')
    )

    result = {}
    for key, rule_ids in rule_ids_by_key.items():
        tag_ids = {tag_id for rule_id in rule_ids for tag_id in tags_by_rule.get(rule_id, ())}
        tag_ids.update(
            builtin_by_code[code] for code in codes_by_key.get(key) or () if code in builtin_by_code
        )
        result[key] = tag_ids
    return result


def found_tags_by_upload(upload_pks, rule_set_key):
    """``{upload_pk: [{id, name, description, category_id, category_priority}]}``: the tags found in each log, by name.

    Finds what attach_rule_tags finds, from the cached analysis a tag search
    reads (the viewer's rule set, else the shared one), in a fixed number of
    queries for any number of logs - for listing pages. A log without a fresh
    cached analysis gets no tags.
    """
    upload_pks = list(upload_pks)
    found = {pk: [] for pk in upload_pks}
    if not upload_pks:
        return found

    candidates = UploadedLog.objects.filter(pk__in=upload_pks)
    row_sets = [_fresh_analyses(candidates, rule_set_key)]
    if rule_set_key != SHARED_RULE_SET_KEY:
        row_sets.append(
            _fresh_analyses(candidates, SHARED_RULE_SET_KEY)
            .exclude(upload__in=row_sets[0].values('upload'))
        )
    rule_ids_by_upload = {}
    codes_by_upload = {}
    for rows in row_sets:
        for upload_pk, payload in rows.values_list('upload_id', 'payload'):
            rule_ids_by_upload[upload_pk] = payload_rule_ids(payload)
            codes_by_upload[upload_pk] = {
                warning.get('code') for warning in payload.get('warnings') or []
            }
    if not rule_ids_by_upload:
        return found

    tag_ids_by_upload = tag_ids_by_key(rule_ids_by_upload, codes_by_upload)
    all_tag_ids = set().union(*tag_ids_by_upload.values())
    tags = {
        tag.pk: {
            'id': tag.pk, 'name': tag.name, 'description': tag.description,
            'category_id': tag.category_id, 'category_priority': tag.category.priority,
        }
        for tag in RuleTag.objects.filter(pk__in=all_tag_ids).select_related('category')
    } if all_tag_ids else {}
    for upload_pk, tag_ids in tag_ids_by_upload.items():
        found[upload_pk] = sorted(
            (tags[tag_id] for tag_id in tag_ids if tag_id in tags),
            key=lambda tag: tag['name'].lower(),
        )
    return found


def tags_for_listing(tags):
    """The found tags an uploads list or case log row shows (see found_tags_by_upload).

    Tags of priority-0 categories are left out - they are in nearly every log;
    the rest come highest category priority first, then by name.
    """
    return sorted(
        (tag for tag in tags if tag['category_priority'] > 0),
        key=lambda tag: (-tag['category_priority'], tag['name'].lower()),
    )


def selected_tags_for_picker(tag_ids):
    """`[{id, name, description, category_id}]` for `tag_ids`, in order, to fill a tag picker."""
    tags = RuleTag.objects.in_bulk(tag_ids)
    return [
        {
            'id': tags[pk].pk, 'name': tags[pk].name, 'description': tags[pk].description,
            'category_id': tags[pk].category_id,
        }
        for pk in tag_ids if pk in tags
    ]


def first_tagged_line(payload, tag_ids):
    """The text of the first line whose deciding rules carry one of `tag_ids`, or None."""
    rule_ids = set(
        ClassificationRule.tags.through.objects.filter(ruletag_id__in=tag_ids)
        .values_list('classificationrule_id', flat=True)
    )
    for line in payload.get('lines') or []:
        if rule_ids.intersection(line.get('rule_ids') or []):
            return line.get('line')
    return None


def attach_tags_to_matches(*match_lists):
    """Give every rule match (dicts with an 'id') its rule's tags, in place.

    For the analyzer's line inspector, which lists effective and shadowed
    matches: a tagged rule that was shadowed explains why a line lacks a tag.
    """
    matches = [match for matches in match_lists for match in matches or []]
    rule_ids = {match.get('id') for match in matches if match.get('id') is not None}
    tags_by_rule = {}
    if rule_ids:
        links = (
            ClassificationRule.tags.through.objects.filter(classificationrule_id__in=rule_ids)
            .select_related('ruletag')
            .order_by('ruletag__name')
        )
        for link in links:
            tags_by_rule.setdefault(link.classificationrule_id, []).append(
                {'id': link.ruletag_id, 'name': link.ruletag.name, 'category_id': link.ruletag.category_id}
            )
    for match in matches:
        match['tags'] = tags_by_rule.get(match.get('id'), [])
