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

With `match_log_lines` the same conditions also run on every analysed log
line: the regex and exclude regex on the line text, statuses on the line's
verdict, entry types on its parsed entry. A matching line carries the tag even
when no tagged rule decided it. The matches are computed when an analysis is
cached and stored with it (UploadedLogAnalysis.line_tags), so listings, tag
search and stats read ids instead of running regexes on every page view. Each
stored entry carries a signature of the tag's conditions: an entry whose tag
changed is recomputed when read, and saving or deleting a line tag refreshes
every stored analysis in the background (see refresh_line_tags).

Built-in tags stand for the analyzer's hardcoded log warnings: besides being
ordinary tags (on rules, with conditions, applied automatically), they are
"found" in a log whenever their warning fires. They cannot be deleted.
"""

import hashlib
import json
import logging
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass
from functools import cached_property

from . import frst_extractors
from .analyzer import ANALYSIS_PAYLOAD_FORMAT, _re2, evaluate_regex_pattern
from django.conf import settings
from django.db import connections, transaction
from django.db.models import Case, F, IntegerField, JSONField, Q, Value, When
from django.db.models.fields.json import KT
from django.db.models.functions import Cast

from .models import (
    TAG_CATEGORY_COLOR_RE, ClassificationRule, FixlistSnippet, RuleTag, Speech, TagCategory, UploadedLog,
    UploadedLogAnalysis, UploadedLogStat,
)
from .rule_sets import SHARED_RULE_SET_KEY

logger = logging.getLogger(__name__)

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

# Part of every line signature: bumping it makes all stored line matches stale,
# for a change in how lines are matched. 2: entry types are the line's own
# parsed entry, no longer the deciding matcher's label.
LINE_MATCH_VERSION = 2

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
    # Also run the conditions on analysed log lines (RuleTag.match_log_lines).
    lines: bool = False

    @classmethod
    def of(cls, tag):
        return cls(
            pattern=tag.match_pattern or '',
            exclude_pattern=tag.exclude_pattern or '',
            scope=tag.match_scope or RuleTag.SCOPE_ANY,
            statuses=tuple(tag.match_statuses or ()),
            entry_types=tuple(tag.match_entry_types or ()),
            lines=bool(tag.match_log_lines),
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

    @property
    def matches_lines(self):
        """Whether the conditions run on log lines at all."""
        return self.lines and not self.is_empty

    def match_line(self, line, parsed_entry_type=None):
        """Whether an analysed log line (a payload `lines` entry) meets the conditions.

        Statuses look at the line's verdict and entry types at the line's own
        parsed FRST entry, whatever rule decided it; the regex and exclude
        regex search the line text. The scope only applies to rules.
        `parsed_entry_type` is a callable giving that entry type, so a caller
        checking several tags parses the line at most once.
        """
        if not self.matches_lines:
            return False
        if self.statuses and line.get('dominant_status') not in self.statuses:
            return False
        if self.entry_types:
            entry_type = parsed_entry_type() if parsed_entry_type is not None else line_parsed_entry_type(line)
            if entry_type not in self.entry_types:
                return False
        text = line.get('line') or ''
        if self.exclude_pattern:
            exclude = compile_pattern(self.exclude_pattern)
            if exclude is not None and exclude.search(text):
                return False
        if not self.pattern:
            return True
        compiled = compile_pattern(self.pattern)
        return compiled is not None and compiled.search(text) is not None

    @cached_property
    def line_signature(self):
        """A short fingerprint of what decides line matches, stored with them
        so a changed tag's stored matches are recognised as stale."""
        raw = json.dumps([
            LINE_MATCH_VERSION, self.pattern, self.exclude_pattern, sorted(self.statuses), sorted(self.entry_types),
        ])
        return hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]


def line_parsed_entry_type(line):
    """The parsed FRST entry type of an analysed line, '' for none.

    Read from the payload; analyses cached before it was recorded there get
    the line parsed again, with the analyzer's own parser.
    """
    entry_type = line.get('parsed_entry_type')
    if entry_type is None:
        entry = frst_extractors.get_frst_entry(line.get('line') or '')
        entry_type = entry.entry_type if entry is not None else ''
    return entry_type or ''


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
    if conditions.lines:
        parts.append('also on log lines')
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
        'match_log_lines': tag.match_log_lines,
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
    if 'match_log_lines' in payload:
        if not isinstance(payload['match_log_lines'], bool):
            return None, 'Field "match_log_lines" must be a boolean.'
        values['lines'] = payload['match_log_lines']
    else:
        values['lines'] = base.lines
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
    exclude_pattern, match_scope, match_statuses, match_entry_types,
    match_log_lines, auto_apply, category_id (null for the default category),
    speech_ids, snippet_ids. Absent fields keep the tag's values. Applying the
    tag to rules is left to the caller; when what the tag matches on log lines
    changes, the stored line matches are refreshed in the background.
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
    if conditions.lines and conditions.is_empty:
        return None, 'Matching log lines needs a condition: a regex, a status or an entry type.'

    line_key_before = _line_key(TagConditions.of(tag)) if tag is not None else None
    if tag is None:
        tag = RuleTag(created_by=user)
    tag.name = name
    tag.description = description
    tag.match_pattern = conditions.pattern
    tag.exclude_pattern = conditions.exclude_pattern
    tag.match_scope = conditions.scope
    tag.match_statuses = list(conditions.statuses)
    tag.match_entry_types = list(conditions.entry_types)
    tag.match_log_lines = conditions.lines
    tag.auto_apply = auto_apply
    tag.category_id = category_id
    tag.updated_by = user
    tag.save()
    if speech_ids is not None:
        set_speech_links(tag, user, speech_ids)
    if snippet_ids is not None:
        set_snippet_links(tag, user, snippet_ids)
    if _line_key(conditions) != line_key_before:
        schedule_line_tag_refresh([tag.pk])
    return tag, None


def _line_key(conditions):
    """What a tag matches on log lines: its line signature, or None for nothing."""
    return conditions.line_signature if conditions.matches_lines else None


def delete_tag(tag):
    """Delete a tag; if it matched log lines, its stored matches are dropped in the background."""
    was_line_tag = TagConditions.of(tag).matches_lines
    pk = tag.pk
    tag.delete()
    if was_line_tag:
        schedule_line_tag_refresh([pk])


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


# --- Tags on log lines ------------------------------------------------------

_line_set_cache = {}


def _line_regex_set(patterns):
    """``(re2 Set, positions)`` searching all `patterns` case-insensitively in one
    pass, or ``(None, [])`` without re2. `positions` maps a Set index back to the
    pattern's index in `patterns`; patterns the Set refuses are left out and
    checked one by one instead."""
    if _re2 is None or not patterns:
        return None, []
    key = tuple(patterns)
    cached = _line_set_cache.get(key)
    if cached is not None:
        return cached
    result = (None, [])
    try:
        options = _re2.Options()
        options.max_mem = 64 * 1024 * 1024
        regex_set = _re2.Set(_re2._Anchor.UNANCHORED, options)
        positions = []
        for index, pattern in enumerate(patterns):
            try:
                regex_set.Add(f'(?i){pattern}')
            except Exception:
                continue
            positions.append(index)
        if positions:
            regex_set.Compile()
            result = (regex_set, positions)
    except Exception:
        result = (None, [])
    if len(_line_set_cache) > 50:
        _line_set_cache.clear()
    _line_set_cache[key] = result
    return result


class LineTagMatcher:
    """Finds the lines of an analysis that line-matching tags match.

    The tags' regexes run as one re2 Set per line, so the cost hardly grows
    with the number of tags; a line whose verdict no regex tag accepts skips
    the regex pass entirely.
    """

    def __init__(self, conditions_by_tag):
        items = [(tag_id, conditions) for tag_id, conditions in conditions_by_tag.items() if conditions.matches_lines]
        self.empty = not items
        self.plain = [(tag_id, conditions) for tag_id, conditions in items if not conditions.pattern]
        patterned = [(tag_id, conditions) for tag_id, conditions in items if conditions.pattern]
        self.regex_set, positions = _line_regex_set([conditions.pattern for _tag_id, conditions in patterned])
        self.set_items = [patterned[index] for index in positions]
        in_set = set(positions)
        self.loose = [item for index, item in enumerate(patterned) if index not in in_set]
        # The verdicts any regex tag accepts; None when one accepts every verdict.
        statuses = set()
        for _tag_id, conditions in patterned:
            if not conditions.statuses:
                statuses = None
                break
            statuses.update(conditions.statuses)
        self.regex_statuses = statuses

    def hits(self, payload):
        """``{tag_id: [line index]}`` for the tags with at least one matching line."""
        hits = {}
        if self.empty or not isinstance(payload, dict):
            return hits
        for index, line in enumerate(payload.get('lines') or []):
            if not isinstance(line, dict):
                continue
            candidates = list(self.plain)
            if self.set_items or self.loose:
                if self.regex_statuses is None or line.get('dominant_status') in self.regex_statuses:
                    candidates.extend(self.loose)
                    if self.regex_set is not None:
                        try:
                            matched = self.regex_set.Match(line.get('line') or '')
                        except Exception:
                            matched = None
                        # google-re2's Set.Match returns None (not []) when nothing matched.
                        candidates.extend(self.set_items[position] for position in matched or ())
            parsed = []

            def parsed_entry_type(line=line, parsed=parsed):
                if not parsed:
                    parsed.append(line_parsed_entry_type(line))
                return parsed[0]

            for tag_id, conditions in candidates:
                if conditions.match_line(line, parsed_entry_type):
                    hits.setdefault(tag_id, []).append(index)
        return hits


def current_line_tags(tags=None):
    """``{tag_id: TagConditions}`` for every tag that matches log lines (among `tags`, if given)."""
    if tags is None:
        tags = RuleTag.objects.filter(match_log_lines=True)
    result = {}
    for tag in tags:
        conditions = TagConditions.of(tag)
        if conditions.matches_lines:
            result[tag.pk] = conditions
    return result


def _line_and_builtin_tags():
    """``(current line tags, {builtin_code: tag pk})`` in one query, for listings."""
    tags = list(RuleTag.objects.filter(Q(match_log_lines=True) | Q(builtin_code__isnull=False)))
    builtin_by_code = {tag.builtin_code: tag.pk for tag in tags if tag.builtin_code is not None}
    return current_line_tags(tags), builtin_by_code


def _stored_line_tags(current, hits):
    """The `line_tags` value stored with a cached analysis."""
    return {
        'sigs': {str(tag_id): conditions.line_signature for tag_id, conditions in current.items()},
        'lines': {str(tag_id): indexes for tag_id, indexes in hits.items() if tag_id in current and indexes},
    }


def compute_line_tags(payload, current=None):
    """The `line_tags` to store with a cached analysis of `payload`."""
    if current is None:
        current = current_line_tags()
    return _stored_line_tags(current, LineTagMatcher(current).hits(payload))


def line_tag_hits(stored):
    """``{tag_id: [line index]}`` from a stored `line_tags` value, as it is."""
    lines = (stored or {}).get('lines') if isinstance(stored, dict) else None
    hits = {}
    for key, indexes in (lines or {}).items():
        try:
            hits[int(key)] = list(indexes)
        except (TypeError, ValueError):
            continue
    return hits


def _split_line_tags(stored, current, force=()):
    """``(hits, stale, dropped)``: what of a stored `line_tags` value still holds.

    `hits` are the stored matches of tags whose signature still agrees,
    `stale` the ``{tag_id: TagConditions}`` that must be matched against the
    analysis again (changed, new, or in `force`), and `dropped` whether the
    stored value names tags that no longer match lines. Needs no payload.
    """
    stored = stored if isinstance(stored, dict) else {}
    sigs = stored.get('sigs') if isinstance(stored.get('sigs'), dict) else {}
    stored_hits = line_tag_hits(stored)
    force = set(force)
    hits = {}
    stale = {}
    for tag_id, conditions in current.items():
        if tag_id not in force and sigs.get(str(tag_id)) == conditions.line_signature:
            if stored_hits.get(tag_id):
                hits[tag_id] = stored_hits[tag_id]
        else:
            stale[tag_id] = conditions
    current_keys = {str(tag_id) for tag_id in current}
    dropped = any(key not in current_keys for key in sigs) or any(
        tag_id not in current for tag_id in stored_hits
    )
    return hits, stale, dropped


def fresh_line_tags(stored, payload, current, force=()):
    """``(hits, updated)`` for a cached analysis under the current line tags.

    `hits` is ``{tag_id: [line index]}``. Stored matches are reused where the
    tag's signature still agrees; tags that changed, are new, or are in
    `force` are recomputed against `payload`, and tags that no longer match
    lines are dropped. `updated` is the value to store back, or None when the
    stored one is still right. `payload` may be a callable returning it, so
    callers only load it when a tag actually has to be matched again.
    """
    hits, stale, dropped = _split_line_tags(stored, current, force)
    if not stale and not dropped:
        return hits, None
    if stale:
        hits.update(LineTagMatcher(stale).hits(payload() if callable(payload) else payload))
    return hits, _stored_line_tags(current, hits)


def _write_line_tags(updates):
    """Store recomputed `line_tags`: ``{analysis pk: value}``."""
    for pk, value in updates.items():
        UploadedLogAnalysis.objects.filter(pk=pk).update(line_tags=value)


REFRESH_BATCH_SIZE = 50


def refresh_line_tags(tag_ids=None):
    """Recompute the stored line matches of every cached analysis, and the
    line tags of the stat snapshots of logs that still have a shared one.

    `tag_ids` limits the recompute to those tags (one just edited, added or
    deleted); None recomputes every line tag - the tags page's "recompute"
    button and the recompute_line_tags command. Returns how many cached
    analyses were updated. Snapshots of logs that are gone keep what they had.
    """
    current = current_line_tags()
    force = set(current) if tag_ids is None else set(tag_ids)
    pks = list(UploadedLogAnalysis.objects.order_by('pk').values_list('pk', flat=True))
    updated_count = 0
    for start in range(0, len(pks), REFRESH_BATCH_SIZE):
        batch = list(UploadedLogAnalysis.objects.filter(pk__in=pks[start:start + REFRESH_BATCH_SIZE]).values_list(
            'pk', 'upload_id', 'rule_set_key', 'line_tags',
        ))
        # Decoding payloads is nearly the whole cost of a refresh; only rows
        # with a tag to match again need theirs (a deleted tag only drops).
        needs_payload = {pk for pk, _upload_id, _key, stored in batch if _split_line_tags(stored, current, force)[1]}
        payloads = dict(
            UploadedLogAnalysis.objects.filter(pk__in=needs_payload).values_list('pk', 'payload')
        ) if needs_payload else {}
        for pk, upload_id, rule_set_key, stored in batch:
            payload = payloads.get(pk) if pk in needs_payload else {}
            if not isinstance(payload, dict):
                continue
            hits, updated = fresh_line_tags(stored, payload, current, force=force)
            if updated is None:
                continue
            UploadedLogAnalysis.objects.filter(pk=pk).update(line_tags=updated)
            updated_count += 1
            if rule_set_key == SHARED_RULE_SET_KEY:
                UploadedLogStat.objects.filter(source_id=upload_id).update(line_tag_ids=sorted(hits))
        # The refresh shares its process with request threads; let them run.
        time.sleep(0)
    return updated_count


# A process runs its background refreshes one at a time: one asked for while
# another runs is merged into the next run instead of starting its own thread,
# so a burst of tag saves costs at most two passes, not one each.
_ALL_TAGS = object()
_refresh_lock = threading.Lock()
_refresh_pending = None  # None: nothing queued; _ALL_TAGS; or a set of tag ids.
_refresh_running = False


def _queue_refresh(tag_ids):
    """Merge `tag_ids` (None: all) into the queued refresh. True if a thread must be started."""
    global _refresh_pending, _refresh_running
    with _refresh_lock:
        if tag_ids is None or _refresh_pending is _ALL_TAGS:
            _refresh_pending = _ALL_TAGS
        else:
            _refresh_pending = (_refresh_pending or set()) | set(tag_ids)
        if _refresh_running:
            return False
        _refresh_running = True
        return True


def _take_queued_refresh():
    """``(has_work, tag_ids)`` for the next run; marks the thread finished when nothing is queued."""
    global _refresh_pending, _refresh_running
    with _refresh_lock:
        pending, _refresh_pending = _refresh_pending, None
        if pending is None:
            _refresh_running = False
            return False, None
        return True, None if pending is _ALL_TAGS else sorted(pending)


def _refresh_line_tags_in_thread():
    try:
        while True:
            has_work, tag_ids = _take_queued_refresh()
            if not has_work:
                return
            try:
                refresh_line_tags(tag_ids)
            except Exception:
                logger.exception('Background line tag refresh failed (tag_ids=%s)', tag_ids)
    finally:
        connections.close_all()


def schedule_line_tag_refresh(tag_ids=None):
    """Run refresh_line_tags off the request thread, once the change is committed.

    Runs synchronously under the test runner. Until it is done, a read of a
    stale analysis recomputes the changed tags itself (fresh_line_tags), so
    only the stat snapshots wait for it. Overlapping requests are coalesced
    (see _queue_refresh).
    """
    tag_ids = None if tag_ids is None else list(tag_ids)
    if getattr(settings, 'TESTING', False):
        refresh_line_tags(tag_ids)
        return

    def start():
        if _queue_refresh(tag_ids):
            threading.Thread(target=_refresh_line_tags_in_thread, name='line-tag-refresh', daemon=True).start()

    transaction.on_commit(start)


def tag_summary_of(payload):
    """`UploadedLogAnalysis.tag_summary` for `payload`: all a tag lookup reads of it.

    ``{"format", "rule_ids", "codes"}`` - the payload format (for the freshness
    test), every credited rule id (see payload_rule_ids) and the warning codes.
    None for a payload that is not a dict.
    """
    if not isinstance(payload, dict):
        return None
    return {
        'format': payload.get('format'),
        'rule_ids': sorted(payload_rule_ids(payload)),
        'codes': sorted({
            warning.get('code') for warning in payload.get('warnings') or []
            if isinstance(warning.get('code'), str)
        }),
    }


def payload_rule_ids(payload):
    """Every rule id an analysis credits: lines' deciding rules, alert warnings', whole-log."""
    rule_ids = set(payload.get('wholelog_rule_ids') or [])
    for line in payload.get('lines') or []:
        rule_ids.update(line.get('rule_ids') or [])
    for warning in payload.get('warnings') or []:
        rule_ids.update(warning.get('rule_ids') or [])
    return rule_ids


def attach_rule_tags(payload, line_hits=None):
    """Add the rule tags behind an analysis to its payload, in place.

    Each line gets `tag_ids` from its deciding `rule_ids` and from the
    line-matching tags whose conditions it meets; each warning gets `tag_ids`
    from its alert rules' tags plus the built-in tag of its code; and the
    payload gets `rule_tags`: every tag found, with the number of lines it
    covers. Done when the analysis is served rather than when it is computed,
    so tagging a rule shows up at once without invalidating any cached
    analysis. `line_hits` (``{tag_id: [line index]}``) defaults to matching
    the current line tags now - one pass over this one log.
    """
    lines = payload.get('lines') or []
    warnings = payload.get('warnings') or []
    wholelog_rule_ids = payload.get('wholelog_rule_ids') or []
    rule_ids = payload_rule_ids(payload)
    if line_hits is None:
        line_hits = LineTagMatcher(current_line_tags()).hits(payload)

    tags_by_rule = {}
    if rule_ids:
        links = ClassificationRule.tags.through.objects.filter(
            classificationrule_id__in=rule_ids,
        ).values_list('classificationrule_id', 'ruletag_id')
        for rule_id, tag_id in links:
            tags_by_rule.setdefault(rule_id, []).append(tag_id)

    def tags_of(ids):
        return {tag_id for rule_id in ids or [] for tag_id in tags_by_rule.get(rule_id, [])}

    line_tags_by_index = {}
    for tag_id, indexes in line_hits.items():
        for index in indexes:
            line_tags_by_index.setdefault(index, set()).add(tag_id)

    line_counts = Counter()
    for index, line in enumerate(lines):
        tag_ids = sorted(tags_of(line.get('rule_ids')) | line_tags_by_index.get(index, set()))
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
    The format is read from the small `tag_summary` - testing it on `payload`
    makes the database decompress every candidate's whole payload. A CASE,
    because only it fixes the order: given a plain OR, Postgres may test the
    payload first.
    """
    payload_format = Case(
        When(tag_summary__isnull=False, then=Cast(KT('tag_summary__format'), IntegerField())),
        default=Cast(KT('payload__format'), IntegerField()),
        output_field=IntegerField(),
    )
    return UploadedLogAnalysis.objects.alias(_payload_format=payload_format).filter(
        _payload_format=ANALYSIS_PAYLOAD_FORMAT,
        upload__in=candidates,
        rule_set_key=rule_set_key,
        source_content_hash=F('upload__content_hash'),
    )


def _tag_rows(row_sets, current, need_line_hits=True):
    """``[(upload_pk, rule_ids, codes, line_hits)]`` from cached analyses, decoding few payloads.

    Reads each row's `tag_summary` and stored `line_tags`. The payload comes
    along in the same query only for a row without a summary, and is loaded
    afterwards only for a row with a line tag to match again. Summaries and
    line matches derived on the way are stored back. Without
    `need_line_hits`, line tags are neither read nor matched.
    """
    payload_if_unsummarized = Case(
        When(tag_summary__isnull=True, then=F('payload')),
        default=Value(None, output_field=JSONField()),
        output_field=JSONField(),
    )
    rows = []
    summary_updates = {}
    payloads = {}
    late = []
    for row_set in row_sets:
        values = (
            row_set.annotate(_unsummarized_payload=payload_if_unsummarized)
            .values_list('pk', 'upload_id', 'tag_summary', 'line_tags', '_unsummarized_payload')
        )
        for pk, upload_pk, summary, stored, payload in values:
            needs_lines = need_line_hits and bool(_split_line_tags(stored, current)[1])
            if summary is None:
                summary_updates[pk] = summary = tag_summary_of(payload) or {}
                if needs_lines:
                    payloads[pk] = payload
            elif needs_lines:
                late.append(pk)
            # Payloads are kept only for rows that match a line tag again.
            rows.append((pk, upload_pk, summary, stored))
    for start in range(0, len(late), REFRESH_BATCH_SIZE):
        payloads.update(
            UploadedLogAnalysis.objects.filter(pk__in=late[start:start + REFRESH_BATCH_SIZE])
            .values_list('pk', 'payload')
        )

    line_updates = {}
    result = []
    for pk, upload_pk, summary, stored in rows:
        line_hits = {}
        if need_line_hits:
            line_hits, updated = fresh_line_tags(stored, lambda pk=pk: payloads.get(pk) or {}, current)
            if updated is not None:
                line_updates[pk] = updated
        result.append((
            upload_pk, set(summary.get('rule_ids') or ()), set(summary.get('codes') or ()), line_hits,
        ))

    for pk, summary in summary_updates.items():
        UploadedLogAnalysis.objects.filter(pk=pk).update(tag_summary=summary)
    _write_line_tags(line_updates)
    return result


def _searched_rows(candidates, rule_set_key):
    """The querysets of cached analyses a tag search reads: the viewer's rule
    set first, then the shared one for logs the viewer has none for."""
    row_sets = [_fresh_analyses(candidates, rule_set_key)]
    if rule_set_key != SHARED_RULE_SET_KEY:
        row_sets.append(
            _fresh_analyses(candidates, SHARED_RULE_SET_KEY)
            .exclude(upload__in=row_sets[0].values('upload'))
        )
    return row_sets


def logs_with_tags(tag_ids, rule_set_key, candidates):
    """The uploads among `candidates` that contain every tag in `tag_ids`.

    Returns ``(upload_pks, unanalyzed_count)``: the matching primary keys in
    the order of `candidates`, and how many analyzable candidates had no
    usable cached analysis and so could not be searched. A log contains a tag the way
    attach_rule_tags finds one: a rule carrying it decided a line, raised an
    alert or matched the whole log, the tag's built-in warning fired, or one
    of the log's lines meets the tag's line conditions (stored with the
    analysis, see fresh_line_tags).

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
    current = current_line_tags()
    # A tag on no rule, without a warning of its own and not matching lines is in no log.
    if any(
        not rules_by_tag[tag_id] and tag_id not in builtin_codes and tag_id not in current
        for tag_id in tag_ids
    ):
        return [], 0
    searched_line_tags = {tag_id for tag_id in tag_ids if tag_id in current}

    def has_all_tags(rule_ids, codes, line_hits):
        return all(
            rules_by_tag[tag_id] & rule_ids
            or builtin_codes.get(tag_id) in codes
            or bool(line_hits.get(tag_id))
            for tag_id in tag_ids
        )

    analyzed = set()
    matched = set()
    rows = _tag_rows(_searched_rows(candidates, rule_set_key), current, need_line_hits=bool(searched_line_tags))
    for upload_pk, rule_ids, codes, line_hits in rows:
        analyzed.add(upload_pk)
        if has_all_tags(rule_ids, codes, line_hits):
            matched.add(upload_pk)

    # Logs of a type the analyzer skips never have an analysis and hold no
    # tags; only analyzable ones are worth reporting as missed.
    analyzable = candidates.filter(log_type__in=UploadedLog.ANALYZED_LOG_TYPES).values_list('pk', flat=True)
    unanalyzed_count = sum(1 for pk in analyzable if pk not in analyzed)
    return [pk for pk in candidate_pks if pk in matched], unanalyzed_count


def tag_ids_by_key(rule_ids_by_key, codes_by_key, line_tag_ids_by_key=None, builtin_by_code=None):
    """``{key: set(tag_ids)}``: the tags found from each key's credited rules, warning codes and line tags.

    A tag is found the way attach_rule_tags finds one: a rule carrying it was
    credited, the tag's built-in warning fired, or (`line_tag_ids_by_key`,
    already resolved) one of the log's lines matched it. Two queries for any
    number of keys (one, when `builtin_by_code` is passed in).
    """
    line_tag_ids_by_key = line_tag_ids_by_key or {}
    tags_by_rule = {}
    all_rule_ids = set().union(*rule_ids_by_key.values()) if rule_ids_by_key else set()
    if all_rule_ids:
        links = ClassificationRule.tags.through.objects.filter(
            classificationrule_id__in=all_rule_ids,
        ).values_list('classificationrule_id', 'ruletag_id')
        for rule_id, tag_id in links:
            tags_by_rule.setdefault(rule_id, set()).add(tag_id)
    if builtin_by_code is None:
        builtin_by_code = dict(
            RuleTag.objects.filter(builtin_code__isnull=False).values_list('builtin_code', 'pk')
        )

    result = {}
    for key, rule_ids in rule_ids_by_key.items():
        tag_ids = {tag_id for rule_id in rule_ids for tag_id in tags_by_rule.get(rule_id, ())}
        tag_ids.update(
            builtin_by_code[code] for code in codes_by_key.get(key) or () if code in builtin_by_code
        )
        tag_ids.update(line_tag_ids_by_key.get(key) or ())
        result[key] = tag_ids
    return result


def found_tags_by_upload(upload_pks, rule_set_key):
    """``{upload_pk: [{id, name, description, category_id, category_priority}]}``: the tags found in each log, by name.

    Finds what attach_rule_tags finds, from the cached analysis a tag search
    reads (the viewer's rule set, else the shared one), in a fixed number of
    queries for any number of logs - for listing pages. Line tags come from
    the matches stored with each analysis. A log without a fresh cached
    analysis gets no tags.
    """
    upload_pks = list(upload_pks)
    found = {pk: [] for pk in upload_pks}
    if not upload_pks:
        return found

    candidates = UploadedLog.objects.filter(pk__in=upload_pks)
    current, builtin_by_code = _line_and_builtin_tags()
    rule_ids_by_upload = {}
    codes_by_upload = {}
    line_tag_ids_by_upload = {}
    for upload_pk, rule_ids, codes, line_hits in _tag_rows(_searched_rows(candidates, rule_set_key), current):
        rule_ids_by_upload[upload_pk] = rule_ids
        codes_by_upload[upload_pk] = codes
        line_tag_ids_by_upload[upload_pk] = set(line_hits)
    if not rule_ids_by_upload:
        return found

    tag_ids_by_upload = tag_ids_by_key(
        rule_ids_by_upload, codes_by_upload, line_tag_ids_by_upload, builtin_by_code=builtin_by_code,
    )
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
    """The text of the first line carrying one of `tag_ids` - through its deciding
    rules or by meeting a tag's line conditions - or None."""
    rule_ids = set(
        ClassificationRule.tags.through.objects.filter(ruletag_id__in=tag_ids)
        .values_list('classificationrule_id', flat=True)
    )
    wanted = set(tag_ids)
    line_tags = {tag_id: conditions for tag_id, conditions in current_line_tags().items() if tag_id in wanted}
    hit_indexes = {index for indexes in LineTagMatcher(line_tags).hits(payload).values() for index in indexes}
    for index, line in enumerate(payload.get('lines') or []):
        if index in hit_indexes or rule_ids.intersection(line.get('rule_ids') or []):
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
