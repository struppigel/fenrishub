"""
Classification rule management views.

Handles: creating, editing, deleting, testing, and viewing classification rules.
"""

import json
import time
from urllib.parse import urlencode
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.urls import reverse
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q, Case, When

from .. import frst_extractors, script_matcher
from ..analyzer import (
    parse_rule_line, inspect_line_matches, VALID_STATUSES,
    evaluate_regex_pattern, REPARSE_FIELDS,
)
from ..log_types import (
    ALL_LOG_TYPES, DEFAULT_RULE_LOG_TYPES, default_rule_scope, normalize_log_type_selection, scope_payload,
)
from ..models import (
    ClassificationRule,
    Fact,
    FactRule,
    RuleCondition,
    DEFAULT_PRIORITY_BY_MATCH_TYPE,
    PRIORITY_DEFAULT_LABELS,
    PRIORITY_MAX,
    PRIORITY_MIN,
    RuleTag,
    known_log_type_names,
)
from ..fact_service import (
    DUPLICATE_CONDITIONS_ERROR, condition_key_for, conditions_error, conditions_from_payload,
    rule_condition_specs, set_rule_conditions,
)
from ..rule_sets import invalidate_for_rule_owner
from ..tagging import auto_tag_rules, parse_tag_ids, selected_tags_for_picker, serialize_tag
from ..rule_test_service import (
    build_rule_test_results,
    build_wholelog_rule_test_result,
    scan_logs_for_rule_matches,
    scan_logs_for_wholelog_matches,
)
from ..validators import PayloadValidator
from .guest import deny_guests, is_moderator
from .utils import get_action_scoped_uploads, redirect_with_return_q, sanitize_return_q


def _priority_choices():
    return [
        (
            str(p),
            f"{p} ({PRIORITY_DEFAULT_LABELS[p]})" if p in PRIORITY_DEFAULT_LABELS else str(p),
        )
        for p in range(PRIORITY_MIN, PRIORITY_MAX + 1)
    ]


def _coerce_priority(raw_value, match_type: str) -> int:
    """Return a clamped priority for the given match_type, or the default if unset/invalid."""
    if raw_value is None or str(raw_value).strip() == '':
        return ClassificationRule.default_priority_for(match_type)
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return ClassificationRule.default_priority_for(match_type)
    return max(PRIORITY_MIN, min(PRIORITY_MAX, value))


def _patterns_for(match_type: str, source_text: str) -> list:
    """Split source text into rule patterns.

    Script rules are a single multi-line snippet, so the whole blob is one rule.
    Every other match type creates one rule per non-empty line.
    """
    if match_type == ClassificationRule.MATCH_SCRIPT:
        return [source_text] if source_text.strip() else []
    return _split_patterns(source_text)


def _creatable_match_type_choices(user):
    """Match types a user may author. Only moderators may create script rules."""
    if is_moderator(user):
        return ClassificationRule.MATCH_TYPE_CHOICES
    return [
        (code, label)
        for code, label in ClassificationRule.MATCH_TYPE_CHOICES
        if code != ClassificationRule.MATCH_SCRIPT
    ]


def _whole_log_error(whole_log: bool, status: str, match_type: str) -> str | None:
    """Validate the whole-log flag. Returns an error message, or None if OK.

    Whole-log rules run once against the entire log and surface only as alerts, so
    they are restricted to Alert status and the regex / script match types.
    """
    if not whole_log:
        return None
    if status != ClassificationRule.STATUS_ALERT:
        return 'Whole-log rules must use Alert status.'
    if match_type not in (ClassificationRule.MATCH_REGEX, ClassificationRule.MATCH_SCRIPT):
        return 'Whole-log rules support only regex and script match types.'
    return None


def _color_whole_line_for(color_whole_line: bool, match_type: str) -> bool:
    """Only substring and file path rules can opt into colouring the whole analyzer
    line; every other match type already does, so the flag is dropped rather than
    rejected."""
    return bool(color_whole_line) and match_type in ClassificationRule.COLOR_WHOLE_LINE_MATCH_TYPES


def _script_rule_error(match_type: str, source_text: str, user, whole_log: bool = False) -> str | None:
    """Validate a script rule before save. Returns an error message, or None if OK.

    Non-moderators may not author script rules at all. For moderators, the snippet
    must compile, run cleanly on adversarial input, and stay within the time budget.
    Whole-log script rules read their input from the ``log`` variable instead of ``line``.
    """
    if match_type != ClassificationRule.MATCH_SCRIPT:
        return None
    if not is_moderator(user):
        return 'Script rules can only be created by moderators.'
    var_name = 'log' if whole_log else 'line'
    evaluation = script_matcher.evaluate_script(source_text, var_name=var_name)
    if not evaluation['compile_ok']:
        return evaluation['compile_error'] or 'Invalid script.'
    if evaluation['runtime_error']:
        return f"Script failed on test input: {evaluation['runtime_error']}"
    if evaluation['is_slow']:
        return 'Script is too slow on adversarial input and was rejected.'
    return None


def _split_patterns(source_text: str) -> list:
    """Split a textarea blob into individual pattern lines, dropping empties.

    Each non-empty line becomes its own pattern. Trims whitespace per line so
    a trailing \\r on Windows pastes does not produce pseudo-duplicates.
    Preserves order and de-duplicates within the submit.
    """
    seen = set()
    patterns = []
    for raw in source_text.splitlines():
        line = raw.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        patterns.append(line)
    return patterns


def _tag_ids_from_post(request):
    """The tag ids the form posted, or None when it had no tag picker.

    The picker always posts `tags_present`, so a form without one - the quick-edit
    panel on the rules list - leaves a rule's tags alone instead of clearing them.
    """
    if not request.POST.get('tags_present'):
        return None
    return parse_tag_ids(request.POST.getlist('tag_ids'))


def _set_rule_tags(rules, tag_ids) -> None:
    """Link every rule in `rules` to exactly the tags in `tag_ids`."""
    through = ClassificationRule.tags.through
    rule_ids = [rule.pk for rule in rules if rule.pk]
    through.objects.filter(classificationrule_id__in=rule_ids).exclude(
        ruletag_id__in=tag_ids,
    ).delete()
    through.objects.bulk_create(
        [through(classificationrule_id=rule_id, ruletag_id=tag_id)
         for rule_id in rule_ids for tag_id in tag_ids],
        ignore_conflicts=True,
    )


def _log_scope_from_post(request) -> tuple:
    """The log type scope picker of a POST: `(scope, error)`.

    `scope` is `(all_log_types, log_types)`, or None when the form has no
    picker (the rule keeps its scope, a new rule gets the default).
    """
    mode = request.POST.get('log_scope')
    if mode is None:
        return None, None
    if mode.strip() == ALL_LOG_TYPES:
        return (True, []), None
    scope, error = normalize_log_type_selection(request.POST.getlist('log_types'))
    if error:
        return None, f'Log types: {error}.'
    return scope, None


def _log_scope_from_query(params) -> tuple | None:
    """A scope carried in the add page's query string, or None (default / invalid)."""
    mode = params.get('log_scope')
    if mode == ALL_LOG_TYPES:
        return True, []
    if mode == 'selected':
        scope, error = normalize_log_type_selection(params.getlist('log_types'))
        return None if error else scope
    return None


def _conditions_from_post(request) -> tuple:
    """The conditions block of a POST: `(specs, error)`; specs None when the
    form had no conditions block (the rule keeps its conditions). The editor
    always posts `conditions_present`, like the tag picker's `tags_present`."""
    if not request.POST.get('conditions_present'):
        return None, None
    return conditions_from_payload(request.POST.get('conditions', ''))


def clean_entry_types(raw) -> tuple:
    """`(types, error)` for a parsed-type restriction (only_entry_types): the
    names in frst_extractors.ENTRY_TYPES order, [] for none."""
    if raw in (None, '', []):
        return [], None
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or not all(isinstance(value, str) for value in raw):
        return [], 'Parsed types must be a list of names.'
    wanted = set(raw)
    unknown = sorted(wanted - set(frst_extractors.ENTRY_TYPES))
    if unknown:
        return [], f'Unknown parsed type: {", ".join(unknown)}.'
    return [name for name in frst_extractors.ENTRY_TYPES if name in wanted], None


def entry_types_from_post(request) -> tuple:
    """The advanced "only on lines parsed as" checkboxes: `(types, error)`;
    types None when the form has none (the quick-edit panel, the token API:
    keep the rule's own)."""
    if not request.POST.get('only_entry_types_present'):
        return None, None
    return clean_entry_types(request.POST.getlist('only_entry_types'))


def entry_type_choices():
    """(value, label) of every parsed type a rule can be restricted to."""
    return [(name, name.replace('_', ' ')) for name in frst_extractors.ENTRY_TYPES]


def _apply_to_block_from_post(request):
    """The advanced "apply the verdict to its block" checkbox, or None when
    the form has none (the quick-edit panel, the token API: keep the rule's)."""
    if not request.POST.get('apply_to_block_present'):
        return None
    return request.POST.get('apply_to_block') == 'on'


def _rule_form_from_post(request) -> dict:
    """Read the shared rule-form fields out of a POST."""
    log_scope, log_scope_error = _log_scope_from_post(request)
    conditions, conditions_problem = _conditions_from_post(request)
    only_entry_types, entry_types_problem = entry_types_from_post(request)
    return {
        'log_scope': log_scope,
        'log_scope_error': log_scope_error,
        'conditions': conditions,
        'conditions_error': conditions_problem,
        'only_entry_types': only_entry_types,
        'only_entry_types_error': entry_types_problem,
        'tag_ids': _tag_ids_from_post(request),
        'status': request.POST.get('status', '').strip(),
        'match_type': request.POST.get('match_type', '').strip(),
        'source_text': request.POST.get('source_text', '').strip(),
        'description': request.POST.get('description', '').strip(),
        'is_enabled': request.POST.get('is_enabled') == 'on',
        'whole_log': request.POST.get('whole_log') == 'on',
        'color_whole_line': request.POST.get('color_whole_line') == 'on',
        'apply_to_block': _apply_to_block_from_post(request),
        # Kept as a string: the template selects an option with `form_priority == value`
        # against the str-keyed `_priority_choices()`, and an int would never compare
        # equal -- leaving the select unselected and letting the page's JS overwrite
        # the rule's hand-tuned priority with the match-type default.
        'priority': request.POST.get('priority', '').strip(),
    }


def _rule_form_from_rule(rule) -> dict:
    """Form state for an existing rule. See _rule_form_from_post on the priority str."""
    return {
        'log_scope': (rule.all_log_types, list(rule.log_types or [])),
        'log_scope_error': None,
        # None: keep the rule's conditions (the form shows them, see _rule_form_context).
        'conditions': None,
        'conditions_error': None,
        'only_entry_types': list(rule.only_entry_types or []),
        'only_entry_types_error': None,
        'tag_ids': list(rule.tags.values_list('pk', flat=True)),
        'status': rule.status,
        'match_type': rule.match_type,
        'source_text': rule.source_text,
        'description': rule.description,
        'is_enabled': rule.is_enabled,
        'whole_log': rule.whole_log,
        'color_whole_line': rule.color_whole_line,
        'apply_to_block': rule.apply_to_block,
        'priority': '' if rule.priority is None else str(rule.priority),
    }


def _warn_about_unassignable_values(request, rule) -> None:
    """Warn when a rule holds a status or match type the current user cannot assign.

    The form offers only what a user may author, so such a value has no option to
    select, the browser falls back to the first one, and saving would rewrite the
    rule. These values should not occur -- `?` rules in particular are not supposed
    to exist -- so the editor says so out loud rather than quietly offering them.
    """
    if rule.status not in dict(ClassificationRule.CREATABLE_STATUS_CHOICES):
        label = dict(ClassificationRule.STATUS_CHOICES).get(rule.status, rule.status)
        messages.warning(
            request,
            f'This rule has status "{rule.status} - {label}", which cannot be '
            f'assigned here. Saving will change it to the status shown below.',
        )
    if rule.match_type not in dict(_creatable_match_type_choices(request.user)):
        label = dict(ClassificationRule.MATCH_TYPE_CHOICES).get(
            rule.match_type, rule.match_type
        )
        messages.warning(
            request,
            f'This rule has match type "{label}", which you cannot assign. '
            f'Saving will change it to the match type shown below.',
        )


def _assign_parsed_metadata(rule, form: dict) -> None:
    """Refresh the parsed metadata columns from the rule's current source text.

    Every field is assigned, including the empty ones, so changing a filepath rule's
    path does not leave the previous `normalized_filepath` behind still matching the
    old path. Same field set and semantics as the `reparse_rules` command.
    """
    parsed = parse_rule_line(form['source_text'], status=form['status'])
    if parsed and form['match_type'] in (
        ClassificationRule.MATCH_PARSED_ENTRY, ClassificationRule.MATCH_FILEPATH
    ):
        parsed['match_type'] = form['match_type']
    for field in REPARSE_FIELDS:
        if parsed is None:
            blank = False if field in ('file_not_signed', 'is_hidden') else ''
            setattr(rule, field, blank)
        else:
            setattr(rule, field, parsed.get(field))


def _rule_id_from_query(query: str) -> int | None:
    """The rule id a search names ("27617" or "#27617"), or None."""
    digits = query.strip().removeprefix('#').strip()
    if not digits.isdigit() or not digits.isascii():
        return None
    return int(digits)


def _rule_for_editor_or_404(request, pk):
    """The rule `request.user` may edit: their own, or any rule for a superuser.
    The rule keeps its owner either way."""
    rules = ClassificationRule.objects.select_related('owner')
    if not request.user.is_superuser:
        rules = rules.filter(owner=request.user)
    return get_object_or_404(rules, pk=pk)


def _apply_rule_edit(rule, form: dict, user) -> str | None:
    """Validate and save an edit to one rule. Returns an error message, or None.

    Shared by the quick-edit panel on the rules list and the full-page editor so the
    two cannot drift. `source_text` is a single value -- never split per line -- so a
    script rule keeps its newlines and one rule in stays one rule out.

    `user` is the editor and decides what may be authored (script rules). The
    duplicate check and cache invalidation follow the rule's owner, who differs
    from the editor when a superuser edits another helper's rule via the API.
    """
    priority = _coerce_priority(form['priority'], form['match_type'])
    script_error = _script_rule_error(
        form['match_type'], form['source_text'], user, form['whole_log']
    )
    whole_log_error = _whole_log_error(form['whole_log'], form['status'], form['match_type'])

    if not form['source_text']:
        return 'Rule source text is required.'
    if form['status'] not in dict(ClassificationRule.CREATABLE_STATUS_CHOICES):
        return 'Invalid status.'
    if form['match_type'] not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
        return 'Invalid match type.'
    # An edit saves one rule, so line breaks would be stored inside a single
    # source_text and that rule would then never match a real log line. Script
    # rules are a genuine multi-line snippet and are exempt.
    if form['match_type'] != ClassificationRule.MATCH_SCRIPT and (
        '\n' in form['source_text'] or '\r' in form['source_text']
    ):
        return (
            'A rule matches a single line. Remove the line breaks, or use '
            '"add rule" to create one rule per line.'
        )
    if whole_log_error:
        return whole_log_error
    if script_error:
        return script_error
    if form.get('log_scope_error'):
        return form['log_scope_error']
    if form.get('conditions_error'):
        return form['conditions_error']
    if form.get('only_entry_types_error'):
        return form['only_entry_types_error']

    # Conditions are an advanced option: a form without them (the quick-edit
    # panel, the token API) keeps the rule's own, which must still suit it.
    new_conditions = form.get('conditions')
    conditions = new_conditions if new_conditions is not None else rule_condition_specs(rule)
    if conditions:
        problem = conditions_error(conditions, whole_log=form['whole_log'])
        if problem:
            return problem
    condition_key = condition_key_for(conditions)

    duplicate = ClassificationRule.objects.filter(
        owner_id=rule.owner_id, status=form['status'], match_type=form['match_type'],
        source_text=form['source_text'], whole_log=form['whole_log'], condition_key=condition_key,
    ).exclude(pk=rule.pk).exists()
    if duplicate:
        if condition_key:
            return DUPLICATE_CONDITIONS_ERROR
        return 'A rule with this status, match type, and source text already exists.'

    rule.status = form['status']
    rule.match_type = form['match_type']
    rule.source_text = form['source_text']
    rule.description = form['description']
    rule.is_enabled = form['is_enabled']
    rule.priority = priority
    rule.whole_log = form['whole_log']
    rule.color_whole_line = _color_whole_line_for(form['color_whole_line'], form['match_type'])
    if form.get('apply_to_block') is not None:
        rule.apply_to_block = form['apply_to_block']
    # A whole-log rule has no line, so no block either.
    rule.apply_to_block = rule.apply_to_block and not form['whole_log']
    if form.get('only_entry_types') is not None:
        rule.only_entry_types = list(form['only_entry_types'])
    # Nor a parsed type.
    if form['whole_log']:
        rule.only_entry_types = []
    _assign_parsed_metadata(rule, form)
    scope_fields = []
    if form.get('log_scope') is not None:
        rule.all_log_types, rule.log_types = form['log_scope'][0], list(form['log_scope'][1])
        scope_fields = ['all_log_types', 'log_types']
    # Saved with the rest, so the rule never passes through an identity
    # (new text, old conditions) that another rule may have. The key encodes
    # the conditions exactly, so an unchanged key means unchanged conditions.
    conditions_changed = new_conditions is not None and rule.condition_key != condition_key
    rule.condition_key = condition_key
    try:
        # One transaction: a failed condition write must not leave the rule
        # with a condition_key its RuleCondition rows do not match.
        with transaction.atomic():
            rule.save(update_fields=[
                'status', 'match_type', 'source_text', 'description', 'is_enabled', 'priority',
                'whole_log', 'color_whole_line', 'apply_to_block', 'only_entry_types', *scope_fields, *REPARSE_FIELDS,
                'condition_key', 'updated_at',
            ])
            if conditions_changed:
                set_rule_conditions(rule, new_conditions)
    except ValueError as error:
        return str(error)
    # Tags are looked up when an analysis is served, not baked into the cached
    # result, so changing them needs no invalidation of their own.
    if form.get('tag_ids') is not None:
        _set_rule_tags([rule], form['tag_ids'])
    invalidate_for_rule_owner(rule.owner)
    return None


def _rule_form_context(user, form: dict, *, editing: bool, return_q: str = '', rule=None) -> dict:
    """Context for add_rule.html, which serves both the add page and the editor."""
    cancel_url = reverse('rules')
    if return_q:
        cancel_url = f"{cancel_url}?{return_q}"

    tag_ids = form.get('tag_ids')
    if tag_ids is None:
        tag_ids = list(rule.tags.values_list('pk', flat=True)) if rule else []
    tags_by_id = {tag.pk: tag for tag in RuleTag.objects.filter(pk__in=tag_ids).select_related('category')}

    log_scope = form.get('log_scope') or default_rule_scope(form['match_type'])
    log_type_choices = known_log_type_names()
    # A stored type no longer defined anywhere stays checked (saving keeps it), with a warning.
    unknown_log_types = [name for name in log_scope[1] if name not in log_type_choices]

    return {
        'unknown_log_types': unknown_log_types,
        # For RuleForm.createLogScopePicker (json_script in add_rule.html).
        'log_scope_picker': {
            'choices': log_type_choices + unknown_log_types,
            'value': scope_payload(*log_scope),
            'unknown': unknown_log_types,
            'defaults': list(DEFAULT_RULE_LOG_TYPES),
            # The user's own pick (a re-shown POST, or a kept query) is not overridden by match type changes.
            'chosen': form.get('log_scope') is not None,
            # A refused scope re-renders the form; the editor opens the tab holding it.
            'error': bool(form.get('log_scope_error')),
        },
        'log_preview_scope_text': _log_preview_scope_text(_log_preview_log_types(scope_payload(*log_scope))),
        'form_tags_json': [serialize_tag(tags_by_id[pk]) for pk in tag_ids if pk in tags_by_id],
        'editing': editing,
        'rule': rule,
        'return_q': return_q,
        'cancel_url': cancel_url,
        'status_choices': ClassificationRule.STATUS_CHOICES,
        'creatable_status_choices': ClassificationRule.CREATABLE_STATUS_CHOICES,
        'match_type_choices': ClassificationRule.MATCH_TYPE_CHOICES,
        'creatable_match_type_choices': _creatable_match_type_choices(user),
        'form_status': form['status'],
        'form_match_type': form['match_type'],
        'form_source_text': form['source_text'],
        'form_description': form['description'],
        'form_priority': form['priority'],
        'form_whole_log': form['whole_log'],
        'form_color_whole_line': form['color_whole_line'],
        # None (a POST without the box, e.g. the quick edit's hand-off): the rule's own.
        'form_apply_to_block': bool(
            form.get('apply_to_block') if form.get('apply_to_block') is not None
            else isinstance(rule, ClassificationRule) and rule.apply_to_block
        ),
        # Same for the parsed types; a fact rule has them too.
        'form_only_entry_types': (
            form.get('only_entry_types') if form.get('only_entry_types') is not None
            else list(getattr(rule, 'only_entry_types', None) or [])
        ),
        'entry_type_choices': entry_type_choices(),
        'form_is_enabled': form['is_enabled'],
        'default_priority_by_match_type': DEFAULT_PRIORITY_BY_MATCH_TYPE,
        'default_priority_by_match_type_json': json.dumps(DEFAULT_PRIORITY_BY_MATCH_TYPE),
        'priority_min': PRIORITY_MIN,
        'priority_max': PRIORITY_MAX,
        'priority_choices': _priority_choices(),
        'log_preview_max_logs': LOG_PREVIEW_MAX_LOGS,
        **_fact_mode_context(form, editing=editing, rule=rule),
        **_conditions_context(form, rule=rule),
    }


def _conditions_context(form: dict, *, rule=None) -> dict:
    """The conditions block of add_rule.html (advanced options): the
    conditions to show and the facts to pick from. Fact rules have none."""
    conditions = form.get('conditions')
    if conditions is None:
        conditions = rule_condition_specs(rule) if isinstance(rule, ClassificationRule) else []
    return {
        'conditions_offered': not isinstance(rule, FactRule),
        'conditions_data': {
            'conditions': [
                {'fact_id': spec.fact_id, 'polarity': spec.polarity, 'scope': spec.scope} for spec in conditions
            ],
            'facts': [{'id': pk, 'name': name} for pk, name in Fact.objects.order_by('name').values_list('pk', 'name')],
            'polarities': [{'value': v, 'label': label} for v, label in RuleCondition.POLARITY_CHOICES],
            'scopes': [{'value': v, 'label': label} for v, label in RuleCondition.SCOPE_CHOICES],
            'max': RuleCondition.MAX_PER_RULE,
        },
        'has_conditions': bool(conditions),
    }


def _fact_mode_context(form: dict, *, editing: bool, rule=None) -> dict:
    """The "fact" choice in add_rule.html's status dropdown (records a fact
    instead of setting a status): offered when adding, the only choice when
    editing a fact rule. Editing a classification rule never shows it."""
    from .facts import FACT_STATUS_VALUE

    is_fact_rule = isinstance(rule, FactRule)
    offered = is_fact_rule or not editing
    return {
        'fact_status_value': FACT_STATUS_VALUE,
        'fact_mode_offered': offered,
        'fact_mode_locked': is_fact_rule,
        'fact_choices': list(Fact.objects.order_by('name').only('pk', 'name')) if offered else [],
        'form_record_fact': is_fact_rule or bool(form.get('record_fact')),
        'form_fact_id': form.get('fact_id') or '',
        'form_new_fact_name': form.get('new_fact_name') or '',
        'fact_name_max_length': Fact.NAME_MAX_LENGTH,
    }


def _owned_rule_id(raw, user):
    """Coerce a caller-supplied rule id, keeping it only if `user` owns that rule."""
    if raw is None or raw == '':
        return None
    try:
        rule_id = int(raw)
    except (TypeError, ValueError):
        return None
    if not ClassificationRule.objects.filter(pk=rule_id, owner=user).exists():
        return None
    return rule_id


def _format_skipped(skipped: list, limit: int = 5) -> str:
    """Format a short summary of skipped patterns for a user-facing message."""
    if not skipped:
        return ''
    shown = skipped[:limit]
    parts = ', '.join(repr(s) for s in shown)
    if len(skipped) > limit:
        parts += f', … and {len(skipped) - limit} more'
    return parts


@login_required
@require_http_methods(["GET", "POST"])
def rules_view(request):
    """Manage classification rules: create, edit, delete, view others'."""
    STATUS_MAP = dict(ClassificationRule.STATUS_CHOICES)
    MATCH_TYPE_MAP = dict(ClassificationRule.MATCH_TYPE_CHOICES)

    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'create':
            log_scope, log_scope_error = _log_scope_from_post(request)
            if log_scope_error:
                messages.error(request, log_scope_error)
                return redirect('rules')
            created, skipped, error = create_rules(
                request.user,
                status=request.POST.get('status', '').strip(),
                match_type=request.POST.get('match_type', '').strip(),
                source_text=request.POST.get('source_text', '').strip(),
                description=request.POST.get('description', '').strip(),
                raw_priority=request.POST.get('priority', '').strip(),
                whole_log=request.POST.get('whole_log') == 'on',
                color_whole_line=request.POST.get('color_whole_line') == 'on',
                tag_ids=_tag_ids_from_post(request),
                source_name=f'web-rules:{request.user.username}',
                log_scope=log_scope,
            )
            if error:
                messages.error(request, error)
            else:
                _report_created_rules(request, created, skipped)
            return redirect('rules')

        if action == 'edit':
            pk = request.POST.get('pk', '').strip()
            rule = _rule_for_editor_or_404(request, pk)
            error = _apply_rule_edit(rule, _rule_form_from_post(request), request.user)
            if error:
                messages.error(request, error)
            else:
                messages.success(request, 'Rule updated.')
            return redirect_with_return_q('rules', request.POST.get('return_q', ''))

        if action == 'delete':
            pk = request.POST.get('pk', '').strip()
            rule = _rule_for_editor_or_404(request, pk)
            owner = rule.owner
            rule.delete()
            invalidate_for_rule_owner(owner)
            messages.success(request, 'Rule deleted.')
            return redirect_with_return_q('rules', request.POST.get('return_q', ''))

        if action == 'toggle':
            pk = request.POST.get('pk', '').strip()
            rule = _rule_for_editor_or_404(request, pk)
            rule.is_enabled = not rule.is_enabled
            rule.save(update_fields=['is_enabled', 'updated_at'])
            invalidate_for_rule_owner(rule.owner)
            label = 'enabled' if rule.is_enabled else 'disabled'
            messages.success(request, f'Rule {label}.')
            return redirect('rules')

    filter_mode = request.GET.get('filter', 'own')
    filter_status = request.GET.get('status', '')
    filter_match = request.GET.get('match', '')
    search_q = request.GET.get('q', '').strip()
    search_mode = request.GET.get('search_mode', 'text')
    if search_mode not in ('text', 'line', 'id'):
        search_mode = 'text'
    sort = request.GET.get('sort', 'recent')

    SORT_OPTIONS = {
        'recent': '-updated_at',
        'created': '-created_at',
        'status': ('status', 'match_type', 'source_text'),
        'priority': ('-priority', 'status', 'match_type', 'source_text'),
    }

    if filter_mode == 'all':
        owner_q = Q()
    elif filter_mode == 'others':
        owner_q = ~Q(owner=request.user)
    else:
        filter_mode = 'own'
        owner_q = Q(owner=request.user)
    rules = ClassificationRule.objects.select_related('owner')
    # The id search ("27617" or "#27617") finds that rule whoever owns it -- ids
    # come up in the MCP API and analyzer tooltips, and the own/others tab should
    # not hide the one rule asked for. Text search does not look at ids.
    id_search = search_mode == 'id' and bool(search_q)
    search_rule_id = _rule_id_from_query(search_q) if id_search else None
    if not id_search:
        rules = rules.filter(owner_q)

    # Rules must carry every picked tag. `tag` is the older single-tag param,
    # still used by bookmarks; it is folded into `tags`.
    filter_tag_ids = parse_tag_ids(request.GET.getlist('tags') + request.GET.getlist('tag'))
    # One join per tag; each matches at most one row per rule, so no duplicates.
    for tag_id in filter_tag_ids:
        rules = rules.filter(tags=tag_id)
    rules = rules.prefetch_related('tags')
    selected_tags = selected_tags_for_picker(filter_tag_ids)

    filter_priority = request.GET.get('priority', '').strip()
    if filter_priority.isdigit() and PRIORITY_MIN <= int(filter_priority) <= PRIORITY_MAX:
        filter_priority = str(int(filter_priority))
        rules = rules.filter(priority=int(filter_priority))
    else:
        filter_priority = ''

    # Appended to the tab, clear and pagination links so they keep these filters.
    extra_filter_params = [('tags', tag_id) for tag_id in filter_tag_ids]
    if filter_priority:
        extra_filter_params.append(('priority', filter_priority))
    extra_filter_query = ('&' + urlencode(extra_filter_params)) if extra_filter_params else ''

    if filter_status and filter_status in dict(ClassificationRule.STATUS_CHOICES):
        rules = rules.filter(status=filter_status)
    if filter_match and filter_match in dict(ClassificationRule.MATCH_TYPE_CHOICES):
        rules = rules.filter(match_type=filter_match)
    if search_q:
        if search_mode == 'line':
            inspection = inspect_line_matches(search_q)
            ordered_ids = []
            seen = set()
            for m in inspection['matches'] + inspection.get('shadowed_matches', []):
                if m['id'] not in seen:
                    ordered_ids.append(m['id'])
                    seen.add(m['id'])
            rules = rules.filter(id__in=ordered_ids).order_by(
                Case(*[When(id=rid, then=pos) for pos, rid in enumerate(ordered_ids)])
            )
        elif search_mode == 'id':
            rules = rules.filter(pk=search_rule_id) if search_rule_id is not None else rules.none()
        else:
            rules = rules.filter(Q(source_text__icontains=search_q) | Q(description__icontains=search_q))
    else:
        sort_value = SORT_OPTIONS.get(sort, '-updated_at')
        if isinstance(sort_value, tuple):
            rules = rules.order_by(*sort_value)
        else:
            rules = rules.order_by(sort_value)

    paginator = Paginator(rules, 12)
    page_obj = paginator.get_page(request.GET.get('page'))

    context = {
        'page_obj': page_obj,
        'filter_mode': filter_mode,
        'filter_status': filter_status,
        'filter_match': filter_match,
        'selected_tags': selected_tags,
        'filter_priority': filter_priority,
        'extra_filter_query': extra_filter_query,
        'tag_filter_title': 'only rules that have every selected tag',
        'search_q': search_q,
        'search_mode': search_mode,
        'sort': sort,
        'current_query_string': request.GET.urlencode(),
        'status_choices': ClassificationRule.STATUS_CHOICES,
        'creatable_status_choices': ClassificationRule.CREATABLE_STATUS_CHOICES,
        'match_type_choices': ClassificationRule.MATCH_TYPE_CHOICES,
        'creatable_match_type_choices': _creatable_match_type_choices(request.user),
        'status_map': STATUS_MAP,
        'match_type_map': MATCH_TYPE_MAP,
        'default_priority_by_match_type': DEFAULT_PRIORITY_BY_MATCH_TYPE,
        'default_priority_by_match_type_json': json.dumps(DEFAULT_PRIORITY_BY_MATCH_TYPE),
        'priority_min': PRIORITY_MIN,
        'priority_max': PRIORITY_MAX,
        'priority_choices': _priority_choices(),
    }
    return render(request, 'rules.html', context)


def create_rules(user, *, status, match_type, source_text, description='', raw_priority='',
                 whole_log=False, color_whole_line=False, tag_ids=None, source_name='',
                 log_scope=None, conditions=None, apply_to_block=False, only_entry_types=None):
    """Validate and create rules for `user`, one per line of `source_text` (a script rule stays one).

    Returns ``(created, skipped, error)``: the new rules, the patterns skipped
    as duplicates of the user's existing rules, and an error message (nothing
    created) or None. `tag_ids` None leaves the tags to auto-apply; a list
    becomes the new rules' tags. `log_scope` is `(all_log_types, log_types)`;
    None gives the match type's default (log_types.default_rule_scope).
    `conditions` (fact_service.ConditionSpec list, advanced) makes them
    conditional rules; `apply_to_block` (advanced) gives their verdict to the
    whole block of a line they decide; `only_entry_types` (advanced) limits
    them to lines parsed as those types. Shared by the add-rule page and the
    token API.
    """
    conditions = list(conditions or [])
    only_entry_types, entry_types_problem = clean_entry_types(only_entry_types)
    if entry_types_problem:
        return [], [], entry_types_problem
    color_whole_line = _color_whole_line_for(color_whole_line, match_type)
    patterns = _patterns_for(match_type, source_text)
    script_error = _script_rule_error(match_type, source_text, user, whole_log)
    whole_log_error = _whole_log_error(whole_log, status, match_type)
    if not patterns:
        return [], [], 'Rule source text is required.'
    if status not in dict(ClassificationRule.CREATABLE_STATUS_CHOICES):
        return [], [], 'Invalid status.'
    if match_type not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
        return [], [], 'Invalid match type.'
    if whole_log_error:
        return [], [], whole_log_error
    if script_error:
        return [], [], script_error
    conditions_problem = conditions_error(conditions, whole_log=whole_log) if conditions else None
    if conditions_problem:
        return [], [], conditions_problem

    priority = _coerce_priority(raw_priority, match_type)
    all_log_types, log_types = log_scope or default_rule_scope(match_type)
    condition_key = condition_key_for(conditions)
    existing = set(
        ClassificationRule.objects.filter(
            owner=user,
            status=status,
            match_type=match_type,
            whole_log=whole_log,
            condition_key=condition_key,
            source_text__in=patterns,
        ).values_list('source_text', flat=True)
    )

    to_create = []
    skipped = []
    for pattern in patterns:
        if pattern in existing:
            skipped.append(pattern)
            continue
        parsed = parse_rule_line(pattern, status=status, source_name=source_name)
        if parsed and match_type in (ClassificationRule.MATCH_PARSED_ENTRY, ClassificationRule.MATCH_FILEPATH):
            parsed['match_type'] = match_type
        create_kwargs = {
            'owner': user,
            'status': status,
            'match_type': match_type,
            'source_text': pattern,
            'description': description,
            'priority': priority,
            'whole_log': whole_log,
            'color_whole_line': color_whole_line,
            'apply_to_block': bool(apply_to_block) and not whole_log,
            'only_entry_types': [] if whole_log else list(only_entry_types),
            'all_log_types': all_log_types,
            'log_types': list(log_types),
            'condition_key': condition_key,
        }
        if parsed:
            for field in (*REPARSE_FIELDS, 'source_name'):
                if parsed.get(field):
                    create_kwargs[field] = parsed[field]
        to_create.append(ClassificationRule(**create_kwargs))

    if not to_create:
        return [], skipped, None
    # One transaction: a rule with a condition_key must never be left without
    # its RuleCondition rows (e.g. a fact deleted meanwhile).
    with transaction.atomic():
        created = ClassificationRule.objects.bulk_create(to_create)
        if conditions:
            RuleCondition.objects.bulk_create([
                RuleCondition(rule=rule, fact_id=spec.fact_id, polarity=spec.polarity, scope=spec.scope)
                for rule in created for spec in conditions
            ])
    # bulk_create sends no signals, so auto tags are added here.
    auto_tag_rules(created)
    # The picker already shows the auto tags filled in, so with a
    # picker its tags are the rules' tags - a removed auto tag stays off.
    if tag_ids is not None:
        _set_rule_tags(created, tag_ids)
    invalidate_for_rule_owner(user)
    return created, skipped, None


def _kept_log_scope_params(log_scope, match_type) -> dict:
    """Query params that carry a log type scope over to the next add page, or
    {} when it is just the match type's default. The picker always posts its
    value; carried over, the next page would take it as the user's own choice
    and stop following the match type (file path rules: all log types)."""
    if log_scope is None:
        return {}
    all_log_types, log_types = log_scope
    default_all, default_types = default_rule_scope(match_type)
    if all_log_types == default_all and (all_log_types or sorted(log_types) == sorted(default_types)):
        return {}
    return {
        'log_scope': ALL_LOG_TYPES if all_log_types else 'selected',
        'log_types': list(log_types),
    }


def _report_created_rules(request, created, skipped, noun='rule') -> bool:
    """Flash the outcome of `create_rules` (or create_fact_rules, `noun` "fact
    rule"); return True when any rule was created."""
    m = len(skipped)
    skipped_text = f'{m} duplicate{"" if m == 1 else "s"} skipped: {_format_skipped(skipped)}' if m else ''
    if not created:
        messages.error(request, f'No {noun}s created. {skipped_text}')
        return False
    n = len(created)
    messages.success(request, f'{n} {noun}{"" if n == 1 else "s"} created.')
    if skipped_text:
        messages.warning(request, skipped_text)
    return True


@login_required
@require_http_methods(["GET", "POST"])
def add_rule_view(request):
    """Dedicated page for adding a new classification rule with log preview."""
    form_status = request.GET.get('status', '').strip()
    form_match_type = request.GET.get('match_type', '').strip()
    form_source_text = ''
    form_description = ''
    form_priority = ''
    form_whole_log = request.GET.get('whole_log') == '1'
    form_color_whole_line = request.GET.get('color_whole_line') == '1'
    form_apply_to_block = False
    # Advanced: only lines parsed as these types (frst_extractors.ENTRY_TYPES).
    form_only_entry_types = []
    # None: the post had no tag picker, so auto-apply alone decides the tags.
    form_tag_ids = None
    # Advanced: the conditions of the new rules (fact_service.ConditionSpec list).
    form_conditions = None
    # None: the match type's default scope. Kept across "create" via the query string.
    form_log_scope = _log_scope_from_query(request.GET)
    log_scope_error = None

    if form_status not in dict(ClassificationRule.CREATABLE_STATUS_CHOICES):
        form_status = ClassificationRule.STATUS_MALWARE
    if form_match_type not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
        form_match_type = ClassificationRule.MATCH_EXACT

    # Advanced option: record a fact instead of setting a status (views.facts).
    fact_fields = {
        'record_fact': request.GET.get('record_fact') == '1',
        'fact_id': request.GET.get('fact', '').strip(),
        'new_fact_name': '',
    }
    if request.method == 'POST':
        from .facts import create_fact_rules, fact_form_fields, fact_rule_add_redirect

        fact_fields = fact_form_fields(request)

    if request.method == 'POST' and fact_fields['record_fact']:
        match_type = request.POST.get('match_type', '').strip()
        source_text = request.POST.get('source_text', '').strip()
        description = request.POST.get('description', '').strip()
        whole_log = request.POST.get('whole_log') == 'on'
        form_status = request.POST.get('status', '').strip() or form_status
        form_match_type = match_type
        form_source_text = source_text
        form_description = description
        form_priority = request.POST.get('priority', '').strip()
        form_whole_log = whole_log
        form_log_scope, log_scope_error = _log_scope_from_post(request)
        posted_types, entry_types_problem = entry_types_from_post(request)
        form_only_entry_types = posted_types or []
        if log_scope_error or entry_types_problem:
            messages.error(request, log_scope_error or entry_types_problem)
        else:
            fact, created, skipped, error = create_fact_rules(
                request.user,
                fact_id=fact_fields['fact_id'],
                new_fact_name=fact_fields['new_fact_name'],
                match_type=match_type,
                source_text=source_text,
                description=description,
                whole_log=whole_log,
                source_name=f'web-add-rule:{request.user.username}',
                log_scope=form_log_scope,
                only_entry_types=form_only_entry_types,
            )
            if error:
                messages.error(request, error)
            elif _report_created_rules(request, created, skipped, noun='fact rule'):
                return fact_rule_add_redirect(fact, match_type, whole_log, form_log_scope)
            if fact is not None:
                # A new fact was created or reused: offer it as the selection.
                fact_fields = {**fact_fields, 'fact_id': str(fact.pk), 'new_fact_name': ''}
    elif request.method == 'POST':
        status = request.POST.get('status', '').strip()
        match_type = request.POST.get('match_type', '').strip()
        source_text = request.POST.get('source_text', '').strip()
        description = request.POST.get('description', '').strip()
        whole_log = request.POST.get('whole_log') == 'on'
        color_whole_line = _color_whole_line_for(
            request.POST.get('color_whole_line') == 'on', match_type
        )
        raw_priority = request.POST.get('priority', '').strip()
        form_status = status
        form_match_type = match_type
        form_source_text = source_text
        form_description = description
        form_priority = raw_priority
        form_whole_log = whole_log
        form_color_whole_line = color_whole_line
        form_tag_ids = _tag_ids_from_post(request)
        form_log_scope, log_scope_error = _log_scope_from_post(request)
        form_conditions, conditions_problem = _conditions_from_post(request)
        form_apply_to_block = bool(_apply_to_block_from_post(request))
        posted_types, entry_types_problem = entry_types_from_post(request)
        form_only_entry_types = posted_types or []
        if log_scope_error or conditions_problem or entry_types_problem:
            created, skipped, error = [], [], log_scope_error or conditions_problem or entry_types_problem
        else:
            created, skipped, error = create_rules(
                request.user,
                status=status,
                match_type=match_type,
                source_text=source_text,
                description=description,
                raw_priority=raw_priority,
                whole_log=whole_log,
                color_whole_line=color_whole_line,
                tag_ids=form_tag_ids,
                source_name=f'web-add-rule:{request.user.username}',
                log_scope=form_log_scope,
                conditions=form_conditions,
                apply_to_block=form_apply_to_block,
                only_entry_types=form_only_entry_types,
            )
        if error:
            messages.error(request, error)
        elif _report_created_rules(request, created, skipped):
            keep_params = {'status': status, 'match_type': match_type}
            if whole_log:
                keep_params['whole_log'] = '1'
            if color_whole_line:
                keep_params['color_whole_line'] = '1'
            keep_params.update(_kept_log_scope_params(form_log_scope, match_type))
            return redirect(f"{reverse('add_rule')}?{urlencode(keep_params, doseq=True)}")

    form = {
        'status': form_status,
        'match_type': form_match_type,
        'source_text': form_source_text,
        'description': form_description,
        'priority': form_priority,
        'whole_log': form_whole_log,
        'color_whole_line': form_color_whole_line,
        'apply_to_block': form_apply_to_block,
        'only_entry_types': form_only_entry_types,
        # New rules are always created enabled; the add form has no such field.
        'is_enabled': True,
        'tag_ids': form_tag_ids or [],
        'log_scope': form_log_scope,
        'log_scope_error': log_scope_error,
        'conditions': form_conditions,
        **fact_fields,
    }
    return render(
        request, 'add_rule.html', _rule_form_context(request.user, form, editing=False)
    )


@login_required
@require_http_methods(["GET", "POST"])
def edit_rule_view(request, pk: int):
    """Full-page editor for one rule: the add-rule form plus its live line preview.

    Shares `add_rule.html` with `add_rule_view` (the same way `edit_log_type_rule_view`
    shares its template) and saves through `_apply_rule_edit`, so the quick-edit panel
    on the rules list and this page apply identical rules.
    """
    rule = _rule_for_editor_or_404(request, pk)

    if request.method == 'POST':
        return_q = request.POST.get('return_q', '')
        form = _rule_form_from_post(request)
        # A POST without the picker (the quick edit's hand-off) keeps the
        # rule's own scope, both when saving and when shown here.
        if form['log_scope'] is None and not form['log_scope_error']:
            form['log_scope'] = (rule.all_log_types, list(rule.log_types or []))
        # The quick-edit panel hands over by POSTing its own form here so whatever the
        # user had typed survives the jump. That hand-off only prefills this page --
        # it never saves. Its own field name, so it cannot collide with the `action`
        # the quick-edit form already carries for `rules_view`.
        if not request.POST.get('open_editor'):
            error = _apply_rule_edit(rule, form, request.user)
            if error:
                messages.error(request, error)
            else:
                messages.success(request, 'Rule updated.')
                return redirect_with_return_q('rules', return_q)
    else:
        return_q = request.GET.get('return_q', '')
        form = _rule_form_from_rule(rule)

    _warn_about_unassignable_values(request, rule)
    return render(request, 'add_rule.html', _rule_form_context(
        request.user, form,
        editing=True, return_q=sanitize_return_q(return_q), rule=rule,
    ))


CASE_INSENSITIVE_FLAG = '(?i)'


def _regex_pattern_warnings(patterns) -> list[dict]:
    """Warnings for valid but suspect regex patterns, one entry per pattern that
    has any: rejected by re2 (fallback), slow on adversarial input (slow), or
    starting with the (?i) flag, which makes regex matching slow
    (case_insensitive)."""
    regex_warnings = []
    for pattern in patterns:
        evaluation = evaluate_regex_pattern(pattern)
        warning_kinds = []
        if not evaluation['re2_ok']:
            warning_kinds.append('fallback')
        if evaluation['is_slow']:
            warning_kinds.append('slow')
        if pattern.lstrip().startswith(CASE_INSENSITIVE_FLAG):
            warning_kinds.append('case_insensitive')
        if not warning_kinds:
            continue
        regex_warnings.append({
            'pattern': pattern,
            'kinds': warning_kinds,
            're2_error': evaluation['re2_error'],
            'worst_ms': round(evaluation['worst_ms'], 2),
            'worst_input': evaluation['worst_input'],
        })
    return regex_warnings


def _read_rule_test_payload(request):
    """Parse and validate the rule definition the two rule preview APIs share.

    Returns ``(payload, rule, error_response)``: the raw JSON payload, the cleaned
    rule fields with the source split into ``patterns``, and an error response
    that is set (and the other two None) when the request must be refused.
    """
    payload, error = PayloadValidator.json_object(request)
    if error:
        return None, None, error

    source_text = (payload.get('source_text') or '').strip()
    status = (payload.get('status') or '?').strip()
    match_type = (payload.get('match_type') or '').strip()
    raw_priority = payload.get('priority')
    whole_log = bool(payload.get('whole_log'))

    def refuse(message, status_code=400):
        return None, None, JsonResponse({'error': message}, status=status_code)

    if not source_text:
        return refuse('Field "source_text" is required.')
    if status not in VALID_STATUSES:
        status = '?'

    # Previewing a script rule executes the submitted snippet, so it is gated to
    # moderators exactly like authoring one.
    if match_type == ClassificationRule.MATCH_SCRIPT and not is_moderator(request.user):
        return refuse('Script rules can only be tested by moderators.', 403)

    if raw_priority is None or raw_priority == '':
        priority = None
    else:
        try:
            priority = max(PRIORITY_MIN, min(PRIORITY_MAX, int(raw_priority)))
        except (TypeError, ValueError):
            priority = None

    patterns = _patterns_for(match_type, source_text)
    if not patterns:
        return refuse('Field "source_text" is required.')
    if len(patterns) > 100:
        return refuse('At most 100 patterns are allowed.')
    if whole_log and match_type not in (ClassificationRule.MATCH_REGEX, ClassificationRule.MATCH_SCRIPT):
        return refuse('Whole-log rules support only regex and script match types.')
    only_entry_types, entry_types_problem = clean_entry_types(payload.get('only_entry_types'))
    if entry_types_problem:
        return refuse(entry_types_problem)

    return payload, {
        'patterns': patterns,
        'status': status,
        'match_type': match_type,
        'priority': priority,
        'whole_log': whole_log,
        'only_entry_types': [] if whole_log else only_entry_types,
        # The rule editor passes the rule it is editing so the preview reports the
        # lines as they would look without it -- otherwise the saved copy shows up
        # as an existing match and can appear to shadow the user's own pending
        # edit. Honoured only for a rule the caller owns.
        'exclude_rule_id': _owned_rule_id(payload.get('exclude_rule_id'), request.user),
    }, None


@login_required
@require_http_methods(["POST"])
def test_rule_api(request):
    """Test a rule definition against a list of log lines and return per-line match results."""
    payload, rule, error_response = _read_rule_test_payload(request)
    if error_response:
        return error_response

    lines = payload.get('lines', [])
    if not isinstance(lines, list) or len(lines) > 500:
        return JsonResponse({'error': 'Field "lines" must be a list with at most 500 entries.'}, status=400)

    patterns = rule['patterns']
    status = rule['status']
    match_type = rule['match_type']

    # Whole-log rules run once against the entire log (regex / script only), so the
    # preview reconstructs the pasted text and returns a single log-level verdict.
    if rule['whole_log']:
        log_text = '\n'.join(str(line) for line in lines)
        try:
            result_payload = build_wholelog_rule_test_result(patterns, match_type, log_text)
        except ValueError as exc:
            return JsonResponse({'error': str(exc)}, status=400)
        if match_type == ClassificationRule.MATCH_REGEX:
            regex_warnings = _regex_pattern_warnings(patterns)
            if regex_warnings:
                result_payload['regex_warnings'] = regex_warnings
        return JsonResponse(result_payload)

    try:
        response_payload = build_rule_test_results(
            patterns=patterns,
            status=status,
            match_type=match_type,
            lines=lines,
            priority=rule['priority'],
            exclude_rule_id=rule['exclude_rule_id'],
            only_entry_types=rule['only_entry_types'],
        )
    except ValueError as exc:
        return JsonResponse({'error': str(exc)}, status=400)

    if match_type == ClassificationRule.MATCH_REGEX:
        # Invalid patterns are already rejected with HTTP 400 by
        # build_rule_test_results, so by the time we get here every pattern
        # compiles in stdlib re.
        regex_warnings = _regex_pattern_warnings(patterns)
        if regex_warnings:
            response_payload['regex_warnings'] = regex_warnings

    return JsonResponse(response_payload)


# The stored-log preview reruns on every edit in the rule editor, so each request
# is bounded three ways: how many logs it reads, how many distinct matched lines
# it returns, and wall-clock time.
LOG_PREVIEW_MAX_LOGS = 50
LOG_PREVIEW_MAX_LINES = 200
LOG_PREVIEW_TIME_BUDGET_S = 3.0
# Only complete scans: FRST and Addition merged into one log.
LOG_PREVIEW_LOG_TYPE = 'FRST&Addition'


def _log_preview_log_types(raw_scope):
    """The log types whose newest uploads the stored-log preview scans: exactly
    the rule's types, or ALL_LOG_TYPES (no type filter) for "all log types".
    A request without a valid scope scans FRST&Addition logs, as it always has.
    """
    if raw_scope is None:
        return [LOG_PREVIEW_LOG_TYPE]
    scope, error = normalize_log_type_selection(raw_scope)
    if error:
        return [LOG_PREVIEW_LOG_TYPE]
    return ALL_LOG_TYPES if scope[0] else list(scope[1])


def _first_log_types(matches, log_type_by_upload) -> list:
    """The log type of the first log each scanned line was found in (None if unknown)."""
    return [
        log_type_by_upload.get(entry['logs'][0]['upload_id']) if entry.get('logs') else None
        for entry in matches
    ]


def _log_preview_scope_text(log_types) -> str:
    """The editor's wording for what _log_preview_log_types scans."""
    if log_types == ALL_LOG_TYPES:
        return 'newest uploaded logs of every type'
    return f"newest uploaded {', '.join(log_types)} logs"


@deny_guests
@login_required
@require_http_methods(["POST"])
def test_rule_logs_api(request):
    """Test a rule definition against the newest stored logs.

    Scans the logs of the rule's log types (see _log_preview_log_types) the
    user can open in the analyzer (own and
    general channel, not trashed) and returns the distinct lines the rule matches, each with the
    same per-line verdict `test_rule_api` gives plus the logs it occurs in. A
    whole-log alert rule instead returns the logs it would fire on.
    """
    payload, rule, error_response = _read_rule_test_payload(request)
    if error_response:
        return error_response

    patterns = rule['patterns']
    match_type = rule['match_type']
    log_types = _log_preview_log_types(payload.get('log_types'))

    if match_type == ClassificationRule.MATCH_REGEX:
        # The paste preview only warns about slow patterns; run over dozens of
        # whole logs one could stall the worker, so it is refused here.
        for pattern in patterns:
            evaluation = evaluate_regex_pattern(pattern)
            if evaluation['stdlib_ok'] and evaluation['is_slow']:
                return JsonResponse({
                    'error': 'This regex is too slow to run against stored logs '
                             f"({evaluation['worst_ms']:.0f} ms on a {evaluation['worst_input']} input).",
                }, status=400)

    logs = get_action_scoped_uploads(request.user).live()
    if log_types != ALL_LOG_TYPES:
        logs = logs.filter(log_type__in=log_types)
    rows = (
        logs
        .order_by('-created_at')
        .values_list('upload_id', 'content', 'log_type')[:LOG_PREVIEW_MAX_LOGS]
        .iterator(chunk_size=10)
    )
    # Each matched line's existing verdict uses the rules of its log's type.
    log_type_by_upload = {}

    def corpus():
        for upload_id, content, log_type in rows:
            log_type_by_upload[upload_id] = log_type
            yield upload_id, content

    logs = corpus()
    deadline = time.monotonic() + LOG_PREVIEW_TIME_BUDGET_S

    try:
        if rule['whole_log']:
            response_payload = scan_logs_for_wholelog_matches(
                patterns, match_type, logs, deadline=deadline,
            )
        else:
            scan = scan_logs_for_rule_matches(
                patterns, rule['status'], match_type, logs,
                max_lines=LOG_PREVIEW_MAX_LINES, deadline=deadline,
                only_entry_types=rule['only_entry_types'],
            )
            matches = scan.pop('matches')
            response_payload = build_rule_test_results(
                patterns=patterns,
                status=rule['status'],
                match_type=match_type,
                lines=[entry['line'] for entry in matches],
                priority=rule['priority'],
                exclude_rule_id=rule['exclude_rule_id'],
                line_log_types=_first_log_types(matches, log_type_by_upload),
                only_entry_types=rule['only_entry_types'],
            )
            for result, entry in zip(response_payload['results'], matches):
                result['logs'] = entry['logs']
                result['log_count'] = entry['log_count']
            response_payload.update(scan)
    except ValueError as exc:
        return JsonResponse({'error': str(exc)}, status=400)

    response_payload['max_logs'] = LOG_PREVIEW_MAX_LOGS
    response_payload['max_lines'] = LOG_PREVIEW_MAX_LINES
    response_payload['log_types'] = log_types
    return JsonResponse(response_payload)
