"""
Classification rule management views.

Handles: creating, editing, deleting, testing, and viewing classification rules.
"""

import json
from urllib.parse import parse_qsl, urlencode
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.urls import reverse
from django.core.paginator import Paginator
from django.db.models import Q, Case, When

from .. import script_matcher
from ..analyzer import (
    parse_rule_line, inspect_line_matches, VALID_STATUSES,
    evaluate_regex_pattern, REPARSE_FIELDS,
)
from ..models import (
    ClassificationRule,
    DEFAULT_PRIORITY_BY_MATCH_TYPE,
    PRIORITY_DEFAULT_LABELS,
    PRIORITY_MAX,
    PRIORITY_MIN,
)
from ..rule_sets import invalidate_for_rule_owner
from ..rule_test_service import build_rule_test_results, build_wholelog_rule_test_result
from .guest import is_moderator


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


def _sanitize_return_q(raw) -> str:
    """Re-encode a caller-supplied rules-list query string, dropping anything that
    is not a valid key=value pair. A hostile value like `//evil.com` yields nothing,
    so callers fall back to the plain rules URL."""
    value = (raw or '').strip()
    if not value:
        return ''
    return urlencode(parse_qsl(value, keep_blank_values=True), doseq=True)


def _rules_redirect(return_q):
    """Back to the rules list, keeping the filter/search the user came from."""
    safe_query = _sanitize_return_q(return_q)
    if safe_query:
        return redirect(f"{reverse('rules')}?{safe_query}")
    return redirect('rules')


def _rule_form_from_post(request) -> dict:
    """Read the shared rule-form fields out of a POST."""
    return {
        'status': request.POST.get('status', '').strip(),
        'match_type': request.POST.get('match_type', '').strip(),
        'source_text': request.POST.get('source_text', '').strip(),
        'description': request.POST.get('description', '').strip(),
        'is_enabled': request.POST.get('is_enabled') == 'on',
        'whole_log': request.POST.get('whole_log') == 'on',
        # Kept as a string: the template selects an option with `form_priority == value`
        # against the str-keyed `_priority_choices()`, and an int would never compare
        # equal -- leaving the select unselected and letting the page's JS overwrite
        # the rule's hand-tuned priority with the match-type default.
        'priority': request.POST.get('priority', '').strip(),
    }


def _rule_form_from_rule(rule) -> dict:
    """Form state for an existing rule. See _rule_form_from_post on the priority str."""
    return {
        'status': rule.status,
        'match_type': rule.match_type,
        'source_text': rule.source_text,
        'description': rule.description,
        'is_enabled': rule.is_enabled,
        'whole_log': rule.whole_log,
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


def _apply_rule_edit(rule, form: dict, user) -> str | None:
    """Validate and save an edit to one rule. Returns an error message, or None.

    Shared by the quick-edit panel on the rules list and the full-page editor so the
    two cannot drift. `source_text` is a single value -- never split per line -- so a
    script rule keeps its newlines and one rule in stays one rule out.
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

    duplicate = ClassificationRule.objects.filter(
        owner=user, status=form['status'], match_type=form['match_type'],
        source_text=form['source_text'], whole_log=form['whole_log'],
    ).exclude(pk=rule.pk).exists()
    if duplicate:
        return 'A rule with this status, match type, and source text already exists.'

    rule.status = form['status']
    rule.match_type = form['match_type']
    rule.source_text = form['source_text']
    rule.description = form['description']
    rule.is_enabled = form['is_enabled']
    rule.priority = priority
    rule.whole_log = form['whole_log']
    _assign_parsed_metadata(rule, form)
    rule.save(update_fields=[
        'status', 'match_type', 'source_text', 'description',
        'is_enabled', 'priority', 'whole_log', *REPARSE_FIELDS, 'updated_at',
    ])
    invalidate_for_rule_owner(user)
    return None


def _rule_form_context(user, form: dict, *, editing: bool, return_q: str = '', rule=None) -> dict:
    """Context for add_rule.html, which serves both the add page and the editor."""
    cancel_url = reverse('rules')
    if return_q:
        cancel_url = f"{cancel_url}?{return_q}"

    return {
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
        'form_is_enabled': form['is_enabled'],
        'default_priority_by_match_type': DEFAULT_PRIORITY_BY_MATCH_TYPE,
        'default_priority_by_match_type_json': json.dumps(DEFAULT_PRIORITY_BY_MATCH_TYPE),
        'priority_min': PRIORITY_MIN,
        'priority_max': PRIORITY_MAX,
        'priority_choices': _priority_choices(),
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
            status = request.POST.get('status', '').strip()
            match_type = request.POST.get('match_type', '').strip()
            source_text = request.POST.get('source_text', '').strip()
            description = request.POST.get('description', '').strip()
            whole_log = request.POST.get('whole_log') == 'on'
            priority = _coerce_priority(request.POST.get('priority'), match_type)
            patterns = _patterns_for(match_type, source_text)
            script_error = _script_rule_error(match_type, source_text, request.user, whole_log)
            whole_log_error = _whole_log_error(whole_log, status, match_type)
            if not patterns:
                messages.error(request, 'Rule source text is required.')
            elif status not in dict(ClassificationRule.CREATABLE_STATUS_CHOICES):
                messages.error(request, 'Invalid status.')
            elif match_type not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
                messages.error(request, 'Invalid match type.')
            elif whole_log_error:
                messages.error(request, whole_log_error)
            elif script_error:
                messages.error(request, script_error)
            else:
                existing = set(
                    ClassificationRule.objects.filter(
                        owner=request.user,
                        status=status,
                        match_type=match_type,
                        whole_log=whole_log,
                        source_text__in=patterns,
                    ).values_list('source_text', flat=True)
                )
                to_create = [
                    ClassificationRule(
                        owner=request.user,
                        status=status,
                        match_type=match_type,
                        source_text=pattern,
                        description=description,
                        priority=priority,
                        whole_log=whole_log,
                    )
                    for pattern in patterns if pattern not in existing
                ]
                skipped = [pattern for pattern in patterns if pattern in existing]
                if to_create:
                    ClassificationRule.objects.bulk_create(to_create)
                    invalidate_for_rule_owner(request.user)
                    n = len(to_create)
                    messages.success(request, f'{n} rule{"" if n == 1 else "s"} created.')
                    if skipped:
                        m = len(skipped)
                        messages.warning(
                            request,
                            f'{m} duplicate{"" if m == 1 else "s"} skipped: {_format_skipped(skipped)}',
                        )
                else:
                    m = len(skipped)
                    messages.error(
                        request,
                        f'No rules created. {m} duplicate{"" if m == 1 else "s"} skipped: {_format_skipped(skipped)}',
                    )
            return redirect('rules')

        if action == 'edit':
            pk = request.POST.get('pk', '').strip()
            rule = get_object_or_404(ClassificationRule, pk=pk, owner=request.user)
            error = _apply_rule_edit(rule, _rule_form_from_post(request), request.user)
            if error:
                messages.error(request, error)
            else:
                messages.success(request, 'Rule updated.')
            return _rules_redirect(request.POST.get('return_q', ''))

        if action == 'delete':
            pk = request.POST.get('pk', '').strip()
            rule = get_object_or_404(ClassificationRule, pk=pk, owner=request.user)
            rule.delete()
            invalidate_for_rule_owner(request.user)
            messages.success(request, 'Rule deleted.')
            return _rules_redirect(request.POST.get('return_q', ''))

        if action == 'toggle':
            pk = request.POST.get('pk', '').strip()
            rule = get_object_or_404(ClassificationRule, pk=pk, owner=request.user)
            rule.is_enabled = not rule.is_enabled
            rule.save(update_fields=['is_enabled', 'updated_at'])
            invalidate_for_rule_owner(request.user)
            label = 'enabled' if rule.is_enabled else 'disabled'
            messages.success(request, f'Rule {label}.')
            return redirect('rules')

    filter_mode = request.GET.get('filter', 'own')
    filter_status = request.GET.get('status', '')
    filter_match = request.GET.get('match', '')
    search_q = request.GET.get('q', '').strip()
    search_mode = request.GET.get('search_mode', 'text')
    sort = request.GET.get('sort', 'recent')

    SORT_OPTIONS = {
        'recent': '-updated_at',
        'created': '-created_at',
        'status': ('status', 'match_type', 'source_text'),
        'priority': ('-priority', 'status', 'match_type', 'source_text'),
    }

    if filter_mode == 'all':
        rules = ClassificationRule.objects.all().select_related('owner')
    elif filter_mode == 'others':
        rules = ClassificationRule.objects.exclude(owner=request.user).select_related('owner')
    else:
        filter_mode = 'own'
        rules = ClassificationRule.objects.filter(owner=request.user)

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
        else:
            rules = rules.filter(
                Q(source_text__icontains=search_q) | Q(description__icontains=search_q)
            )
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

    if form_status not in dict(ClassificationRule.CREATABLE_STATUS_CHOICES):
        form_status = ClassificationRule.STATUS_MALWARE
    if form_match_type not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
        form_match_type = ClassificationRule.MATCH_EXACT

    if request.method == 'POST':
        status = request.POST.get('status', '').strip()
        match_type = request.POST.get('match_type', '').strip()
        source_text = request.POST.get('source_text', '').strip()
        description = request.POST.get('description', '').strip()
        whole_log = request.POST.get('whole_log') == 'on'
        raw_priority = request.POST.get('priority', '').strip()
        form_status = status
        form_match_type = match_type
        form_source_text = source_text
        form_description = description
        form_priority = raw_priority
        form_whole_log = whole_log
        patterns = _patterns_for(match_type, source_text)
        script_error = _script_rule_error(match_type, source_text, request.user, whole_log)
        whole_log_error = _whole_log_error(whole_log, status, match_type)
        if not patterns:
            messages.error(request, 'Rule source text is required.')
        elif status not in dict(ClassificationRule.CREATABLE_STATUS_CHOICES):
            messages.error(request, 'Invalid status.')
        elif match_type not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
            messages.error(request, 'Invalid match type.')
        elif whole_log_error:
            messages.error(request, whole_log_error)
        elif script_error:
            messages.error(request, script_error)
        else:
            priority = _coerce_priority(raw_priority, match_type)
            existing = set(
                ClassificationRule.objects.filter(
                    owner=request.user,
                    status=status,
                    match_type=match_type,
                    whole_log=whole_log,
                    source_text__in=patterns,
                ).values_list('source_text', flat=True)
            )

            to_create = []
            skipped = []
            for pattern in patterns:
                if pattern in existing:
                    skipped.append(pattern)
                    continue
                parsed = parse_rule_line(
                    pattern,
                    status=status,
                    source_name=f'web-add-rule:{request.user.username}',
                )
                if parsed and match_type in (ClassificationRule.MATCH_PARSED_ENTRY, ClassificationRule.MATCH_FILEPATH):
                    parsed['match_type'] = match_type
                create_kwargs = {
                    'owner': request.user,
                    'status': status,
                    'match_type': match_type,
                    'source_text': pattern,
                    'description': description,
                    'priority': priority,
                    'whole_log': whole_log,
                }
                if parsed:
                    for field in ('entry_type', 'clsid', 'name', 'filepath', 'normalized_filepath',
                                  'filename', 'company', 'arguments', 'file_not_signed', 'source_name'):
                        if parsed.get(field):
                            create_kwargs[field] = parsed[field]
                to_create.append(ClassificationRule(**create_kwargs))

            if to_create:
                ClassificationRule.objects.bulk_create(to_create)
                invalidate_for_rule_owner(request.user)
                n = len(to_create)
                messages.success(request, f'{n} rule{"" if n == 1 else "s"} created.')
                if skipped:
                    summary = _format_skipped(skipped)
                    m = len(skipped)
                    messages.warning(
                        request,
                        f'{m} duplicate{"" if m == 1 else "s"} skipped: {summary}',
                    )
                keep_params = {'status': status, 'match_type': match_type}
                if whole_log:
                    keep_params['whole_log'] = '1'
                keep_qs = urlencode(keep_params)
                return redirect(f"{reverse('add_rule')}?{keep_qs}")
            else:
                summary = _format_skipped(skipped)
                m = len(skipped)
                messages.error(
                    request,
                    f'No rules created. {m} duplicate{"" if m == 1 else "s"} skipped: {summary}',
                )

    form = {
        'status': form_status,
        'match_type': form_match_type,
        'source_text': form_source_text,
        'description': form_description,
        'priority': form_priority,
        'whole_log': form_whole_log,
        # New rules are always created enabled; the add form has no such field.
        'is_enabled': True,
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
    rule = get_object_or_404(ClassificationRule, pk=pk, owner=request.user)

    if request.method == 'POST':
        return_q = request.POST.get('return_q', '')
        form = _rule_form_from_post(request)
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
                return _rules_redirect(return_q)
    else:
        return_q = request.GET.get('return_q', '')
        form = _rule_form_from_rule(rule)

    _warn_about_unassignable_values(request, rule)
    return render(request, 'add_rule.html', _rule_form_context(
        request.user, form,
        editing=True, return_q=_sanitize_return_q(return_q), rule=rule,
    ))


@login_required
@require_http_methods(["POST"])
def test_rule_api(request):
    """Test a rule definition against a list of log lines and return per-line match results."""
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    source_text = (payload.get('source_text') or '').strip()
    status = (payload.get('status') or '?').strip()
    match_type = (payload.get('match_type') or '').strip()
    lines = payload.get('lines', [])
    raw_priority = payload.get('priority')
    whole_log = bool(payload.get('whole_log'))
    # The rule editor passes the rule it is editing so the preview reports the lines
    # as they would look without it -- otherwise the saved copy shows up as an
    # existing match and can appear to shadow the user's own pending edit. Honoured
    # only for a rule the caller owns.
    exclude_rule_id = _owned_rule_id(payload.get('exclude_rule_id'), request.user)

    if not isinstance(lines, list) or len(lines) > 500:
        return JsonResponse({'error': 'Field "lines" must be a list with at most 500 entries.'}, status=400)
    if not source_text:
        return JsonResponse({'error': 'Field "source_text" is required.'}, status=400)
    if status not in VALID_STATUSES:
        status = '?'

    # Previewing a script rule executes the submitted snippet, so it is gated to
    # moderators exactly like authoring one.
    if match_type == ClassificationRule.MATCH_SCRIPT and not is_moderator(request.user):
        return JsonResponse({'error': 'Script rules can only be tested by moderators.'}, status=403)

    if raw_priority is None or raw_priority == '':
        priority = None
    else:
        try:
            priority = max(PRIORITY_MIN, min(PRIORITY_MAX, int(raw_priority)))
        except (TypeError, ValueError):
            priority = None

    patterns = _patterns_for(match_type, source_text)
    if not patterns:
        return JsonResponse({'error': 'Field "source_text" is required.'}, status=400)
    if len(patterns) > 100:
        return JsonResponse({'error': 'At most 100 patterns are allowed.'}, status=400)

    # Whole-log rules run once against the entire log (regex / script only), so the
    # preview reconstructs the pasted text and returns a single log-level verdict.
    if whole_log:
        if match_type not in (ClassificationRule.MATCH_REGEX, ClassificationRule.MATCH_SCRIPT):
            return JsonResponse(
                {'error': 'Whole-log rules support only regex and script match types.'},
                status=400,
            )
        log_text = '\n'.join(str(line) for line in lines)
        try:
            result_payload = build_wholelog_rule_test_result(patterns, match_type, log_text)
        except ValueError as exc:
            return JsonResponse({'error': str(exc)}, status=400)
        if match_type == ClassificationRule.MATCH_REGEX:
            regex_warnings = []
            for pattern in patterns:
                evaluation = evaluate_regex_pattern(pattern)
                warning_kinds = []
                if not evaluation['re2_ok']:
                    warning_kinds.append('fallback')
                if evaluation['is_slow']:
                    warning_kinds.append('slow')
                if not warning_kinds:
                    continue
                regex_warnings.append({
                    'pattern': pattern,
                    'kinds': warning_kinds,
                    're2_error': evaluation['re2_error'],
                    'worst_ms': round(evaluation['worst_ms'], 2),
                    'worst_input': evaluation['worst_input'],
                })
            if regex_warnings:
                result_payload['regex_warnings'] = regex_warnings
        return JsonResponse(result_payload)

    try:
        response_payload = build_rule_test_results(
            patterns=patterns,
            status=status,
            match_type=match_type,
            lines=lines,
            priority=priority,
            exclude_rule_id=exclude_rule_id,
        )
    except ValueError as exc:
        return JsonResponse({'error': str(exc)}, status=400)

    if match_type == ClassificationRule.MATCH_REGEX:
        # Invalid patterns are already rejected with HTTP 400 by
        # build_rule_test_results, so by the time we get here every pattern
        # compiles in stdlib re. Warnings only cover the "valid but suspect"
        # cases: rejected by re2 (fallback), or slow on adversarial input.
        regex_warnings = []
        for pattern in patterns:
            evaluation = evaluate_regex_pattern(pattern)
            warning_kinds = []
            if not evaluation['re2_ok']:
                warning_kinds.append('fallback')
            if evaluation['is_slow']:
                warning_kinds.append('slow')
            if not warning_kinds:
                continue
            regex_warnings.append({
                'pattern': pattern,
                'kinds': warning_kinds,
                're2_error': evaluation['re2_error'],
                'worst_ms': round(evaluation['worst_ms'], 2),
                'worst_input': evaluation['worst_input'],
            })
        if regex_warnings:
            response_payload['regex_warnings'] = regex_warnings

    return JsonResponse(response_payload)
