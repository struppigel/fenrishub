"""
Fact views.

Handles: the facts list (delete a fact, toggle or delete its fact rules), the
fact editor (name, description, tag sources), and creating and editing fact
rules through the rule editor page (add_rule.html in fact mode).

Facts are shared and any logged-in helper may edit them. Fact rules are owned
like classification rules: only their owner or a superuser edits them, and
they follow the owner's rule set.
"""

import json
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Count, ProtectedError, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from ..analyzer import REPARSE_FIELDS, invalidate_rule_buckets_cache, parse_rule_line
from ..fact_service import fact_delete_error
from ..log_types import default_rule_scope
from ..models import ClassificationRule, Fact, FactRule, FactTagSource, RuleTag
from ..rule_sets import invalidate_for_rule_owner
from .guest import deny_guests
from .utils import redirect_with_return_q, sanitize_return_q

FACTS_PER_PAGE = 12

NEW_FACT = 'new'


# ---------------------------------------------------------------------------
# Fact rules (created and edited through the rule editor page)
# ---------------------------------------------------------------------------

def _fact_whole_log_error(whole_log: bool, match_type: str) -> str | None:
    if whole_log and match_type not in (FactRule.MATCH_REGEX, FactRule.MATCH_SCRIPT):
        return 'Whole-log fact rules support only regex and script match types.'
    return None


def _fact_name_error(name: str, exclude_pk=None) -> str | None:
    if not name:
        return 'Give the fact a name.'
    if len(name) > Fact.NAME_MAX_LENGTH:
        return f'Fact names are at most {Fact.NAME_MAX_LENGTH} characters.'
    clash = Fact.objects.filter(name__iexact=name)
    if exclude_pk is not None:
        clash = clash.exclude(pk=exclude_pk)
    if clash.exists():
        return f'A fact named "{name}" already exists.'
    return None


def _resolve_fact(user, fact_id: str, new_fact_name: str):
    """(fact, error) for the fact picker's value: an existing fact's id, or
    "new" with a name (an existing fact of that name, any case, is reused)."""
    if fact_id == NEW_FACT:
        name = (new_fact_name or '').strip()
        if not name:
            return None, 'Give the new fact a name.'
        if len(name) > Fact.NAME_MAX_LENGTH:
            return None, f'Fact names are at most {Fact.NAME_MAX_LENGTH} characters.'
        existing = Fact.objects.filter(name__iexact=name).first()
        if existing is not None:
            return existing, None
        try:
            with transaction.atomic():
                return Fact.objects.create(name=name, created_by=user, updated_by=user), None
        except IntegrityError:
            # Another helper created it a moment ago: use theirs.
            existing = Fact.objects.filter(name__iexact=name).first()
            if existing is not None:
                return existing, None
            raise
    if fact_id and fact_id.isdigit():
        fact = Fact.objects.filter(pk=int(fact_id)).first()
        if fact is not None:
            return fact, None
    return None, 'Choose the fact this fact rule records.'


def _parsed_fields(pattern: str, source_name: str = '') -> dict:
    """The parsed metadata of a pattern, as create_rules stores it: parsed and
    file path rules match with it; other types keep it for reference only
    (fact rules get no file path fallback, see analyzer._index_rules)."""
    parsed = parse_rule_line(pattern, status=ClassificationRule.STATUS_INFO, source_name=source_name)
    if not parsed:
        return {}
    return {field: parsed[field] for field in (*REPARSE_FIELDS, 'source_name') if parsed.get(field)}


def create_fact_rules(user, *, fact_id, new_fact_name='', match_type, source_text, description='',
                      whole_log=False, source_name='', log_scope=None, only_entry_types=None):
    """Validate and create fact rules for `user`, one per line of `source_text`
    (a script rule stays one). Returns ``(fact, created, skipped, error)``,
    like create_rules; the fact is resolved (or created) only once the rules
    are valid. `only_entry_types` limits them to lines parsed as those types."""
    from .rules import _patterns_for, _script_rule_error, clean_entry_types

    only_entry_types, error = clean_entry_types(only_entry_types)
    if error:
        return None, [], [], error
    patterns = _patterns_for(match_type, source_text)
    if not patterns:
        return None, [], [], 'Rule source text is required.'
    if match_type not in dict(FactRule.MATCH_TYPE_CHOICES):
        return None, [], [], 'Invalid match type.'
    error = _fact_whole_log_error(whole_log, match_type) or _script_rule_error(
        match_type, source_text, user, whole_log,
    )
    if error:
        return None, [], [], error

    all_log_types, log_types = log_scope or default_rule_scope(match_type)
    with transaction.atomic():
        fact, error = _resolve_fact(user, fact_id, new_fact_name)
        if error:
            return None, [], [], error
        existing = set(FactRule.objects.filter(
            owner=user, fact=fact, match_type=match_type, whole_log=whole_log, source_text__in=patterns,
        ).values_list('source_text', flat=True))
        to_create = []
        skipped = []
        for pattern in patterns:
            if pattern in existing:
                skipped.append(pattern)
                continue
            to_create.append(FactRule(
                owner=user, fact=fact, match_type=match_type, source_text=pattern, description=description,
                whole_log=whole_log, all_log_types=all_log_types, log_types=list(log_types),
                only_entry_types=[] if whole_log else list(only_entry_types),
                **_parsed_fields(pattern, source_name),
            ))
        created = FactRule.objects.bulk_create(to_create) if to_create else []
    if created:
        invalidate_for_rule_owner(user)
    return fact, created, skipped, None


def apply_fact_rule_edit(rule, form: dict, user) -> str | None:
    """Validate and save an edit to one fact rule. Returns an error message,
    or None. Mirrors rules._apply_rule_edit."""
    from .rules import _script_rule_error

    if not form['source_text']:
        return 'Rule source text is required.'
    if form['match_type'] not in dict(FactRule.MATCH_TYPE_CHOICES):
        return 'Invalid match type.'
    if form['match_type'] != FactRule.MATCH_SCRIPT and (
        '\n' in form['source_text'] or '\r' in form['source_text']
    ):
        return 'A rule matches a single line. Remove the line breaks.'
    error = (
        _fact_whole_log_error(form['whole_log'], form['match_type'])
        or _script_rule_error(form['match_type'], form['source_text'], user, form['whole_log'])
        or form.get('log_scope_error')
        or form.get('only_entry_types_error')
    )
    if error:
        return error
    # One transaction: a "new fact" made for an edit that is then refused is
    # rolled back rather than left behind without rules.
    with transaction.atomic():
        fact, error = _resolve_fact(user, form.get('fact_id', ''), form.get('new_fact_name', ''))
        if error:
            return error
        duplicate = FactRule.objects.filter(
            owner_id=rule.owner_id, fact=fact, match_type=form['match_type'],
            source_text=form['source_text'], whole_log=form['whole_log'],
        ).exclude(pk=rule.pk).exists()
        if duplicate:
            transaction.set_rollback(True)
            return 'A fact rule with this fact, match type, and source text already exists.'

        rule.fact = fact
        rule.match_type = form['match_type']
        rule.source_text = form['source_text']
        rule.description = form['description']
        rule.is_enabled = form['is_enabled']
        rule.whole_log = form['whole_log']
        parsed = _parsed_fields(form['source_text'])
        for field in REPARSE_FIELDS:
            setattr(rule, field, parsed.get(field, False if field in ('file_not_signed', 'is_hidden') else ''))
        if form.get('log_scope') is not None:
            rule.all_log_types, rule.log_types = form['log_scope'][0], list(form['log_scope'][1])
        if form.get('only_entry_types') is not None:
            rule.only_entry_types = list(form['only_entry_types'])
        if rule.whole_log:
            rule.only_entry_types = []
        rule.save()
    invalidate_for_rule_owner(rule.owner)
    return None


def _fact_rule_for_editor_or_404(request, pk):
    """The fact rule `request.user` may edit: their own, or any for a superuser."""
    rules = FactRule.objects.select_related('owner', 'fact')
    if not request.user.is_superuser:
        rules = rules.filter(owner=request.user)
    return get_object_or_404(rules, pk=pk)


FACT_STATUS_VALUE = 'fact'


def fact_form_fields(request) -> dict:
    """The fact picker's fields of a rule editor POST. "fact" in the status
    dropdown (a choice there, though no status) means: record a fact."""
    return {
        'record_fact': (
            request.POST.get('record_fact') == 'on' or request.POST.get('status') == FACT_STATUS_VALUE
        ),
        'fact_id': request.POST.get('fact_id', '').strip(),
        'new_fact_name': request.POST.get('new_fact_name', '').strip(),
    }


def fact_rule_add_redirect(fact, match_type, whole_log, log_scope):
    """Back to the add page in fact mode, keeping the fact and the settings
    (the log type scope only when it is not the match type's default)."""
    from .rules import _kept_log_scope_params

    params = {'record_fact': '1', 'fact': fact.pk, 'match_type': match_type}
    if whole_log:
        params['whole_log'] = '1'
    params.update(_kept_log_scope_params(log_scope, match_type))
    return redirect(f"{reverse('add_rule')}?{urlencode(params, doseq=True)}")


@deny_guests
@login_required
@require_http_methods(["GET", "POST"])
def edit_fact_rule_view(request, pk: int):
    """The rule editor page for one fact rule (fact mode, locked)."""
    from .rules import _log_scope_from_post, _rule_form_context, entry_types_from_post

    rule = _fact_rule_for_editor_or_404(request, pk)
    if request.method == 'POST':
        log_scope, log_scope_error = _log_scope_from_post(request)
        only_entry_types, entry_types_problem = entry_types_from_post(request)
        form = {
            'only_entry_types': only_entry_types,
            'only_entry_types_error': entry_types_problem,
            'log_scope': log_scope if log_scope is not None or log_scope_error
            else (rule.all_log_types, list(rule.log_types or [])),
            'log_scope_error': log_scope_error,
            'tag_ids': [],
            'status': ClassificationRule.STATUS_INFO,
            'match_type': request.POST.get('match_type', '').strip(),
            'source_text': request.POST.get('source_text', '').strip(),
            'description': request.POST.get('description', '').strip(),
            'is_enabled': request.POST.get('is_enabled') == 'on',
            'whole_log': request.POST.get('whole_log') == 'on',
            'color_whole_line': False,
            'priority': '',
            **fact_form_fields(request),
            'record_fact': True,
        }
        error = apply_fact_rule_edit(rule, form, request.user)
        if error:
            messages.error(request, error)
        else:
            messages.success(request, 'Fact rule updated.')
            return redirect('fact_edit', pk=rule.fact_id)
    else:
        form = {
            'only_entry_types': list(rule.only_entry_types or []),
            'log_scope': (rule.all_log_types, list(rule.log_types or [])),
            'log_scope_error': None,
            'tag_ids': [],
            'status': ClassificationRule.STATUS_INFO,
            'match_type': rule.match_type,
            'source_text': rule.source_text,
            'description': rule.description,
            'is_enabled': rule.is_enabled,
            'whole_log': rule.whole_log,
            'color_whole_line': False,
            'priority': '',
            'record_fact': True,
            'fact_id': str(rule.fact_id),
            'new_fact_name': '',
        }
    context = _rule_form_context(request.user, form, editing=True, rule=rule)
    context['cancel_url'] = reverse('fact_edit', args=[rule.fact_id])
    return render(request, 'add_rule.html', context)


# ---------------------------------------------------------------------------
# Facts list and editor
# ---------------------------------------------------------------------------

def _delete_fact(fact):
    """Delete a fact with its fact rules and tag sources."""
    owners = list({rule.owner for rule in FactRule.objects.filter(fact=fact).select_related('owner')})
    with transaction.atomic():
        fact.delete()
    for owner in owners:
        invalidate_for_rule_owner(owner)
    invalidate_rule_buckets_cache(None)


@deny_guests
@login_required
@require_http_methods(["GET", "POST"])
def facts_view(request):
    """List facts with their rule and source counts; delete facts; toggle or
    delete fact rules (from the fact editor's list of them)."""
    if request.method == 'POST':
        action = request.POST.get('action')
        return_to = request.POST.get('return_to', '')
        if action == 'delete':
            fact = get_object_or_404(Fact, pk=request.POST.get('pk', '').strip() or 0)
            error = fact_delete_error(fact, request.user)
            if not error:
                name = fact.name
                try:
                    _delete_fact(fact)
                except ProtectedError:
                    # A condition on the fact was added after the check above.
                    error = 'Rules have conditions on this fact; remove those conditions first.'
            if error:
                messages.error(request, error)
            else:
                messages.success(request, f'Fact "{name}" deleted.')
                return redirect_with_return_q('facts', request.POST.get('return_q'))
        elif action in ('fact_rule_toggle', 'fact_rule_delete'):
            rule = _fact_rule_for_editor_or_404(request, request.POST.get('pk', '').strip() or 0)
            if action == 'fact_rule_toggle':
                rule.is_enabled = not rule.is_enabled
                rule.save(update_fields=['is_enabled', 'updated_at'])
                messages.success(request, f'Fact rule {"enabled" if rule.is_enabled else "disabled"}.')
            else:
                rule.delete()
                messages.success(request, 'Fact rule deleted.')
            invalidate_for_rule_owner(rule.owner)
            if return_to == 'fact':
                return redirect('fact_edit', pk=rule.fact_id)
            if return_to == 'rules':
                # From the rules page, which lists fact rules with the rules.
                return redirect_with_return_q('rules', request.POST.get('return_q'))
        return redirect_with_return_q('facts', request.POST.get('return_q'))

    search_query = request.GET.get('q', '').strip()
    facts = Fact.objects.select_related('updated_by').annotate(
        fact_rule_count=Count('fact_rules', distinct=True),
        tag_source_count=Count('tag_sources', distinct=True),
    )
    if search_query:
        facts = facts.filter(Q(name__icontains=search_query) | Q(description__icontains=search_query))
    paginator = Paginator(facts.order_by('name'), FACTS_PER_PAGE)
    page_obj = paginator.get_page(request.GET.get('page'))
    params = {'q': search_query} if search_query else {}
    return render(request, 'facts.html', {
        'facts': page_obj.object_list,
        'page_obj': page_obj,
        'search_query': search_query,
        'has_any_facts': Fact.objects.exists(),
        'current_query_string': request.GET.urlencode(),
        'pagination_query': urlencode(params),
    })


def _sources_from_post(raw: str):
    """(sources, error) from the editor's JSON list of tag sources:
    [{tag_id, statuses, mode, include_filepath_fallback}]."""
    try:
        items = json.loads(raw or '[]')
    except ValueError:
        return None, 'The tag sources could not be read.'
    if not isinstance(items, list):
        return None, 'The tag sources could not be read.'
    statuses_allowed = dict(ClassificationRule.CREATABLE_STATUS_CHOICES)
    modes = dict(FactTagSource.MODE_CHOICES)
    sources = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            return None, 'The tag sources could not be read.'
        tag_id = item.get('tag_id')
        if isinstance(tag_id, str) and tag_id.isdigit():
            tag_id = int(tag_id)
        if not isinstance(tag_id, int) or isinstance(tag_id, bool):
            return None, 'Choose a tag for every tag source.'
        if tag_id in seen:
            return None, 'Each tag can be a source of a fact only once.'
        seen.add(tag_id)
        statuses = item.get('statuses') or []
        if not isinstance(statuses, list) or any(code not in statuses_allowed for code in statuses):
            return None, 'Unknown status in a tag source.'
        mode = item.get('mode') or FactTagSource.MODE_MATCHED
        if mode not in modes:
            return None, 'Unknown mode in a tag source.'
        sources.append({
            'tag_id': tag_id,
            'statuses': sorted(set(statuses)),
            'mode': mode,
            'include_filepath_fallback': bool(item.get('include_filepath_fallback')),
        })
    known = set(RuleTag.objects.filter(pk__in=seen).values_list('pk', flat=True))
    if known != seen:
        return None, 'A tag source names a tag that no longer exists.'
    return sources, None


def _save_fact(fact, user, name, description, sources):
    """Create or update a fact and replace its tag sources: `(fact, error)`.
    The error is set when another fact took the name meanwhile."""
    created = fact is None
    try:
        with transaction.atomic():
            if fact is None:
                fact = Fact(created_by=user)
            fact.name = name
            fact.description = description
            fact.updated_by = user
            fact.save()
            keep = {source['tag_id'] for source in sources}
            FactTagSource.objects.filter(fact=fact).exclude(tag_id__in=keep).delete()
            for source in sources:
                FactTagSource.objects.update_or_create(
                    fact=fact, tag_id=source['tag_id'],
                    defaults={key: source[key] for key in ('statuses', 'mode', 'include_filepath_fallback')},
                )
    except IntegrityError:
        if created:
            fact = None
        else:
            fact.refresh_from_db()  # drop the refused name
        return fact, f'A fact named "{name}" already exists.'
    invalidate_rule_buckets_cache(None)
    return fact, None


def _fact_editor(request, fact=None):
    error = None
    name = fact.name if fact else ''
    description = fact.description if fact else ''
    sources = [
        {
            'tag_id': source.tag_id,
            'statuses': list(source.statuses or []),
            'mode': source.mode,
            'include_filepath_fallback': source.include_filepath_fallback,
        }
        for source in (fact.tag_sources.all() if fact else [])
    ]
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        description = request.POST.get('description', '').strip()
        posted_sources, error = _sources_from_post(request.POST.get('tag_sources', ''))
        if posted_sources is not None:
            sources = posted_sources
        error = error or _fact_name_error(name, exclude_pk=fact.pk if fact else None)
        if not error:
            created = fact is None
            saved, error = _save_fact(fact, request.user, name, description, sources)
            if not error:
                messages.success(request, f'Fact "{saved.name}" {"created" if created else "saved"}.')
                return redirect('fact_edit', pk=saved.pk)
            fact = saved

    fact_rules = []
    if fact is not None and fact.pk:
        fact_rules = list(FactRule.objects.filter(fact=fact).select_related('owner').order_by('match_type', 'source_text'))
    tags = list(RuleTag.objects.order_by('name').values('pk', 'name'))
    return render(request, 'fact_editor.html', {
        'fact': fact if fact is not None and fact.pk else None,
        'form_name': name,
        'form_description': description,
        'error': error,
        'fact_rules': fact_rules,
        'name_max_length': Fact.NAME_MAX_LENGTH,
        'editor_data': {
            'sources': sources,
            'tags': [{'id': tag['pk'], 'name': tag['name']} for tag in tags],
            'statuses': [
                {'code': code, 'label': label} for code, label in ClassificationRule.CREATABLE_STATUS_CHOICES
            ],
            'modes': [{'value': value, 'label': label} for value, label in FactTagSource.MODE_CHOICES],
        },
        'return_q': sanitize_return_q(request.GET.get('return_q', '')),
    })


@deny_guests
@login_required
@require_http_methods(["GET", "POST"])
def fact_add_view(request):
    return _fact_editor(request)


@deny_guests
@login_required
@require_http_methods(["GET", "POST"])
def fact_edit_view(request, pk: int):
    return _fact_editor(request, get_object_or_404(Fact, pk=pk))
