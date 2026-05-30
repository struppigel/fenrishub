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

from ..analyzer import (
    parse_rule_line, inspect_line_matches, VALID_STATUSES,
    evaluate_regex_pattern,
)
from ..models import (
    ClassificationRule,
    DEFAULT_PRIORITY_BY_MATCH_TYPE,
    PRIORITY_DEFAULT_LABELS,
    PRIORITY_MAX,
    PRIORITY_MIN,
)
from ..rule_sets import invalidate_for_rule_owner
from ..rule_test_service import build_rule_test_results


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
            priority = _coerce_priority(request.POST.get('priority'), match_type)
            patterns = _split_patterns(source_text)
            if not patterns:
                messages.error(request, 'Rule source text is required.')
            elif status not in dict(ClassificationRule.CREATABLE_STATUS_CHOICES):
                messages.error(request, 'Invalid status.')
            elif match_type not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
                messages.error(request, 'Invalid match type.')
            else:
                existing = set(
                    ClassificationRule.objects.filter(
                        owner=request.user,
                        status=status,
                        match_type=match_type,
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
            status = request.POST.get('status', '').strip()
            match_type = request.POST.get('match_type', '').strip()
            source_text = request.POST.get('source_text', '').strip()
            description = request.POST.get('description', '').strip()
            is_enabled = request.POST.get('is_enabled') == 'on'
            priority = _coerce_priority(request.POST.get('priority'), match_type)
            if not source_text:
                messages.error(request, 'Rule source text is required.')
            elif status not in dict(ClassificationRule.CREATABLE_STATUS_CHOICES):
                messages.error(request, 'Invalid status.')
            elif match_type not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
                messages.error(request, 'Invalid match type.')
            else:
                duplicate = ClassificationRule.objects.filter(
                    owner=request.user, status=status, match_type=match_type, source_text=source_text
                ).exclude(pk=rule.pk).exists()
                if duplicate:
                    messages.error(request, 'A rule with this status, match type, and source text already exists.')
                else:
                    rule.status = status
                    rule.match_type = match_type
                    rule.source_text = source_text
                    rule.description = description
                    rule.is_enabled = is_enabled
                    rule.priority = priority
                    rule.save(update_fields=[
                        'status', 'match_type', 'source_text', 'description',
                        'is_enabled', 'priority', 'updated_at',
                    ])
                    invalidate_for_rule_owner(request.user)
                    messages.success(request, 'Rule updated.')
            return_q = request.POST.get('return_q', '').strip()
            if return_q:
                safe_query = urlencode(parse_qsl(return_q, keep_blank_values=True), doseq=True)
                if safe_query:
                    return redirect(f"{reverse('rules')}?{safe_query}")
            return redirect('rules')

        if action == 'delete':
            pk = request.POST.get('pk', '').strip()
            rule = get_object_or_404(ClassificationRule, pk=pk, owner=request.user)
            rule.delete()
            invalidate_for_rule_owner(request.user)
            messages.success(request, 'Rule deleted.')
            return_q = request.POST.get('return_q', '').strip()
            if return_q:
                safe_query = urlencode(parse_qsl(return_q, keep_blank_values=True), doseq=True)
                if safe_query:
                    return redirect(f"{reverse('rules')}?{safe_query}")
            return redirect('rules')

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

    if form_status not in dict(ClassificationRule.CREATABLE_STATUS_CHOICES):
        form_status = ClassificationRule.STATUS_MALWARE
    if form_match_type not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
        form_match_type = ClassificationRule.MATCH_EXACT

    if request.method == 'POST':
        status = request.POST.get('status', '').strip()
        match_type = request.POST.get('match_type', '').strip()
        source_text = request.POST.get('source_text', '').strip()
        description = request.POST.get('description', '').strip()
        raw_priority = request.POST.get('priority', '').strip()
        form_status = status
        form_match_type = match_type
        form_source_text = source_text
        form_description = description
        form_priority = raw_priority
        patterns = _split_patterns(source_text)
        if not patterns:
            messages.error(request, 'Rule source text is required.')
        elif status not in dict(ClassificationRule.CREATABLE_STATUS_CHOICES):
            messages.error(request, 'Invalid status.')
        elif match_type not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
            messages.error(request, 'Invalid match type.')
        else:
            priority = _coerce_priority(raw_priority, match_type)
            existing = set(
                ClassificationRule.objects.filter(
                    owner=request.user,
                    status=status,
                    match_type=match_type,
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
                keep_qs = urlencode({'status': status, 'match_type': match_type})
                return redirect(f"{reverse('add_rule')}?{keep_qs}")
            else:
                summary = _format_skipped(skipped)
                m = len(skipped)
                messages.error(
                    request,
                    f'No rules created. {m} duplicate{"" if m == 1 else "s"} skipped: {summary}',
                )

    context = {
        'status_choices': ClassificationRule.STATUS_CHOICES,
        'creatable_status_choices': ClassificationRule.CREATABLE_STATUS_CHOICES,
        'match_type_choices': ClassificationRule.MATCH_TYPE_CHOICES,
        'form_status': form_status,
        'form_match_type': form_match_type,
        'form_source_text': form_source_text,
        'form_description': form_description,
        'form_priority': form_priority,
        'default_priority_by_match_type': DEFAULT_PRIORITY_BY_MATCH_TYPE,
        'default_priority_by_match_type_json': json.dumps(DEFAULT_PRIORITY_BY_MATCH_TYPE),
        'priority_min': PRIORITY_MIN,
        'priority_max': PRIORITY_MAX,
        'priority_choices': _priority_choices(),
    }
    return render(request, 'add_rule.html', context)


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

    if not isinstance(lines, list) or len(lines) > 500:
        return JsonResponse({'error': 'Field "lines" must be a list with at most 500 entries.'}, status=400)
    if not source_text:
        return JsonResponse({'error': 'Field "source_text" is required.'}, status=400)
    if status not in VALID_STATUSES:
        status = '?'

    if raw_priority is None or raw_priority == '':
        priority = None
    else:
        try:
            priority = max(PRIORITY_MIN, min(PRIORITY_MAX, int(raw_priority)))
        except (TypeError, ValueError):
            priority = None

    patterns = _split_patterns(source_text)
    if not patterns:
        return JsonResponse({'error': 'Field "source_text" is required.'}, status=400)
    if len(patterns) > 100:
        return JsonResponse({'error': 'At most 100 patterns are allowed.'}, status=400)

    try:
        first_payload = build_rule_test_results(
            source_text=patterns[0],
            status=status,
            match_type=match_type,
            lines=lines,
            priority=priority,
        )
        aggregated_results = list(first_payload['results'])
        for pattern in patterns[1:]:
            extra = build_rule_test_results(
                source_text=pattern,
                status=status,
                match_type=match_type,
                lines=lines,
                priority=priority,
            )
            for idx, item in enumerate(extra['results']):
                if item.get('matched') and not aggregated_results[idx].get('matched'):
                    aggregated_results[idx] = item
    except ValueError as exc:
        return JsonResponse({'error': str(exc)}, status=400)

    response_payload = dict(first_payload)
    response_payload['results'] = aggregated_results

    if match_type == ClassificationRule.MATCH_REGEX:
        regex_warnings = []
        for pattern in patterns:
            evaluation = evaluate_regex_pattern(pattern)
            warning_kinds = []
            if not evaluation['stdlib_ok']:
                warning_kinds.append('invalid')
            else:
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
                'stdlib_error': evaluation['stdlib_error'],
                'worst_ms': round(evaluation['worst_ms'], 2),
                'worst_input': evaluation['worst_input'],
            })
        if regex_warnings:
            response_payload['regex_warnings'] = regex_warnings

    return JsonResponse(response_payload)
