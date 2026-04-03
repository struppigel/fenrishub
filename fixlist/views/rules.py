"""
Classification rule management views.

Handles: creating, editing, deleting, testing, and viewing classification rules.
"""

import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.db.models import Q, Case, When

from ..analyzer import (
    parse_rule_line, inspect_line_matches, VALID_STATUSES,
)
from ..models import ClassificationRule
from ..rule_test_service import build_rule_test_results


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
            if not source_text:
                messages.error(request, 'Rule source text is required.')
            elif status not in dict(ClassificationRule.STATUS_CHOICES):
                messages.error(request, 'Invalid status.')
            elif match_type not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
                messages.error(request, 'Invalid match type.')
            elif ClassificationRule.objects.filter(
                owner=request.user, status=status, match_type=match_type, source_text=source_text
            ).exists():
                messages.error(request, 'A rule with this status, match type, and source text already exists.')
            else:
                ClassificationRule.objects.create(
                    owner=request.user,
                    status=status,
                    match_type=match_type,
                    source_text=source_text,
                    description=description,
                )
                messages.success(request, 'Rule created.')
            return redirect('rules')

        if action == 'edit':
            pk = request.POST.get('pk', '').strip()
            rule = get_object_or_404(ClassificationRule, pk=pk, owner=request.user)
            status = request.POST.get('status', '').strip()
            match_type = request.POST.get('match_type', '').strip()
            source_text = request.POST.get('source_text', '').strip()
            description = request.POST.get('description', '').strip()
            is_enabled = request.POST.get('is_enabled') == 'on'
            if not source_text:
                messages.error(request, 'Rule source text is required.')
            elif status not in dict(ClassificationRule.STATUS_CHOICES):
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
                    rule.save(update_fields=[
                        'status', 'match_type', 'source_text', 'description', 'is_enabled', 'updated_at',
                    ])
                    messages.success(request, 'Rule updated.')
            return redirect('rules')

        if action == 'delete':
            pk = request.POST.get('pk', '').strip()
            rule = get_object_or_404(ClassificationRule, pk=pk, owner=request.user)
            rule.delete()
            messages.success(request, 'Rule deleted.')
            return redirect('rules')

        if action == 'toggle':
            pk = request.POST.get('pk', '').strip()
            rule = get_object_or_404(ClassificationRule, pk=pk, owner=request.user)
            rule.is_enabled = not rule.is_enabled
            rule.save(update_fields=['is_enabled', 'updated_at'])
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
        'status_choices': ClassificationRule.STATUS_CHOICES,
        'match_type_choices': ClassificationRule.MATCH_TYPE_CHOICES,
        'status_map': STATUS_MAP,
        'match_type_map': MATCH_TYPE_MAP,
    }
    return render(request, 'rules.html', context)


@login_required
@require_http_methods(["GET", "POST"])
def add_rule_view(request):
    """Dedicated page for adding a new classification rule with log preview."""
    if request.method == 'POST':
        status = request.POST.get('status', '').strip()
        match_type = request.POST.get('match_type', '').strip()
        source_text = request.POST.get('source_text', '').strip()
        description = request.POST.get('description', '').strip()
        if not source_text:
            messages.error(request, 'Rule source text is required.')
        elif status not in dict(ClassificationRule.STATUS_CHOICES):
            messages.error(request, 'Invalid status.')
        elif match_type not in dict(ClassificationRule.MATCH_TYPE_CHOICES):
            messages.error(request, 'Invalid match type.')
        else:
            parsed = parse_rule_line(source_text, status=status, source_name=f'web-add-rule:{request.user.username}')
            if parsed and match_type in (ClassificationRule.MATCH_PARSED_ENTRY, ClassificationRule.MATCH_FILEPATH):
                parsed['match_type'] = match_type
            create_kwargs = {
                'owner': request.user,
                'status': status,
                'match_type': match_type,
                'source_text': source_text,
                'description': description,
            }
            if parsed:
                for field in ('entry_type', 'clsid', 'name', 'filepath', 'normalized_filepath',
                              'filename', 'company', 'arguments', 'file_not_signed', 'source_name'):
                    if parsed.get(field):
                        create_kwargs[field] = parsed[field]

            duplicate = ClassificationRule.objects.filter(
                owner=request.user, status=status, match_type=match_type, source_text=source_text,
            ).exists()
            if duplicate:
                messages.error(request, 'A rule with this status, match type, and source text already exists.')
            else:
                ClassificationRule.objects.create(**create_kwargs)
                messages.success(request, 'Rule created.')
                return redirect('rules')

    context = {
        'status_choices': ClassificationRule.STATUS_CHOICES,
        'match_type_choices': ClassificationRule.MATCH_TYPE_CHOICES,
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

    if not isinstance(lines, list) or len(lines) > 500:
        return JsonResponse({'error': 'Field "lines" must be a list with at most 500 entries.'}, status=400)
    if not source_text:
        return JsonResponse({'error': 'Field "source_text" is required.'}, status=400)
    if status not in VALID_STATUSES:
        status = '?'

    try:
        response_payload = build_rule_test_results(
            source_text=source_text,
            status=status,
            match_type=match_type,
            lines=lines,
        )
    except ValueError as exc:
        return JsonResponse({'error': str(exc)}, status=400)

    return JsonResponse(response_payload)
