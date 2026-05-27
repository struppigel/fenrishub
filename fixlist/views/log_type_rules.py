"""Moderator-managed regex rules that decide an UploadedLog's log_type."""

import json
import re

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods

from ..models import (
    DEFAULT_LOG_TYPE_COLOR,
    LOG_TYPE_COLOR_RE,
    LOG_TYPE_NAME_RE,
    RESERVED_LOG_TYPE_NAMES,
    LogTypeBadge,
    LogTypeDetectionRule,
    detect_log_type,
)
from .guest import moderator_required


def _existing_log_type_names() -> list:
    names = set(LogTypeBadge.objects.values_list('name', flat=True))
    names.update(LogTypeDetectionRule.objects.values_list('log_type', flat=True))
    names.discard('Unknown')
    return sorted(names)


def _badge_color_for(log_type: str) -> str:
    badge = LogTypeBadge.objects.filter(name=log_type).first()
    return badge.color if badge else DEFAULT_LOG_TYPE_COLOR


def _form_state_from_rule(rule: LogTypeDetectionRule | None) -> dict:
    if rule is None:
        return {
            'pk': '',
            'name': '',
            'log_type': '',
            'color': DEFAULT_LOG_TYPE_COLOR,
            'pattern': '',
            'scope': LogTypeDetectionRule.SCOPE_START,
            'priority': '100',
            'notes': '',
            'is_enabled': True,
            'is_builtin': False,
        }
    return {
        'pk': str(rule.pk),
        'name': rule.name,
        'log_type': rule.log_type,
        'color': _badge_color_for(rule.log_type),
        'pattern': rule.pattern,
        'scope': rule.scope,
        'priority': str(rule.priority),
        'notes': rule.notes,
        'is_enabled': rule.is_enabled,
        'is_builtin': rule.is_builtin,
    }


def _form_state_from_post(request) -> dict:
    return {
        'pk': request.POST.get('pk', '').strip(),
        'name': request.POST.get('name', '').strip(),
        'log_type': request.POST.get('log_type', '').strip(),
        'color': (request.POST.get('color') or DEFAULT_LOG_TYPE_COLOR).strip(),
        'pattern': request.POST.get('pattern', ''),
        'scope': request.POST.get('scope', LogTypeDetectionRule.SCOPE_START).strip(),
        'priority': request.POST.get('priority', '').strip(),
        'notes': request.POST.get('notes', ''),
        'is_enabled': request.POST.get('is_enabled') == 'on',
        'is_builtin': False,
    }


def _apply_form_to_rule(rule: LogTypeDetectionRule, form: dict) -> list:
    errors = []
    if not form['name']:
        errors.append('Name is required.')
    log_type = form['log_type']
    if not log_type or not LOG_TYPE_NAME_RE.match(log_type):
        errors.append('Log type name must start with a letter or digit; letters, digits, spaces, &, ., _ and - allowed (max 32).')
    elif log_type.lower() in RESERVED_LOG_TYPE_NAMES:
        errors.append(f'"{log_type}" is reserved.')
    color = form['color']
    if not LOG_TYPE_COLOR_RE.match(color):
        errors.append('Color must be a 6-digit hex like #aabbcc.')
    if form['scope'] not in dict(LogTypeDetectionRule.SCOPE_CHOICES):
        errors.append('Invalid scope.')
    pattern = (form['pattern'] or '').strip()
    if not pattern:
        errors.append('Pattern is required.')
    else:
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append(f'Invalid regex: {exc}')
    try:
        priority = int(form['priority']) if form['priority'] != '' else 100
    except (TypeError, ValueError):
        errors.append('Priority must be an integer.')
        priority = 100
    if errors:
        return errors
    rule.name = form['name']
    rule.log_type = log_type
    rule.pattern = pattern
    rule.scope = form['scope']
    rule.priority = priority
    rule.notes = form['notes']
    rule.is_enabled = form['is_enabled']
    return []


def _upsert_badge(log_type: str, color: str):
    """Create the badge if missing; if it exists and is not built-in, update its color."""
    badge, created = LogTypeBadge.objects.get_or_create(
        name=log_type, defaults={'color': color},
    )
    if not created and not badge.is_builtin and badge.color != color:
        badge.color = color
        badge.save(update_fields=['color', 'updated_at'])
    return badge


@moderator_required
@require_http_methods(['GET'])
def log_type_rules_view(request):
    search_q = (request.GET.get('q') or '').strip()
    qs = LogTypeDetectionRule.objects.order_by('-updated_at', '-id')
    if search_q:
        qs = qs.filter(
            Q(name__icontains=search_q)
            | Q(log_type__icontains=search_q)
            | Q(pattern__icontains=search_q)
        )
    paginator = Paginator(qs, 12)
    page_obj = paginator.get_page(request.GET.get('page'))
    badges = {b.name: b for b in LogTypeBadge.objects.all()}
    annotated = [
        {
            'rule': rule,
            'color': (badges.get(rule.log_type).color if badges.get(rule.log_type) else DEFAULT_LOG_TYPE_COLOR),
        }
        for rule in page_obj
    ]
    context = {
        'rules': annotated,
        'page_obj': page_obj,
        'search_q': search_q,
        'scope_choices': LogTypeDetectionRule.SCOPE_CHOICES,
    }
    return render(request, 'log_type_rules.html', context)


@moderator_required
@require_http_methods(['GET', 'POST'])
def add_log_type_rule_view(request):
    if request.method == 'POST':
        form = _form_state_from_post(request)
        rule = LogTypeDetectionRule(created_by=request.user)
        errors = _apply_form_to_rule(rule, form)
        if errors:
            for err in errors:
                messages.error(request, err)
        else:
            try:
                rule.full_clean()
                rule.save()
                _upsert_badge(rule.log_type, form['color'])
            except ValidationError as exc:
                for field_errors in exc.message_dict.values():
                    for err in field_errors:
                        messages.error(request, err)
            else:
                messages.success(request, f'Rule "{rule.name}" created.')
                return redirect('log_type_rules')
    else:
        form = _form_state_from_rule(None)

    context = {
        'form': form,
        'editing': False,
        'existing_log_types': _existing_log_type_names(),
        'scope_choices': LogTypeDetectionRule.SCOPE_CHOICES,
    }
    return render(request, 'add_log_type_rule.html', context)


@moderator_required
@require_http_methods(['GET', 'POST'])
def edit_log_type_rule_view(request, pk: int):
    rule = get_object_or_404(LogTypeDetectionRule, pk=pk)
    if request.method == 'POST':
        form = _form_state_from_post(request)
        errors = _apply_form_to_rule(rule, form)
        if errors:
            for err in errors:
                messages.error(request, err)
        else:
            try:
                rule.full_clean()
                rule.save()
                _upsert_badge(rule.log_type, form['color'])
            except ValidationError as exc:
                for field_errors in exc.message_dict.values():
                    for err in field_errors:
                        messages.error(request, err)
            else:
                messages.success(request, f'Rule "{rule.name}" updated.')
                return redirect('log_type_rules')
    else:
        form = _form_state_from_rule(rule)

    context = {
        'form': form,
        'editing': True,
        'existing_log_types': _existing_log_type_names(),
        'scope_choices': LogTypeDetectionRule.SCOPE_CHOICES,
    }
    return render(request, 'add_log_type_rule.html', context)


@moderator_required
@require_http_methods(['POST'])
def delete_log_type_rule_view(request, pk: int):
    rule = get_object_or_404(LogTypeDetectionRule, pk=pk)
    name = rule.name
    rule.delete()
    messages.success(request, f'Rule "{name}" deleted.')
    return redirect('log_type_rules')


@moderator_required
@require_http_methods(['POST'])
def toggle_log_type_rule_view(request, pk: int):
    rule = get_object_or_404(LogTypeDetectionRule, pk=pk)
    rule.is_enabled = not rule.is_enabled
    rule.save(update_fields=['is_enabled', 'updated_at'])
    label = 'enabled' if rule.is_enabled else 'disabled'
    messages.success(request, f'Rule "{rule.name}" {label}.')
    return redirect('log_type_rules')


@moderator_required
@require_http_methods(['POST'])
def test_log_type_api(request):
    """Test a single regex against pasted content and report what log_type would result.

    Body JSON: { content: str, pattern: str, scope: 'full'|'start' }
    Response: { matches: bool, error?: str, detected_log_type: str, sample?: str }
    """
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    content = payload.get('content') or ''
    if len(content) > 200000:
        return JsonResponse({'error': 'Content too large (max 200,000 chars).'}, status=400)
    pattern = (payload.get('pattern') or '').strip()
    scope = (payload.get('scope') or LogTypeDetectionRule.SCOPE_START).strip()
    if scope not in dict(LogTypeDetectionRule.SCOPE_CHOICES):
        scope = LogTypeDetectionRule.SCOPE_START

    response = {
        'matches': False,
        'sample': '',
        'detected_log_type': detect_log_type(content) if content else 'Unknown',
    }
    if pattern:
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            return JsonResponse({'error': f'Invalid regex: {exc}'}, status=400)
        target = content.lstrip()[:4096] if scope == LogTypeDetectionRule.SCOPE_START else content
        match = compiled.search(target)
        if match:
            response['matches'] = True
            response['sample'] = match.group(0)[:200]
    return JsonResponse(response)
