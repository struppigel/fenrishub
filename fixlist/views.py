from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.db.models import F, Q
from io import BytesIO
import json

from .analyzer import analyze_log_text, parse_rule_line, inspect_line_matches, VALID_STATUSES
from .models import Fixlist, AccessLog, ClassificationRule


def get_client_ip(request):
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def _rule_defaults_from_parsed(parsed: dict) -> dict:
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


def _upsert_classification_rule(parsed: dict) -> tuple[ClassificationRule, bool]:
    lookup = {
        'status': parsed['status'],
        'match_type': parsed['match_type'],
        'source_text': parsed['source_text'],
    }
    defaults = _rule_defaults_from_parsed(parsed)
    return ClassificationRule.objects.update_or_create(**lookup, defaults=defaults)


def _normalize_pending_changes(raw_changes) -> tuple[list[dict], list[dict]]:
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

        if not isinstance(line, str):
            invalid.append({'index': index, 'error': 'Field "line" must be a string.'})
            continue
        if not isinstance(new_status, str):
            invalid.append({'index': index, 'error': 'Field "new_status" must be a string.'})
            continue
        if original_status and not isinstance(original_status, str):
            invalid.append({'index': index, 'error': 'Field "original_status" must be a string when provided.'})
            continue

        line = line.strip()
        new_status = new_status.strip()
        original_status = (original_status or '').strip() or '?'

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
            }
        )

    return normalized, invalid


def _build_pending_rule_preview(pending_changes: list[dict], username: str) -> dict:
    manual_changes = []
    rule_changes = []
    override_conflicts = []
    overlap_conflicts = []

    create_count = 0
    update_count = 0

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

        lookup = {
            'status': parsed['status'],
            'match_type': parsed['match_type'],
            'source_text': parsed['source_text'],
        }
        existing_rule = ClassificationRule.objects.filter(**lookup).first()
        action = 'update' if existing_rule else 'create'
        if action == 'create':
            create_count += 1
        else:
            update_count += 1

        inspection = inspect_line_matches(line)
        dominant_existing = inspection['dominant_status']
        status_codes = inspection['status_codes']
        overlapping_matches = [match for match in inspection['matches'] if match['status'] != new_status]

        if dominant_existing not in ('?', new_status):
            override_conflicts.append(
                {
                    'id': change['id'],
                    'line': line,
                    'selected_status': new_status,
                    'existing_dominant_status': dominant_existing,
                    'existing_status_codes': status_codes,
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


@require_http_methods(["GET", "POST"])
def login_view(request):
    """User login view."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})
    
    return render(request, 'login.html')


@login_required
@require_http_methods(["GET"])
def dashboard_view(request):
    """List all fixlists for the logged-in user."""
    fixlists = Fixlist.objects.filter(owner=request.user)
    return render(request, 'dashboard.html', {'fixlists': fixlists})


@login_required
@require_http_methods(["GET", "POST"])
def create_fixlist_view(request):
    """Create a new fixlist on a dedicated page."""
    if request.method == 'POST':
        title = request.POST.get('title', 'Untitled')
        content = request.POST.get('content', '')
        internal_note = request.POST.get('internal_note', '')

        fixlist = Fixlist.objects.create(
            owner=request.user,
            title=title,
            content=content,
            internal_note=internal_note,
        )

        persist_rules_flag = str(request.POST.get('persist_rules', '')).strip().lower() in {'1', 'true', 'yes', 'on'}
        if persist_rules_flag:
            raw_pending_json = request.POST.get('pending_rule_changes_json', '[]')
            raw_selected_ids_json = request.POST.get('selected_rule_change_ids_json', '[]')

            try:
                raw_pending_changes = json.loads(raw_pending_json or '[]')
            except json.JSONDecodeError:
                raw_pending_changes = []

            try:
                selected_ids_payload = json.loads(raw_selected_ids_json or '[]')
            except json.JSONDecodeError:
                selected_ids_payload = []

            selected_ids = {
                str(value)
                for value in (selected_ids_payload if isinstance(selected_ids_payload, list) else [])
            }
            normalized_changes, _ = _normalize_pending_changes(raw_pending_changes)

            source_name = f'fixlist-save:{request.user.username}'
            for change in normalized_changes:
                if change['id'] not in selected_ids:
                    continue
                parsed = parse_rule_line(change['line'], status=change['new_status'], source_name=source_name)
                if not parsed:
                    continue
                _upsert_classification_rule(parsed)

        return redirect('view_fixlist', pk=fixlist.pk)

    return render(request, 'create_fixlist.html')


@login_required
@require_http_methods(["GET", "POST"])
def view_fixlist(request, pk):
    """View and edit a fixlist."""
    fixlist = get_object_or_404(Fixlist, pk=pk, owner=request.user)
    
    if request.method == 'POST':
        action = request.POST.get('action', '')
        
        if action == 'update':
            fixlist.title = request.POST.get('title', fixlist.title)
            fixlist.content = request.POST.get('content', fixlist.content)
            fixlist.internal_note = request.POST.get('internal_note', fixlist.internal_note)
            fixlist.save()
            return redirect('view_fixlist', pk=fixlist.pk)
        
        elif action == 'delete':
            fixlist.delete()
            return redirect('dashboard')
    
    share_url = request.build_absolute_uri(f'/share/{fixlist.share_token}/')

    context = {
        'fixlist': fixlist,
        'share_url': share_url,
        'guest_preview_url': f'{share_url}?preview=guest',
    }
    return render(request, 'view_fixlist.html', context)


@require_http_methods(["GET"])
def shared_fixlist_view(request, token):
    """View a shared fixlist (non-authenticated access)."""
    fixlist = get_object_or_404(Fixlist, share_token=token)
    
    # Log access
    AccessLog.objects.create(
        fixlist=fixlist,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    # Let the owner preview the page as a guest with ?preview=guest.
    preview_as_guest = (
        request.GET.get('preview') == 'guest'
        and request.user.is_authenticated
        and request.user == fixlist.owner
    )

    # Check if user should be treated as owner for UI behavior.
    is_owner = request.user.is_authenticated and request.user == fixlist.owner and not preview_as_guest
    
    context = {
        'fixlist': fixlist,
        'is_owner': is_owner,
        'preview_as_guest': preview_as_guest,
    }
    return render(request, 'shared_fixlist.html', context)


@require_http_methods(["POST"])
@login_required
def logout_view(request):
    """User logout view."""
    logout(request)
    return redirect('login')


@require_http_methods(["GET"])
def download_fixlist(request, token):
    """Download a fixlist as a text file."""
    fixlist = get_object_or_404(Fixlist, share_token=token)
    Fixlist.objects.filter(pk=fixlist.pk).update(download_count=F('download_count') + 1)
    
    # Log access
    AccessLog.objects.create(
        fixlist=fixlist,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    response = HttpResponse(fixlist.content, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="Fixlist.txt"'
    return response


@require_http_methods(["POST"])
@csrf_exempt
def copy_to_clipboard_api(request, token):
    """API endpoint for copying fixlist content."""
    fixlist = get_object_or_404(Fixlist, share_token=token)
    
    AccessLog.objects.create(
        fixlist=fixlist,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    return JsonResponse({'content': fixlist.content})


@login_required
@require_http_methods(["GET"])
def log_analyzer_view(request):
    """Render log analyzer tool."""
    return render(request, 'log_analyzer.html')


@login_required
@require_http_methods(["POST"])
def analyze_log_api(request):
    """Analyze pasted FRST log content and return line-level classifications."""
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    log_text = payload.get('log', '')
    if not isinstance(log_text, str):
        return JsonResponse({'error': 'Field "log" must be a string.'}, status=400)

    analysis = analyze_log_text(log_text)
    return JsonResponse(analysis)


@login_required
@require_http_methods(["POST"])
def preview_pending_rule_changes_api(request):
    """Preview optional rule persistence before creating a fixlist."""
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    pending_changes = payload.get('pending_changes', [])
    normalized_changes, invalid_changes = _normalize_pending_changes(pending_changes)
    if pending_changes is not None and not isinstance(pending_changes, list):
        return JsonResponse({'error': 'Field "pending_changes" must be a list.'}, status=400)

    preview = _build_pending_rule_preview(normalized_changes, request.user.username)
    preview['invalid_changes'] = invalid_changes
    return JsonResponse(preview)


@login_required
@require_http_methods(["POST"])
def update_analyzed_line_status_api(request):
    """Validate a status override payload without persisting it to the database."""
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    line = payload.get('line', '')
    status = payload.get('status', '')
    current_status = payload.get('current_status', '')

    if not isinstance(line, str):
        return JsonResponse({'error': 'Field "line" must be a string.'}, status=400)
    if not isinstance(status, str):
        return JsonResponse({'error': 'Field "status" must be a string.'}, status=400)
    if current_status and not isinstance(current_status, str):
        return JsonResponse({'error': 'Field "current_status" must be a string when provided.'}, status=400)

    line = line.strip()
    status = status.strip()
    current_status = current_status.strip()

    if not line:
        return JsonResponse({'error': 'Field "line" cannot be empty.'}, status=400)
    if status not in VALID_STATUSES:
        return JsonResponse({'error': f'Invalid status: {status}'}, status=400)
    if current_status == ClassificationRule.STATUS_INFO:
        return JsonResponse({'error': 'Informational lines cannot be edited.'}, status=400)
    if status == ClassificationRule.STATUS_INFO:
        return JsonResponse({'error': 'Setting informational status from analyzer is not allowed.'}, status=400)

    source_name = f'analyzer-ui:{request.user.username}'
    parsed = parse_rule_line(line, status=status, source_name=source_name)
    if not parsed:
        return JsonResponse({'error': 'Unable to parse line into a classification rule.'}, status=400)

    return JsonResponse(
        {
            'persisted': False,
            'status': parsed['status'],
            'match_type': parsed['match_type'],
            'source_text': parsed['source_text'],
        }
    )
