from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.db.models import F, Q
from django.db import transaction
from io import BytesIO
import json

from .analyzer import analyze_log_text, parse_rule_line, inspect_line_matches, VALID_STATUSES
from .models import Fixlist, AccessLog, ClassificationRule


CONFLICT_ACTION_UPDATE_EXISTING = 'update_existing_status'
CONFLICT_ACTION_KEEP_BOTH = 'keep_both'
CONFLICT_ACTION_KEEP_NEW_DISABLE_OTHER = 'keep_new_disable_other'
CONFLICT_ACTION_DISCARD_NEW = 'discard_new'

VALID_CONFLICT_ACTIONS = {
    CONFLICT_ACTION_UPDATE_EXISTING,
    CONFLICT_ACTION_KEEP_BOTH,
    CONFLICT_ACTION_KEEP_NEW_DISABLE_OTHER,
    CONFLICT_ACTION_DISCARD_NEW,
}


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


def _upsert_classification_rule(parsed: dict, owner: User) -> tuple[ClassificationRule, bool]:
    lookup = {
        'owner': owner,
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
        description = raw.get('description', None)

        if not isinstance(line, str):
            invalid.append({'index': index, 'error': 'Field "line" must be a string.'})
            continue
        if not isinstance(new_status, str):
            invalid.append({'index': index, 'error': 'Field "new_status" must be a string.'})
            continue
        if original_status and not isinstance(original_status, str):
            invalid.append({'index': index, 'error': 'Field "original_status" must be a string when provided.'})
            continue
        if description is not None and not isinstance(description, str):
            invalid.append({'index': index, 'error': 'Field "description" must be a string when provided.'})
            continue

        line = line.strip()
        new_status = new_status.strip()
        original_status = (original_status or '').strip() or '?'
        description = description if description is None else description.strip()

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
                'description': description,
            }
        )

    return normalized, invalid


def _normalize_conflict_resolutions(raw_resolutions) -> list[dict]:
    normalized = []
    if raw_resolutions is None or not isinstance(raw_resolutions, list):
        return normalized

    for raw in raw_resolutions:
        if not isinstance(raw, dict):
            continue

        action = str(raw.get('action', '')).strip().lower()
        change_id = str(raw.get('change_id', '')).strip()
        contradiction_type = str(raw.get('contradiction_type', '')).strip().lower()
        conflict_key = str(raw.get('conflict_key', '')).strip()
        existing_rule_id = raw.get('existing_rule_id', None)

        if action not in VALID_CONFLICT_ACTIONS or not change_id:
            continue

        parsed_rule_id = None
        if isinstance(existing_rule_id, int):
            parsed_rule_id = existing_rule_id
        elif isinstance(existing_rule_id, str) and existing_rule_id.strip().isdigit():
            parsed_rule_id = int(existing_rule_id.strip())

        normalized.append(
            {
                'action': action,
                'change_id': change_id,
                'contradiction_type': contradiction_type,
                'existing_rule_id': parsed_rule_id,
                'conflict_key': conflict_key,
            }
        )

    return normalized


def _apply_conflict_resolutions(
    normalized_changes: list[dict],
    selected_ids: set[str],
    conflict_resolutions: list[dict],
    owner: User,
) -> set[str]:
    selected_change_map = {
        change['id']: change
        for change in normalized_changes
        if change['id'] in selected_ids
    }
    discarded_change_ids = {
        resolution['change_id']
        for resolution in conflict_resolutions
        if resolution['action'] in {CONFLICT_ACTION_DISCARD_NEW, CONFLICT_ACTION_UPDATE_EXISTING}
        and resolution['change_id'] in selected_change_map
    }
    effective_selected_ids = {
        change_id
        for change_id in selected_ids
        if change_id not in discarded_change_ids
    }

    for resolution in conflict_resolutions:
        change_id = resolution['change_id']
        if change_id not in selected_change_map:
            continue

        existing_rule_id = resolution['existing_rule_id']
        if existing_rule_id is None:
            continue

        existing_rule = ClassificationRule.objects.filter(pk=existing_rule_id, owner=owner).first()
        if not existing_rule:
            continue

        action = resolution['action']
        if action == CONFLICT_ACTION_UPDATE_EXISTING:
            target_change = selected_change_map.get(change_id)
            if not target_change:
                continue

            target_status = target_change['new_status']
            duplicate_rule = (
                ClassificationRule.objects.filter(
                    owner=owner,
                    status=target_status,
                    match_type=existing_rule.match_type,
                    source_text=existing_rule.source_text,
                )
                .exclude(pk=existing_rule.pk)
                .first()
            )

            if duplicate_rule:
                if not duplicate_rule.is_enabled:
                    duplicate_rule.is_enabled = True
                    duplicate_rule.save(update_fields=['is_enabled', 'updated_at'])
                if existing_rule.is_enabled:
                    existing_rule.is_enabled = False
                    existing_rule.save(update_fields=['is_enabled', 'updated_at'])
                continue

            update_fields = []
            if existing_rule.status != target_status:
                existing_rule.status = target_status
                update_fields.append('status')
            if not existing_rule.is_enabled:
                existing_rule.is_enabled = True
                update_fields.append('is_enabled')
            if update_fields:
                update_fields.append('updated_at')
                existing_rule.save(update_fields=update_fields)
            continue

        if change_id not in effective_selected_ids:
            continue

        if action == CONFLICT_ACTION_KEEP_NEW_DISABLE_OTHER:
            if existing_rule.is_enabled:
                existing_rule.is_enabled = False
                existing_rule.save(update_fields=['is_enabled', 'updated_at'])
            continue

    return effective_selected_ids


def _build_pending_rule_preview(pending_changes: list[dict], username: str, owner: User) -> dict:
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
            'owner': owner,
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
        dominant_matching_rules = [
            match
            for match in inspection['matches']
            if match['status'] == dominant_existing and match['status'] != new_status
        ]
        overlapping_matches = [match for match in inspection['matches'] if match['status'] != new_status]

        if dominant_existing not in ('?', new_status):
            override_conflicts.append(
                {
                    'id': change['id'],
                    'line': line,
                    'selected_status': new_status,
                    'existing_dominant_status': dominant_existing,
                    'existing_status_codes': status_codes,
                    'matching_rules': dominant_matching_rules,
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
                'entry_type': parsed.get('entry_type', ''),
                'clsid': parsed.get('clsid', ''),
                'name': parsed.get('name', ''),
                'filepath': parsed.get('filepath', ''),
                'normalized_filepath': parsed.get('normalized_filepath', ''),
                'filename': parsed.get('filename', ''),
                'company': parsed.get('company', ''),
                'arguments': parsed.get('arguments', ''),
                'file_not_signed': parsed.get('file_not_signed', False),
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


def _persist_selected_pending_rules(
    *,
    raw_pending_changes,
    raw_selected_ids,
    raw_conflict_resolutions,
    username: str,
    source_prefix: str,
    owner: User,
) -> dict:
    selected_ids = {
        str(value)
        for value in (raw_selected_ids if isinstance(raw_selected_ids, list) else [])
    }
    normalized_changes, invalid_changes = _normalize_pending_changes(raw_pending_changes)
    conflict_resolutions = _normalize_conflict_resolutions(raw_conflict_resolutions)

    created_rules = 0
    updated_rules = 0
    skipped_changes = 0

    with transaction.atomic():
        effective_selected_ids = _apply_conflict_resolutions(
            normalized_changes,
            selected_ids,
            conflict_resolutions,
            owner,
        )

        source_name = f'{source_prefix}:{username}'
        for change in normalized_changes:
            if change['id'] not in effective_selected_ids:
                continue

            parsed = parse_rule_line(change['line'], status=change['new_status'], source_name=source_name)
            if not parsed:
                skipped_changes += 1
                continue

            if change.get('description') is not None:
                parsed['description'] = change['description']

            _, is_created = _upsert_classification_rule(parsed, owner=owner)
            if is_created:
                created_rules += 1
            else:
                updated_rules += 1

    return {
        'created_rules': created_rules,
        'updated_rules': updated_rules,
        'skipped_changes': skipped_changes,
        'invalid_changes_count': len(invalid_changes),
        'selected_candidates': len(selected_ids),
        'effective_selected_candidates': len(
            [change for change in normalized_changes if change['id'] in effective_selected_ids]
        ),
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
@require_http_methods(["GET", "POST"])
def change_password_view(request):
    """Allow authenticated users to change their password without email input."""
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            updated_user = form.save()
            # Keep the current session active after password update.
            update_session_auth_hash(request, updated_user)
            messages.success(request, 'Password updated successfully.')
            return redirect('change_password')
    else:
        form = PasswordChangeForm(request.user)

    return render(request, 'change_password.html', {'form': form})


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
def analyze_line_details_api(request):
    """Inspect a single line and return parsed metadata plus matching rule details."""
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    line = payload.get('line', '')
    requested_status = payload.get('status', ClassificationRule.STATUS_UNKNOWN)

    if not isinstance(line, str):
        return JsonResponse({'error': 'Field "line" must be a string.'}, status=400)
    if not isinstance(requested_status, str):
        return JsonResponse({'error': 'Field "status" must be a string.'}, status=400)

    line = line.strip()
    requested_status = requested_status.strip() or ClassificationRule.STATUS_UNKNOWN

    if not line:
        return JsonResponse({'error': 'Field "line" cannot be empty.'}, status=400)
    if requested_status not in VALID_STATUSES:
        requested_status = ClassificationRule.STATUS_UNKNOWN

    parsed_rule = parse_rule_line(
        line,
        status=requested_status,
        source_name=f'analyzer-inspect:{request.user.username}',
    )
    inspection = inspect_line_matches(line)

    return JsonResponse(
        {
            'line': line,
            'parsed_rule': parsed_rule,
            'inspection': inspection,
        }
    )


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

    preview = _build_pending_rule_preview(normalized_changes, request.user.username, request.user)
    preview['invalid_changes'] = invalid_changes
    return JsonResponse(preview)


@login_required
@require_http_methods(["POST"])
def persist_pending_rule_changes_api(request):
    """Persist selected pending analyzer changes as classification rules immediately."""
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    pending_changes = payload.get('pending_changes', [])
    selected_ids = payload.get('selected_rule_change_ids', [])
    conflict_resolutions = payload.get('conflict_resolutions', [])

    if pending_changes is not None and not isinstance(pending_changes, list):
        return JsonResponse({'error': 'Field "pending_changes" must be a list.'}, status=400)
    if selected_ids is not None and not isinstance(selected_ids, list):
        return JsonResponse({'error': 'Field "selected_rule_change_ids" must be a list.'}, status=400)
    if conflict_resolutions is not None and not isinstance(conflict_resolutions, list):
        return JsonResponse({'error': 'Field "conflict_resolutions" must be a list.'}, status=400)

    result = _persist_selected_pending_rules(
        raw_pending_changes=pending_changes,
        raw_selected_ids=selected_ids,
        raw_conflict_resolutions=conflict_resolutions,
        username=request.user.username,
        source_prefix='analyzer-persist',
        owner=request.user,
    )

    return JsonResponse({'ok': True, **result})


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
