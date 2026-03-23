from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from django.conf import settings
from django.core.cache import cache
from django.http import Http404, JsonResponse, HttpResponse, FileResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Count, F
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
from io import BytesIO
import json
import re

from .analyzer import analyze_log_text, parse_rule_line, inspect_line_matches, VALID_STATUSES
from .forms import UploadedLogForm
from .models import Fixlist, AccessLog, ClassificationRule, FixlistSnippet, UploadedLog


def _purge_old_trash():
    cutoff = timezone.now() - timedelta(days=30)
    UploadedLog.objects.filter(deleted_at__isnull=False, deleted_at__lt=cutoff).delete()
    Fixlist.objects.filter(deleted_at__isnull=False, deleted_at__lt=cutoff).delete()


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


def _anonymous_upload_limit() -> tuple[int, int]:
    limit = int(getattr(settings, 'ANON_UPLOAD_RATE_LIMIT_COUNT', 15) or 15)
    window_seconds = int(getattr(settings, 'ANON_UPLOAD_RATE_LIMIT_WINDOW_SECONDS', 3600) or 3600)
    return max(1, limit), max(1, window_seconds)


def _consume_anonymous_upload_slot(client_ip: str) -> bool:
    if not client_ip:
        return True

    limit, window_seconds = _anonymous_upload_limit()
    cache_key = f'anon-upload-rate:{client_ip}'
    current_count = int(cache.get(cache_key, 0) or 0)
    if current_count >= limit:
        return False

    if current_count == 0:
        cache.add(cache_key, 1, timeout=window_seconds)
        return True

    try:
        cache.incr(cache_key)
    except ValueError:
        cache.set(cache_key, current_count + 1, timeout=window_seconds)
    return True


def _merged_upload_username_for_user(user: User) -> str:
    normalized = re.sub(r'[^A-Za-z0-9_]+', '_', user.username or '').strip('_')
    candidate = f'merged_{normalized}' if normalized else 'merged_logs'
    return candidate[:20]


def _merge_logs_content(logs):
    """Merge content from multiple UploadedLog objects."""
    merged_parts = []
    for index, uploaded_log in enumerate(logs):
        piece = uploaded_log.content or ''
        if index > 0 and merged_parts and not merged_parts[-1].endswith('\n'):
            merged_parts[-1] = f"{merged_parts[-1]}\n"
        merged_parts.append(piece)
    return ''.join(merged_parts)


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
    fixlists = Fixlist.objects.filter(owner=request.user, deleted_at__isnull=True)
    fixlist_trash_count = Fixlist.objects.filter(owner=request.user, deleted_at__isnull=False).count()
    return render(request, 'dashboard.html', {'fixlists': fixlists, 'fixlist_trash_count': fixlist_trash_count})


@require_http_methods(["GET", "POST"])
def upload_log_view(request):
    """Public upload endpoint for text logs."""
    uploaded_log_id = None
    uploaded_original_filename = None
    upload_limit, upload_window_seconds = _anonymous_upload_limit()

    if request.method == 'POST':
        form = UploadedLogForm(request.POST, request.FILES)
        if not request.user.is_authenticated:
            client_ip = get_client_ip(request)
            if not _consume_anonymous_upload_slot(client_ip):
                minutes = max(1, (upload_window_seconds + 59) // 60)
                form.add_error(
                    None,
                    (
                        f'Anonymous upload rate limit reached: {upload_limit} upload(s) '
                        f'per {minutes} minute(s). Please wait and try again.'
                    ),
                )
                return render(
                    request,
                    'upload_log.html',
                    {
                        'form': form,
                        'uploaded_log_id': uploaded_log_id,
                        'uploaded_original_filename': uploaded_original_filename,
                    },
                )

        if form.is_valid():
            log_file = form.cleaned_data.get('log_file')
            if log_file:
                filename = log_file.name
                content = getattr(log_file, 'decoded_content', '')
            else:
                filename = 'pasted.txt'
                content = form.cleaned_data['log_text']
            created_log = UploadedLog.objects.create(
                reddit_username=form.cleaned_data['reddit_username'],
                original_filename=filename,
                content=content,
            )
            created_log.recalculate_log_type()
            try:
                created_log.recalculate_analysis_stats()
            except Exception as e:
                import traceback
                print(f"ERROR calculating stats for {created_log.upload_id}: {e}")
                traceback.print_exc()
            request.session['upload_success_id'] = created_log.upload_id
            request.session['upload_success_filename'] = created_log.original_filename
            return redirect('upload_log')
    else:
        prefill = request.GET.get('u', '')
        form = UploadedLogForm(initial={'reddit_username': prefill} if prefill else None)

    uploaded_log_id = request.session.pop('upload_success_id', None)
    uploaded_original_filename = request.session.pop('upload_success_filename', None)

    return render(
        request,
        'upload_log.html',
        {
            'form': form,
            'uploaded_log_id': uploaded_log_id,
            'uploaded_original_filename': uploaded_original_filename,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def uploaded_logs_view(request):
    """List uploaded logs for authenticated users and support merge/delete actions."""
    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'delete':
            upload_id = request.POST.get('upload_id', '').strip()
            uploaded_log = get_object_or_404(UploadedLog, upload_id=upload_id, deleted_at__isnull=True)
            uploaded_log.deleted_at = timezone.now()
            uploaded_log.save(update_fields=['deleted_at'])
            _purge_old_trash()
            messages.success(request, f'Upload {upload_id} moved to trash.')
            return redirect('uploaded_logs')

        if action == 'merge':
            selected_ids = []
            seen_ids = set()
            for upload_id in request.POST.getlist('selected_upload_ids'):
                normalized_id = str(upload_id).strip()
                if not normalized_id or normalized_id in seen_ids:
                    continue
                seen_ids.add(normalized_id)
                selected_ids.append(normalized_id)

            if len(selected_ids) < 2:
                messages.error(request, 'Select at least two uploads to merge.')
                return redirect('uploaded_logs')

            selected_logs = list(UploadedLog.objects.filter(upload_id__in=selected_ids))
            logs_by_id = {entry.upload_id: entry for entry in selected_logs}
            missing_ids = [upload_id for upload_id in selected_ids if upload_id not in logs_by_id]
            if missing_ids:
                messages.error(request, f'Unable to find upload(s): {", ".join(missing_ids)}.')
                return redirect('uploaded_logs')

            ordered_logs = [logs_by_id[upload_id] for upload_id in selected_ids]
            
            # Collect unique usernames from selected logs
            usernames = list(set(log.reddit_username for log in ordered_logs))
            
            # If usernames differ, show selection page
            if len(usernames) > 1:
                context = {
                    'selected_logs': ordered_logs,
                    'selected_upload_ids': selected_ids,
                    'usernames': sorted(usernames),
                }
                return render(request, 'merge_username_selection.html', context)
            
            # All usernames are the same, proceed with merge using that username
            selected_username = usernames[0]
            retained_id = ordered_logs[0].upload_id
            merged_content = _merge_logs_content(ordered_logs)
            now = timezone.now()
            for log in ordered_logs:
                log.upload_id = log.upload_id + '-trsh'
                log.deleted_at = now
                log.save(update_fields=['upload_id', 'deleted_at'])
            _purge_old_trash()
            merged_upload = UploadedLog.objects.create(
                upload_id=retained_id,
                reddit_username=selected_username,
                original_filename='merged-logs.txt',
                content=merged_content,
                created_by=request.user,
            )
            merged_upload.recalculate_log_type()
            try:
                merged_upload.recalculate_analysis_stats()
            except Exception as e:
                import traceback
                print(f"ERROR calculating stats for merged {merged_upload.upload_id}: {e}")
                traceback.print_exc()

            messages.success(request, f'Merged upload created with id {merged_upload.upload_id}.')
            return redirect('view_uploaded_log', upload_id=merged_upload.upload_id)

        if action == 'confirm_merge':
            selected_ids = request.POST.getlist('selected_upload_ids')
            selected_username = request.POST.get('selected_username', '').strip()
            
            if len(selected_ids) < 2:
                messages.error(request, 'Select at least two uploads to merge.')
                return redirect('uploaded_logs')
            
            if not selected_username:
                messages.error(request, 'Please select a username.')
                return redirect('uploaded_logs')
            
            selected_logs = list(UploadedLog.objects.filter(upload_id__in=selected_ids))
            logs_by_id = {entry.upload_id: entry for entry in selected_logs}
            missing_ids = [upload_id for upload_id in selected_ids if upload_id not in logs_by_id]
            if missing_ids:
                messages.error(request, f'Unable to find upload(s): {", ".join(missing_ids)}.')
                return redirect('uploaded_logs')
            
            ordered_logs = [logs_by_id[upload_id] for upload_id in selected_ids]
            
            # Validate selected username exists in the logs
            available_usernames = set(log.reddit_username for log in ordered_logs)
            if selected_username not in available_usernames:
                messages.error(request, 'Invalid username selection.')
                return redirect('uploaded_logs')
            
            retained_id = ordered_logs[0].upload_id
            merged_content = _merge_logs_content(ordered_logs)
            now = timezone.now()
            for log in ordered_logs:
                log.upload_id = log.upload_id + '-trsh'
                log.deleted_at = now
                log.save(update_fields=['upload_id', 'deleted_at'])
            _purge_old_trash()
            merged_upload = UploadedLog.objects.create(
                upload_id=retained_id,
                reddit_username=selected_username,
                original_filename='merged-logs.txt',
                content=merged_content,
                created_by=request.user,
            )
            merged_upload.recalculate_log_type()
            try:
                merged_upload.recalculate_analysis_stats()
            except Exception as e:
                import traceback
                print(f"ERROR calculating stats for merged {merged_upload.upload_id}: {e}")
                traceback.print_exc()

            messages.success(request, f'Merged upload created with id {merged_upload.upload_id}.')
            return redirect('view_uploaded_log', upload_id=merged_upload.upload_id)

        if action == 'rescan_stats_all':
            rescanned_count = 0
            failed_upload_ids = []

            for uploaded_log in UploadedLog.objects.filter(deleted_at__isnull=True).iterator():
                try:
                    uploaded_log.recalculate_analysis_stats()
                    uploaded_log.recalculate_log_type()
                    rescanned_count += 1
                except Exception:
                    failed_upload_ids.append(uploaded_log.upload_id)

            if failed_upload_ids:
                failed_preview = ', '.join(failed_upload_ids[:5])
                if len(failed_upload_ids) > 5:
                    failed_preview = f'{failed_preview}, ...'
                messages.warning(
                    request,
                    (
                        f'Rescanned stats for {rescanned_count} upload(s), '
                        f'failed for {len(failed_upload_ids)}: {failed_preview}'
                    ),
                )
            else:
                messages.success(request, f'Rescanned stats for {rescanned_count} upload(s).')

            return redirect('uploaded_logs')

        messages.error(request, 'Invalid action.')
        return redirect('uploaded_logs')

    username_filter = request.GET.get('u', '').strip()
    uploads = UploadedLog.objects.filter(deleted_at__isnull=True)
    if username_filter:
        uploads = uploads.filter(reddit_username=username_filter)
    all_usernames = UploadedLog.objects.filter(deleted_at__isnull=True).values_list('reddit_username', flat=True).distinct().order_by('reddit_username')
    trash_count = UploadedLog.objects.filter(deleted_at__isnull=False).count()
    duplicate_hashes = set(
        UploadedLog.objects.filter(deleted_at__isnull=True)
        .exclude(content_hash='')
        .values('content_hash')
        .annotate(cnt=Count('id'))
        .filter(cnt__gt=1)
        .values_list('content_hash', flat=True)
    )
    return render(request, 'uploaded_logs.html', {
        'uploads': uploads,
        'username_filter': username_filter,
        'all_usernames': all_usernames,
        'trash_count': trash_count,
        'duplicate_hashes': duplicate_hashes,
    })


@login_required
@require_http_methods(["GET", "POST"])
def view_uploaded_log(request, upload_id):
    """View a single uploaded log by memorable ID."""
    uploaded_log = get_object_or_404(UploadedLog, upload_id=upload_id, deleted_at__isnull=True)

    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'delete':
            uploaded_log.deleted_at = timezone.now()
            uploaded_log.save(update_fields=['deleted_at'])
            _purge_old_trash()
            messages.success(request, f'Upload {upload_id} moved to trash.')
            return redirect('uploaded_logs')

        if action == 'rename_reddit':
            new_username = request.POST.get('reddit_username', '').strip()
            if new_username:
                uploaded_log.reddit_username = new_username
                uploaded_log.save(update_fields=['reddit_username'])
            return redirect('view_uploaded_log', upload_id=upload_id)

    return render(request, 'view_uploaded_log.html', {'uploaded_log': uploaded_log})


@login_required
@require_http_methods(["GET", "POST"])
def uploads_trash_view(request):
    """Trash bin for soft-deleted uploaded logs."""
    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'restore':
            upload_id = request.POST.get('upload_id', '').strip()
            uploaded_log = get_object_or_404(UploadedLog, upload_id=upload_id, deleted_at__isnull=False)
            uploaded_log.deleted_at = None
            uploaded_log.save(update_fields=['deleted_at'])
            messages.success(request, f'Upload {upload_id} restored.')
            return redirect('uploads_trash')

        if action == 'delete_permanent':
            upload_id = request.POST.get('upload_id', '').strip()
            uploaded_log = get_object_or_404(UploadedLog, upload_id=upload_id, deleted_at__isnull=False)
            uploaded_log.delete()
            messages.success(request, f'Upload {upload_id} permanently deleted.')
            return redirect('uploads_trash')

        if action == 'empty_trash':
            count, _ = UploadedLog.objects.filter(deleted_at__isnull=False).delete()
            messages.success(request, f'Trash emptied ({count} upload(s) permanently deleted).')
            return redirect('uploads_trash')

        messages.error(request, 'Invalid action.')
        return redirect('uploads_trash')

    trashed = UploadedLog.objects.filter(deleted_at__isnull=False).order_by('-deleted_at')
    return render(request, 'uploads_trash.html', {'uploads': trashed})


@login_required
@require_http_methods(["GET"])
def uploaded_log_content_api(request, upload_id):
    """Return upload content for analyzer prefill."""
    uploaded_log = get_object_or_404(UploadedLog, upload_id=upload_id, deleted_at__isnull=True)
    return JsonResponse(
        {
            'upload_id': uploaded_log.upload_id,
            'content': uploaded_log.content,
            'original_filename': uploaded_log.original_filename,
            'reddit_username': uploaded_log.reddit_username,
        }
    )


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
def fixlists_trash_view(request):
    """Trash bin for soft-deleted fixlists."""
    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'restore':
            pk = request.POST.get('pk', '').strip()
            fixlist = get_object_or_404(Fixlist, pk=pk, owner=request.user, deleted_at__isnull=False)
            fixlist.deleted_at = None
            fixlist.save(update_fields=['deleted_at'])
            messages.success(request, f'Fixlist "{fixlist.title}" restored.')
            return redirect('fixlists_trash')

        if action == 'delete_permanent':
            pk = request.POST.get('pk', '').strip()
            fixlist = get_object_or_404(Fixlist, pk=pk, owner=request.user, deleted_at__isnull=False)
            title = fixlist.title
            fixlist.delete()
            messages.success(request, f'Fixlist "{title}" permanently deleted.')
            return redirect('fixlists_trash')

        if action == 'empty_trash':
            count, _ = Fixlist.objects.filter(owner=request.user, deleted_at__isnull=False).delete()
            messages.success(request, f'Trash emptied ({count} fixlist(s) permanently deleted).')
            return redirect('fixlists_trash')

        messages.error(request, 'Invalid action.')
        return redirect('fixlists_trash')

    trashed = Fixlist.objects.filter(owner=request.user, deleted_at__isnull=False).order_by('-deleted_at')
    return render(request, 'fixlists_trash.html', {'fixlists': trashed})


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
            fixlist.deleted_at = timezone.now()
            fixlist.save(update_fields=['deleted_at'])
            _purge_old_trash()
            messages.success(request, f'Fixlist "{fixlist.title}" moved to trash.')
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

    # Trashed fixlists are not accessible by guests.
    if fixlist.deleted_at is not None and not (
        request.user.is_authenticated and request.user == fixlist.owner
    ):
        raise Http404

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
    if fixlist.deleted_at is not None and not (
        request.user.is_authenticated and request.user == fixlist.owner
    ):
        raise Http404
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
    if fixlist.deleted_at is not None and not (
        request.user.is_authenticated and request.user == fixlist.owner
    ):
        raise Http404

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
    uploads = UploadedLog.objects.filter(deleted_at__isnull=True)[:200]
    requested_upload_id = (request.GET.get('upload_id') or '').strip()
    initial_upload_id = requested_upload_id if requested_upload_id else ''
    return render(
        request,
        'log_analyzer.html',
        {
            'uploaded_logs': uploads,
            'initial_upload_id': initial_upload_id,
            'is_superuser': request.user.is_superuser,
        },
    )


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
    upload_id = payload.get('upload_id', '')
    if upload_id is None:
        upload_id = ''
    if not isinstance(upload_id, str):
        return JsonResponse({'error': 'Field "upload_id" must be a string when provided.'}, status=400)
    upload_id = upload_id.strip()

    analysis = analyze_log_text(log_text)
    if upload_id:
        uploaded_log = UploadedLog.objects.filter(upload_id=upload_id).first()
        if uploaded_log:
            try:
                uploaded_log.apply_analysis_summary(analysis.get('summary', {}))
                uploaded_log.save(update_fields=UploadedLog.analysis_stat_update_fields())
            except Exception as e:
                import traceback
                print(f"ERROR updating stats for {upload_id} during parse: {e}")
                traceback.print_exc()
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


@login_required
@require_http_methods(["GET", "POST"])
def snippets_view(request):
    """Manage fixlist snippets: create, edit, delete."""
    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'create':
            name = request.POST.get('name', '').strip()
            content = request.POST.get('content', '').strip()
            if not name:
                messages.error(request, 'Snippet name is required.')
            elif not content:
                messages.error(request, 'Snippet content is required.')
            elif FixlistSnippet.objects.filter(owner=request.user, name=name).exists():
                messages.error(request, f'A snippet named "{name}" already exists.')
            else:
                is_shared = request.POST.get('is_shared') == 'on'
                FixlistSnippet.objects.create(owner=request.user, name=name, content=content, is_shared=is_shared)
                messages.success(request, f'Snippet "{name}" created.')
            return redirect('snippets')

        if action == 'edit':
            pk = request.POST.get('pk', '').strip()
            snippet = get_object_or_404(FixlistSnippet, pk=pk, owner=request.user)
            name = request.POST.get('name', '').strip()
            content = request.POST.get('content', '').strip()
            if not name:
                messages.error(request, 'Snippet name is required.')
            elif not content:
                messages.error(request, 'Snippet content is required.')
            else:
                duplicate = FixlistSnippet.objects.filter(owner=request.user, name=name).exclude(pk=snippet.pk).exists()
                if duplicate:
                    messages.error(request, f'A snippet named "{name}" already exists.')
                else:
                    snippet.name = name
                    snippet.content = content
                    snippet.is_shared = request.POST.get('is_shared') == 'on'
                    snippet.save(update_fields=['name', 'content', 'is_shared', 'updated_at'])
                    messages.success(request, f'Snippet "{name}" updated.')
            return redirect('snippets')

        if action == 'delete':
            pk = request.POST.get('pk', '').strip()
            snippet = get_object_or_404(FixlistSnippet, pk=pk, owner=request.user)
            name = snippet.name
            snippet.delete()
            messages.success(request, f'Snippet "{name}" deleted.')
            return redirect('snippets')

    from django.db.models import Q
    filter_mode = request.GET.get('filter', 'own')
    if filter_mode == 'shared':
        snippets = FixlistSnippet.objects.filter(is_shared=True).select_related('owner')
    elif filter_mode == 'all':
        snippets = FixlistSnippet.objects.filter(Q(owner=request.user) | Q(is_shared=True)).select_related('owner')
    else:
        filter_mode = 'own'
        snippets = FixlistSnippet.objects.filter(owner=request.user)
    return render(request, 'snippets.html', {'snippets': snippets, 'filter_mode': filter_mode})


@login_required
@require_http_methods(["GET"])
def snippets_api(request):
    """Return own snippets plus shared snippets from other users."""
    from django.db.models import Q
    qs = FixlistSnippet.objects.filter(
        Q(owner=request.user) | Q(is_shared=True)
    ).select_related('owner').order_by('name')
    snippets = [
        {
            'id': s.id,
            'name': s.name if s.owner_id == request.user.id else f"{s.name} ({s.owner.username})",
            'content': s.content,
        }
        for s in qs
    ]
    return JsonResponse({'snippets': snippets})


@login_required
@require_http_methods(["GET", "POST"])
def rules_view(request):
    """Manage classification rules: create, edit, delete, view others'."""
    from django.db.models import Q

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
        rules = rules.filter(
            Q(source_text__icontains=search_q) | Q(description__icontains=search_q)
        )

    rules = rules[:500]

    context = {
        'rules': rules,
        'filter_mode': filter_mode,
        'filter_status': filter_status,
        'filter_match': filter_match,
        'search_q': search_q,
        'status_choices': ClassificationRule.STATUS_CHOICES,
        'match_type_choices': ClassificationRule.MATCH_TYPE_CHOICES,
        'status_map': STATUS_MAP,
        'match_type_map': MATCH_TYPE_MAP,
    }
    return render(request, 'rules.html', context)
