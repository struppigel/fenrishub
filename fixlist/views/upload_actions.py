"""Upload list action handlers for merged/deleted/assigned operations."""
from django.http import HttpResponse
from django.shortcuts import redirect, get_object_or_404, render
from django.contrib import messages
from django.utils import timezone

from ..models import UploadedLog
from ..permissions import user_can_delete_uploaded_log
from ..upload_utils import soft_delete_uploaded_log, execute_merge
from .utils import _uploads_redirect_with_state, _purge_old_trash


def handle_delete_action(request, upload_id: str, action_scope_uploads) -> HttpResponse:
    """Handle single upload deletion (move to trash)."""
    uploaded_log = get_object_or_404(UploadedLog, upload_id=upload_id, deleted_at__isnull=True)
    if not user_can_delete_uploaded_log(request.user, uploaded_log):
        messages.error(request, f'Only the assigned helper can delete {upload_id}.')
        return _uploads_redirect_with_state(request)
    soft_delete_uploaded_log(uploaded_log)
    _purge_old_trash()
    messages.success(request, f'Upload {upload_id} moved to trash.')
    return _uploads_redirect_with_state(request)


def handle_assign_to_me_action(request, upload_id: str, action_scope_uploads) -> HttpResponse:
    """Handle assign upload to current user."""
    uploaded_log = get_object_or_404(action_scope_uploads, upload_id=upload_id, deleted_at__isnull=True)
    if uploaded_log.recipient_user_id is not None:
        messages.error(request, f'Upload {upload_id} is already assigned.')
        return _uploads_redirect_with_state(request)

    uploaded_log.recipient_user = request.user
    uploaded_log.save(update_fields=['recipient_user', 'updated_at'])
    messages.success(request, f'Upload {upload_id} assigned to {request.user.username}.')
    return _uploads_redirect_with_state(request)


def handle_unassign_to_general_action(request, upload_id: str, action_scope_uploads) -> HttpResponse:
    """Handle unassign upload to general channel."""
    uploaded_log = get_object_or_404(action_scope_uploads, upload_id=upload_id, deleted_at__isnull=True)
    if uploaded_log.recipient_user_id is None:
        messages.error(request, f'Upload {upload_id} is already unassigned.')
        return _uploads_redirect_with_state(request)
    if uploaded_log.recipient_user_id != request.user.id:
        messages.error(request, f'Only the assigned helper can unassign {upload_id}.')
        return _uploads_redirect_with_state(request)

    uploaded_log.recipient_user = None
    uploaded_log.save(update_fields=['recipient_user', 'updated_at'])
    messages.success(request, f'{upload_id} was unassigned')
    return _uploads_redirect_with_state(request)


def handle_delete_selected_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Handle delete multiple selected uploads."""
    if not selected_ids:
        messages.error(request, 'Select at least one upload to delete.')
        return redirect('uploaded_logs')

    selected_logs = list(UploadedLog.objects.filter(upload_id__in=selected_ids, deleted_at__isnull=True))
    found_ids = {entry.upload_id for entry in selected_logs}
    missing_ids = [upload_id for upload_id in selected_ids if upload_id not in found_ids]
    if missing_ids:
        messages.error(request, f'Unable to find upload(s): {", ".join(missing_ids)}.')
        return _uploads_redirect_with_state(request)

    undeletable_ids = [
        log.upload_id for log in selected_logs
        if not user_can_delete_uploaded_log(request.user, log)
    ]
    if undeletable_ids:
        messages.error(
            request,
            f'Only the assigned helper can delete: {", ".join(sorted(undeletable_ids))}.',
        )
        return _uploads_redirect_with_state(request)

    now = timezone.now()
    for log in selected_logs:
        log.deleted_at = now
        log.save(update_fields=['deleted_at'])

    _purge_old_trash()
    messages.success(request, f'Moved {len(selected_logs)} selected upload(s) to trash.')
    return _uploads_redirect_with_state(request)


def handle_merge_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Handle merge selected uploads (single-username case)."""
    if len(selected_ids) < 2:
        messages.error(request, 'Select at least two uploads to merge.')
        return redirect('uploaded_logs')

    selected_logs = list(action_scope_uploads.filter(upload_id__in=selected_ids, deleted_at__isnull=True))
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
    merged_upload = execute_merge(
        ordered_logs=ordered_logs,
        reddit_username=selected_username,
        recipient_user=request.user,
        created_by=request.user,
    )
    _purge_old_trash()
    messages.success(request, f'Merged upload created with id {merged_upload.upload_id}.')
    return redirect('view_uploaded_log', upload_id=merged_upload.upload_id)


def handle_confirm_merge_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Handle merge with user-selected username (multi-username case)."""
    selected_username = request.POST.get('selected_username', '').strip()
    
    if len(selected_ids) < 2:
        messages.error(request, 'Select at least two uploads to merge.')
        return redirect('uploaded_logs')
    
    if not selected_username:
        messages.error(request, 'Please select a username.')
        return redirect('uploaded_logs')
    
    selected_logs = list(action_scope_uploads.filter(upload_id__in=selected_ids, deleted_at__isnull=True))
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
    
    merged_upload = execute_merge(
        ordered_logs=ordered_logs,
        reddit_username=selected_username,
        recipient_user=request.user,
        created_by=request.user,
    )
    _purge_old_trash()
    messages.success(request, f'Merged upload created with id {merged_upload.upload_id}.')
    return redirect('view_uploaded_log', upload_id=merged_upload.upload_id)


def handle_rescan_stats_all_action(request, action_scope_uploads) -> HttpResponse:
    """Handle rescan analysis stats for all uploads."""
    rescanned_count = 0
    failed_upload_ids = []

    for uploaded_log in action_scope_uploads.filter(deleted_at__isnull=True).iterator():
        try:
            uploaded_log.recalculate_analysis_stats()
            uploaded_log.recalculate_log_type()
            uploaded_log.recalculate_scan_date()
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
