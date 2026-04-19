"""Upload list action handlers for merged/deleted/assigned operations."""
from django.http import HttpResponse
from django.shortcuts import redirect, get_object_or_404, render
from django.contrib import messages
from django.urls import reverse
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

    selected_logs = list(UploadedLog.objects.filter(upload_id__in=selected_ids, deleted_at__isnull=True).defer('content'))
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
    UploadedLog.objects.filter(upload_id__in=[log.upload_id for log in selected_logs]).update(deleted_at=now)

    _purge_old_trash()
    messages.success(request, f'Moved {len(selected_logs)} selected upload(s) to trash.')
    return _uploads_redirect_with_state(request)


def _redirect_after_merge(merged_upload: UploadedLog, to_analyzer: bool) -> HttpResponse:
    if to_analyzer:
        return redirect(f"{reverse('log_analyzer')}?upload_id={merged_upload.upload_id}")
    return redirect('uploaded_logs')


def _start_merge(request, selected_ids: list, action_scope_uploads, to_analyzer: bool) -> HttpResponse:
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
    usernames = list(set(log.reddit_username for log in ordered_logs))

    if len(usernames) > 1:
        confirm_action = 'confirm_mergealyze' if to_analyzer else 'confirm_merge'
        context = {
            'selected_logs': ordered_logs,
            'selected_upload_ids': selected_ids,
            'usernames': sorted(usernames),
            'confirm_action': confirm_action,
        }
        return render(request, 'merge_username_selection.html', context)

    merged_upload = execute_merge(
        ordered_logs=ordered_logs,
        reddit_username=usernames[0],
        recipient_user=request.user,
        created_by=request.user,
    )
    _purge_old_trash()
    messages.success(request, f'Merged upload created with id {merged_upload.upload_id}.')
    return _redirect_after_merge(merged_upload, to_analyzer)


def _confirm_merge(request, selected_ids: list, action_scope_uploads, to_analyzer: bool) -> HttpResponse:
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
    return _redirect_after_merge(merged_upload, to_analyzer)


def handle_merge_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Handle merge selected uploads (single-username case)."""
    return _start_merge(request, selected_ids, action_scope_uploads, to_analyzer=False)


def handle_confirm_merge_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Handle merge with user-selected username (multi-username case)."""
    return _confirm_merge(request, selected_ids, action_scope_uploads, to_analyzer=False)


def handle_mergealyze_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Merge selected uploads and open the result in the log analyzer."""
    return _start_merge(request, selected_ids, action_scope_uploads, to_analyzer=True)


def handle_confirm_mergealyze_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Mergealyze with user-selected username (multi-username case)."""
    return _confirm_merge(request, selected_ids, action_scope_uploads, to_analyzer=True)


def handle_copy_to_me_action(request, upload_id: str, action_scope_uploads) -> HttpResponse:
    """Handle copying an upload assigned to another user to the current user."""
    uploaded_log = get_object_or_404(UploadedLog, upload_id=upload_id, deleted_at__isnull=True)
    if uploaded_log.recipient_user_id is None:
        messages.error(request, f'Upload {upload_id} is not assigned — use assign instead.')
        return _uploads_redirect_with_state(request)
    if uploaded_log.recipient_user_id == request.user.id:
        messages.error(request, f'Upload {upload_id} is already assigned to you.')
        return _uploads_redirect_with_state(request)

    copy = UploadedLog(
        reddit_username=uploaded_log.reddit_username,
        original_filename=uploaded_log.original_filename,
        content=uploaded_log.content,
        detected_encoding=uploaded_log.detected_encoding,
        created_by=uploaded_log.created_by,
        recipient_user=request.user,
    )
    copy.save()
    messages.success(request, f'Copied {upload_id} as {copy.upload_id} assigned to {request.user.username}.')
    return _uploads_redirect_with_state(request)


def handle_rescan_stats_selected_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Handle rescan analysis stats for selected uploads."""
    if not selected_ids:
        messages.error(request, 'Select at least one upload to rescan.')
        return redirect('uploaded_logs')

    rescanned_count = 0
    failed_upload_ids = []

    for uploaded_log in action_scope_uploads.filter(deleted_at__isnull=True, upload_id__in=selected_ids).iterator():
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
