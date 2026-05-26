"""Upload list action handlers for merged/deleted/assigned operations."""
from django.http import HttpResponse
from django.shortcuts import redirect, get_object_or_404, render
from django.contrib import messages
from django.urls import reverse
from django.utils import timezone

from ..models import UploadedLog
from ..permissions import user_can_delete_uploaded_log
from ..upload_utils import (
    soft_delete_uploaded_log, restore_uploaded_log, execute_merge,
    schedule_analysis_stats_recalc,
)
from .utils import redirect_preserving_filters, _purge_old_trash, check_missing_ids


def _check_unauthorized_uploads(request, logs, *, verb, target):
    """Return error redirect if user can't act on some logs; else None."""
    unauthorized = sorted(
        log.upload_id for log in logs if not user_can_delete_uploaded_log(request.user, log)
    )
    if not unauthorized:
        return None
    messages.error(
        request,
        f'Only the assigned helper can {verb}: {", ".join(unauthorized)}.',
    )
    return redirect_preserving_filters(request, target)


def handle_delete_action(request, upload_id: str, action_scope_uploads) -> HttpResponse:
    """Handle single upload deletion (move to trash)."""
    uploaded_log = get_object_or_404(UploadedLog, upload_id=upload_id, deleted_at__isnull=True)
    if not user_can_delete_uploaded_log(request.user, uploaded_log):
        messages.error(request, f'Only the assigned helper can delete {upload_id}.')
        return redirect_preserving_filters(request, 'uploaded_logs')
    soft_delete_uploaded_log(uploaded_log)
    _purge_old_trash()
    messages.success(request, f'Upload {upload_id} moved to trash.')
    return redirect_preserving_filters(request, 'uploaded_logs')


def handle_assign_to_me_action(request, upload_id: str, action_scope_uploads) -> HttpResponse:
    """Handle assign upload to current user."""
    uploaded_log = get_object_or_404(action_scope_uploads, upload_id=upload_id, deleted_at__isnull=True)
    if uploaded_log.recipient_user_id is not None:
        messages.error(request, f'Upload {upload_id} is already assigned.')
        return redirect_preserving_filters(request, 'uploaded_logs')

    uploaded_log.recipient_user = request.user
    uploaded_log.save(update_fields=['recipient_user', 'updated_at'])
    # Recipient changed — effective ruleset may have changed too. Refresh
    # count_* + caches so the uploads listing reflects the assignee's view.
    schedule_analysis_stats_recalc(uploaded_log)
    messages.success(request, f'Upload {upload_id} assigned to {request.user.username}.')
    return redirect_preserving_filters(request, 'uploaded_logs')


def handle_unassign_to_general_action(request, upload_id: str, action_scope_uploads) -> HttpResponse:
    """Handle unassign upload to general channel."""
    uploaded_log = get_object_or_404(action_scope_uploads, upload_id=upload_id, deleted_at__isnull=True)
    if uploaded_log.recipient_user_id is None:
        messages.error(request, f'Upload {upload_id} is already unassigned.')
        return redirect_preserving_filters(request, 'uploaded_logs')
    if uploaded_log.recipient_user_id != request.user.id:
        messages.error(request, f'Only the assigned helper can unassign {upload_id}.')
        return redirect_preserving_filters(request, 'uploaded_logs')

    uploaded_log.recipient_user = None
    uploaded_log.save(update_fields=['recipient_user', 'updated_at'])
    schedule_analysis_stats_recalc(uploaded_log)
    messages.success(request, f'{upload_id} was unassigned')
    return redirect_preserving_filters(request, 'uploaded_logs')


def handle_delete_selected_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Handle delete multiple selected uploads."""
    if not selected_ids:
        messages.error(request, 'Select at least one upload to delete.')
        return redirect_preserving_filters(request, 'uploaded_logs')

    selected_logs = list(
        UploadedLog.objects.filter(upload_id__in=selected_ids, deleted_at__isnull=True).defer('content')
    )
    found_ids = {entry.upload_id for entry in selected_logs}
    if resp := check_missing_ids(request, selected_ids, found_ids,
                                 item_label='upload', target='uploaded_logs'):
        return resp
    if resp := _check_unauthorized_uploads(request, selected_logs,
                                           verb='delete', target='uploaded_logs'):
        return resp

    UploadedLog.objects.filter(
        upload_id__in=[log.upload_id for log in selected_logs]
    ).update(deleted_at=timezone.now())
    _purge_old_trash()
    messages.success(request, f'Moved {len(selected_logs)} selected upload(s) to trash.')
    return redirect_preserving_filters(request, 'uploaded_logs')


def handle_restore_selected_action(request, selected_ids: list) -> HttpResponse:
    """Handle restore multiple selected trashed uploads."""
    if not selected_ids:
        messages.error(request, 'Select at least one upload to restore.')
        return redirect_preserving_filters(request, 'uploads_trash')

    selected_logs = list(
        UploadedLog.objects.filter(upload_id__in=selected_ids, deleted_at__isnull=False).defer('content')
    )
    found_ids = {entry.upload_id for entry in selected_logs}
    if resp := check_missing_ids(request, selected_ids, found_ids,
                                 item_label='upload', target='uploads_trash', in_trash=True):
        return resp
    if resp := _check_unauthorized_uploads(request, selected_logs,
                                           verb='restore', target='uploads_trash'):
        return resp

    for log in selected_logs:
        restore_uploaded_log(log)

    messages.success(request, f'Restored {len(selected_logs)} upload(s).')
    return redirect_preserving_filters(request, 'uploads_trash')


def handle_delete_permanent_selected_action(request, selected_ids: list) -> HttpResponse:
    """Handle permanently delete multiple selected trashed uploads."""
    if not selected_ids:
        messages.error(request, 'Select at least one upload to delete.')
        return redirect_preserving_filters(request, 'uploads_trash')

    selected_logs = list(
        UploadedLog.objects.filter(upload_id__in=selected_ids, deleted_at__isnull=False).defer('content')
    )
    found_ids = {entry.upload_id for entry in selected_logs}
    if resp := check_missing_ids(request, selected_ids, found_ids,
                                 item_label='upload', target='uploads_trash', in_trash=True):
        return resp
    if resp := _check_unauthorized_uploads(request, selected_logs,
                                           verb='permanently delete', target='uploads_trash'):
        return resp

    count = len(selected_logs)
    UploadedLog.objects.filter(upload_id__in=[log.upload_id for log in selected_logs]).delete()
    messages.success(request, f'Permanently deleted {count} upload(s).')
    return redirect_preserving_filters(request, 'uploads_trash')


def _redirect_after_merge(request, merged_upload: UploadedLog, to_analyzer: bool) -> HttpResponse:
    if to_analyzer:
        return redirect(f"{reverse('log_analyzer')}?upload_id={merged_upload.upload_id}")
    return redirect_preserving_filters(request, 'uploaded_logs')


def _start_merge(request, selected_ids: list, action_scope_uploads, to_analyzer: bool) -> HttpResponse:
    if len(selected_ids) < 2:
        messages.error(request, 'Select at least two uploads to merge.')
        return redirect_preserving_filters(request, 'uploaded_logs')

    selected_logs = list(action_scope_uploads.filter(upload_id__in=selected_ids, deleted_at__isnull=True))
    logs_by_id = {entry.upload_id: entry for entry in selected_logs}
    missing_ids = [upload_id for upload_id in selected_ids if upload_id not in logs_by_id]
    if missing_ids:
        messages.error(request, f'Unable to find upload(s): {", ".join(missing_ids)}.')
        return redirect_preserving_filters(request, 'uploaded_logs')

    ordered_logs = [logs_by_id[upload_id] for upload_id in selected_ids]
    usernames = list(set(log.forum_username for log in ordered_logs))

    if len(usernames) > 1:
        confirm_action = 'confirm_mergealyze' if to_analyzer else 'confirm_merge'
        context = {
            'selected_logs': ordered_logs,
            'selected_upload_ids': selected_ids,
            'usernames': sorted(usernames),
            'confirm_action': confirm_action,
            'show_all': (request.POST.get('show_all') or '').strip().lower() in {'1', 'true', 'on', 'yes'},
            'username_filter': (request.POST.get('u') or '').strip(),
            'search_query': (request.POST.get('q') or '').strip(),
        }
        return render(request, 'merge_username_selection.html', context)

    merged_upload = execute_merge(
        ordered_logs=ordered_logs,
        forum_username=usernames[0],
        recipient_user=request.user,
        created_by=request.user,
    )
    _purge_old_trash()
    messages.success(request, f'Merged upload created with id {merged_upload.upload_id}.')
    return _redirect_after_merge(request, merged_upload, to_analyzer)


def _confirm_merge(request, selected_ids: list, action_scope_uploads, to_analyzer: bool) -> HttpResponse:
    selected_username = request.POST.get('selected_username', '').strip()

    if len(selected_ids) < 2:
        messages.error(request, 'Select at least two uploads to merge.')
        return redirect_preserving_filters(request, 'uploaded_logs')

    if not selected_username:
        messages.error(request, 'Please select a username.')
        return redirect_preserving_filters(request, 'uploaded_logs')

    selected_logs = list(action_scope_uploads.filter(upload_id__in=selected_ids, deleted_at__isnull=True))
    logs_by_id = {entry.upload_id: entry for entry in selected_logs}
    missing_ids = [upload_id for upload_id in selected_ids if upload_id not in logs_by_id]
    if missing_ids:
        messages.error(request, f'Unable to find upload(s): {", ".join(missing_ids)}.')
        return redirect_preserving_filters(request, 'uploaded_logs')

    ordered_logs = [logs_by_id[upload_id] for upload_id in selected_ids]

    available_usernames = set(log.forum_username for log in ordered_logs)
    if selected_username not in available_usernames:
        messages.error(request, 'Invalid username selection.')
        return redirect_preserving_filters(request, 'uploaded_logs')

    merged_upload = execute_merge(
        ordered_logs=ordered_logs,
        forum_username=selected_username,
        recipient_user=request.user,
        created_by=request.user,
    )
    _purge_old_trash()
    messages.success(request, f'Merged upload created with id {merged_upload.upload_id}.')
    return _redirect_after_merge(request, merged_upload, to_analyzer)


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
        return redirect_preserving_filters(request, 'uploaded_logs')
    if uploaded_log.recipient_user_id == request.user.id:
        messages.error(request, f'Upload {upload_id} is already assigned to you.')
        return redirect_preserving_filters(request, 'uploaded_logs')

    copy = UploadedLog(
        forum_username=uploaded_log.forum_username,
        original_filename=uploaded_log.original_filename,
        content=uploaded_log.content,
        detected_encoding=uploaded_log.detected_encoding,
        created_by=uploaded_log.created_by,
        recipient_user=request.user,
        log_type=uploaded_log.log_type,
        is_incomplete=uploaded_log.is_incomplete,
        scan_date=uploaded_log.scan_date,
    )
    copy.save()
    # The new assignee may have a different effective rule set than the source's
    # assignee. Run analysis for the copy so count_*, cached payloads, and the
    # stats snapshot all reflect the new recipient's view.
    schedule_analysis_stats_recalc(copy)
    messages.success(request, f'Copied {upload_id} as {copy.upload_id} assigned to {request.user.username}.')
    return redirect_preserving_filters(request, 'uploaded_logs')


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
