"""Upload list action handlers for merged/deleted/assigned operations."""
from django.http import HttpResponse
from django.shortcuts import redirect, get_object_or_404, render
from django.contrib import messages
from django.urls import reverse

from .. import trash
from ..models import UploadedLog
from ..permissions import user_can_delete_uploaded_log
from ..upload_utils import (
    soft_delete_uploaded_log, restore_uploaded_log, execute_merge,
    resolve_ordered_logs_for_merge, schedule_analysis_stats_recalc,
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


def _check_protected_uploads(request, logs, *, verb, target):
    """Return error redirect if any log is deletion-protected; else None."""
    if trash.protected_names_error(request, [log.upload_id for log in logs if log.is_protected], verb=verb):
        return redirect_preserving_filters(request, target)
    return None


# Single-upload services shared by the uploads list and the upload detail page.
# Each returns (ok, message); the caller picks the message level and redirect.

def trash_upload(user, uploaded_log) -> tuple[bool, str]:
    """Move one upload to the trash."""
    upload_id = uploaded_log.upload_id
    if uploaded_log.deleted_at is not None:
        return False, f'Upload {upload_id} is already in trash.'
    if not user_can_delete_uploaded_log(user, uploaded_log):
        return False, f'Only the assigned helper can delete {upload_id}.'
    if uploaded_log.is_protected:
        return False, f'Upload {upload_id} is deletion-protected. Remove protection first.'
    soft_delete_uploaded_log(uploaded_log)
    _purge_old_trash()
    return True, f'Upload {upload_id} moved to trash.'


def restore_upload(user, uploaded_log) -> tuple[bool, str]:
    """Bring one upload back from the trash."""
    upload_id = uploaded_log.upload_id
    if uploaded_log.deleted_at is None:
        return False, f'Upload {upload_id} is not in trash.'
    if not user_can_delete_uploaded_log(user, uploaded_log):
        return False, f'Only the assigned helper can restore {upload_id}.'
    restore_uploaded_log(uploaded_log)
    return True, f'Upload {upload_id} restored.'


def assign_upload(user, uploaded_log) -> tuple[bool, str]:
    """Assign an unassigned upload to ``user``."""
    upload_id = uploaded_log.upload_id
    if uploaded_log.recipient_user_id is not None:
        return False, f'Upload {upload_id} is already assigned.'
    uploaded_log.recipient_user = user
    uploaded_log.save(update_fields=['recipient_user', 'updated_at'])
    # Recipient changed — effective ruleset may have changed too. Refresh
    # count_* + caches so listings reflect the assignee's view.
    schedule_analysis_stats_recalc(uploaded_log)
    return True, f'Upload {upload_id} assigned to {user.username}.'


def unassign_upload(user, uploaded_log) -> tuple[bool, str]:
    """Move an upload assigned to ``user`` back to the general channel."""
    upload_id = uploaded_log.upload_id
    if uploaded_log.recipient_user_id is None:
        return False, f'Upload {upload_id} is already unassigned.'
    if not user_can_delete_uploaded_log(user, uploaded_log):
        return False, f'Only the assigned helper can unassign {upload_id}.'
    uploaded_log.recipient_user = None
    uploaded_log.save(update_fields=['recipient_user', 'updated_at'])
    schedule_analysis_stats_recalc(uploaded_log)
    return True, f'{upload_id} was unassigned'


def _flash(request, ok: bool, message: str) -> None:
    (messages.success if ok else messages.error)(request, message)


def handle_delete_action(request, upload_id: str, action_scope_uploads) -> HttpResponse:
    """Handle single upload deletion (move to trash)."""
    uploaded_log = get_object_or_404(UploadedLog, upload_id=upload_id, deleted_at__isnull=True)
    _flash(request, *trash_upload(request.user, uploaded_log))
    return redirect_preserving_filters(request, 'uploaded_logs')


def handle_assign_to_me_action(request, upload_id: str, action_scope_uploads) -> HttpResponse:
    """Handle assign upload to current user."""
    uploaded_log = get_object_or_404(action_scope_uploads, upload_id=upload_id, deleted_at__isnull=True)
    _flash(request, *assign_upload(request.user, uploaded_log))
    return redirect_preserving_filters(request, 'uploaded_logs')


def handle_unassign_to_general_action(request, upload_id: str, action_scope_uploads) -> HttpResponse:
    """Handle unassign upload to general channel."""
    uploaded_log = get_object_or_404(action_scope_uploads, upload_id=upload_id, deleted_at__isnull=True)
    _flash(request, *unassign_upload(request.user, uploaded_log))
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
    if resp := _check_protected_uploads(request, selected_logs,
                                        verb='delete', target='uploaded_logs'):
        return resp

    UploadedLog.objects.filter(upload_id__in=[log.upload_id for log in selected_logs]).move_to_trash()
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
    if resp := _check_protected_uploads(request, selected_logs,
                                        verb='permanently delete', target='uploads_trash'):
        return resp

    count = len(selected_logs)
    UploadedLog.objects.filter(upload_id__in=[log.upload_id for log in selected_logs]).delete()
    messages.success(request, f'Permanently deleted {count} upload(s).')
    return redirect_preserving_filters(request, 'uploads_trash')


def run_merge_flow(request, selected_ids: list, scope_qs, *, confirming: bool, confirm_action: str,
                   submit_url: str, merge, on_error, on_done, extra_context=None) -> HttpResponse:
    """Merge the selected logs, asking which forum username to keep when they differ.

    The first step (``confirming`` False) merges right away when every log has
    the same username, else renders the username picker posting
    ``confirm_action`` to ``submit_url``. The confirm step validates the picked
    name. ``merge(ordered_logs, username)`` does the merge and returns the new
    upload, ``on_done(merged)`` and ``on_error()`` build the response.
    """
    selected_username = (request.POST.get('selected_username') or '').strip()
    if confirming and not selected_username:
        messages.error(request, 'Please select a username.')
        return on_error()

    ordered_logs, error_message = resolve_ordered_logs_for_merge(selected_ids, scope_qs)
    if error_message:
        messages.error(request, error_message)
        return on_error()

    usernames = sorted({log.forum_username for log in ordered_logs})
    if confirming:
        if selected_username not in usernames:
            messages.error(request, 'Invalid username selection.')
            return on_error()
        username = selected_username
    elif len(usernames) > 1:
        return render(request, 'merge_username_selection.html', {
            'selected_logs': ordered_logs,
            'selected_upload_ids': selected_ids,
            'usernames': usernames,
            'confirm_action': confirm_action,
            'submit_url': submit_url,
            'cancel_url': submit_url,
            **(extra_context or {}),
        })
    else:
        username = usernames[0]
    return on_done(merge(ordered_logs, username))


def _merge_uploads(request, selected_ids: list, action_scope_uploads, *, to_analyzer: bool,
                   confirming: bool) -> HttpResponse:
    def merge(ordered_logs, username):
        merged_upload = execute_merge(
            ordered_logs=ordered_logs,
            forum_username=username,
            recipient_user=request.user,
            created_by=request.user,
        )
        _purge_old_trash()
        return merged_upload

    def on_done(merged_upload):
        messages.success(request, f'Merged upload created with id {merged_upload.upload_id}.')
        if to_analyzer:
            return redirect(f"{reverse('log_analyzer')}?upload_id={merged_upload.upload_id}")
        return redirect_preserving_filters(request, 'uploaded_logs')

    return run_merge_flow(
        request, selected_ids, action_scope_uploads,
        confirming=confirming,
        confirm_action='confirm_mergealyze' if to_analyzer else 'confirm_merge',
        submit_url=reverse('uploaded_logs'),
        merge=merge,
        on_error=lambda: redirect_preserving_filters(request, 'uploaded_logs'),
        on_done=on_done,
        extra_context={
            'channel': (request.POST.get('channel') or '').strip(),
            'username_filter': (request.POST.get('u') or '').strip(),
            'search_query': (request.POST.get('q') or '').strip(),
            'page': (request.POST.get('page') or '').strip(),
        },
    )


def handle_merge_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Handle merge selected uploads (single-username case)."""
    return _merge_uploads(request, selected_ids, action_scope_uploads, to_analyzer=False, confirming=False)


def handle_confirm_merge_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Handle merge with user-selected username (multi-username case)."""
    return _merge_uploads(request, selected_ids, action_scope_uploads, to_analyzer=False, confirming=True)


def handle_mergealyze_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Merge selected uploads and open the result in the log analyzer."""
    return _merge_uploads(request, selected_ids, action_scope_uploads, to_analyzer=True, confirming=False)


def handle_confirm_mergealyze_action(request, selected_ids: list, action_scope_uploads) -> HttpResponse:
    """Mergealyze with user-selected username (multi-username case)."""
    return _merge_uploads(request, selected_ids, action_scope_uploads, to_analyzer=True, confirming=True)


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
        return redirect_preserving_filters(request, 'uploaded_logs')

    rescanned_count = 0
    failed_upload_ids = []

    # Rescan only recomputes derived stats/log-type — it never changes ownership
    # or classifications — so it's safe to run on any visible log, including those
    # assigned to other helpers (which fall outside the caller's action scope).
    for uploaded_log in UploadedLog.objects.live().filter(upload_id__in=selected_ids).iterator():
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

    return redirect_preserving_filters(request, 'uploaded_logs')
