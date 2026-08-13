"""Upload merge and soft-delete utilities."""
import logging
import threading

from django.conf import settings
from django.db import IntegrityError, connections, transaction
from django.utils import timezone

from .models import UploadedLog

logger = logging.getLogger(__name__)


def _recalculate_analysis_stats_in_thread(upload_pk: int) -> None:
    try:
        upload = UploadedLog.objects.get(pk=upload_pk)
        upload.recalculate_analysis_stats()
    except Exception:
        logger.exception('Background analysis_stats recalculation failed (upload_pk=%s)', upload_pk)
    finally:
        connections.close_all()


def schedule_analysis_stats_recalc(upload: UploadedLog) -> None:
    """Recalculate analysis stats off the request thread so the upload response
    can return immediately. Runs synchronously under the test runner so existing
    assertions about post-upload stat values remain valid."""
    if getattr(settings, 'TESTING', False):
        upload.recalculate_analysis_stats()
        return
    thread = threading.Thread(
        target=_recalculate_analysis_stats_in_thread,
        args=(upload.pk,),
        name=f'analysis-stats-{upload.pk}',
        daemon=True,
    )
    thread.start()


def soft_delete_uploaded_log(log: UploadedLog) -> None:
    """Move an uploaded log to trash (soft delete)."""
    log.deleted_at = timezone.now()
    log.save(update_fields=['deleted_at'])


def restore_uploaded_log(log: UploadedLog) -> None:
    """Restore a trashed uploaded log."""
    log.deleted_at = None
    log.save(update_fields=['deleted_at'])


def resolve_ordered_logs_for_merge(selected_ids: list[str], scoped_qs):
    """Validate a merge selection and return logs in the order they were selected.

    Returns (ordered_logs, error_message). ordered_logs is empty when an error
    occurred. Shared by the uploads list and the case detail view so both
    surface identical error messages.
    """
    if len(selected_ids) < 2:
        return [], 'Select at least two uploads to merge.'

    selected_logs = list(
        scoped_qs.filter(upload_id__in=selected_ids, deleted_at__isnull=True)
    )
    logs_by_id = {entry.upload_id: entry for entry in selected_logs}
    missing_ids = [upload_id for upload_id in selected_ids if upload_id not in logs_by_id]
    if missing_ids:
        return [], f'Unable to find upload(s): {", ".join(missing_ids)}.'

    # Merging moves every source log to trash, so protected logs can't take part.
    protected_ids = sorted(log.upload_id for log in selected_logs if log.is_protected)
    if protected_ids:
        return [], (
            f'Deletion-protected, cannot merge: {", ".join(protected_ids)}. '
            'Remove protection first.'
        )

    ordered_logs = [logs_by_id[upload_id] for upload_id in selected_ids]
    return ordered_logs, None


def merge_log_content(logs: list[UploadedLog]) -> str:
    """Merge content from multiple UploadedLog objects."""
    merged_parts = []
    for index, uploaded_log in enumerate(logs):
        piece = uploaded_log.content or ''
        if index > 0 and merged_parts and not merged_parts[-1].endswith('\n'):
            merged_parts[-1] = f"{merged_parts[-1]}\n"
        merged_parts.append(piece)
    return ''.join(merged_parts)


def _unique_trash_upload_id(original_id: str) -> str:
    """
    Build a unique trash upload_id by appending '-trsh', or '-trsh-N' on collision.

    Mirrors the collision-retry pattern in UploadedLog._generate_unique_upload_id:
    prefer the clean form, then fall back to a counter suffix.
    """
    base = f"{original_id}-trsh"
    if not UploadedLog.objects.filter(upload_id=base).exists():
        return base
    for counter in range(2, 1000):
        candidate = f"{base}-{counter}"
        if not UploadedLog.objects.filter(upload_id=candidate).exists():
            return candidate
    raise IntegrityError(
        f'Unable to generate a unique trash upload_id for {original_id}.'
    )


def execute_merge(
    ordered_logs: list[UploadedLog],
    forum_username: str,
    recipient_user,
    created_by=None,
) -> UploadedLog:
    """
    Execute merge of multiple uploads.

    - Retains the upload_id of the first log
    - Moves other logs to trash (rename with -trsh suffix, with counter on collision)
    - Creates merged record with combined content
    - Recalculates analysis stats for merged record (best-effort)

    Returns the merged UploadedLog instance.
    """
    if not ordered_logs:
        raise ValueError("Cannot merge empty list of logs")

    retained_id = ordered_logs[0].upload_id
    merged_content = merge_log_content(ordered_logs)
    now = timezone.now()

    with transaction.atomic():
        for log in ordered_logs:
            log.upload_id = _unique_trash_upload_id(log.upload_id)
            log.deleted_at = now
            log.save(update_fields=['upload_id', 'deleted_at'])

        merged_log = UploadedLog.objects.create(
            upload_id=retained_id,
            forum_username=forum_username,
            original_filename='merged-logs.txt',
            content=merged_content,
            created_by=created_by,
            recipient_user=recipient_user,
        )

    # Best-effort stat recalculation; failures here must not invalidate the merge,
    # so this runs outside the atomic block.
    try:
        merged_log.recalculate_log_type()
        merged_log.recalculate_scan_date()
        merged_log.recalculate_analysis_stats()
    except Exception:
        logger.exception("Failed to recalculate stats for merged upload %s", retained_id)

    return merged_log
