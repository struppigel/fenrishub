"""Upload merge and soft-delete utilities."""
import logging

from django.db import IntegrityError, transaction
from django.utils import timezone

from .models import UploadedLog

logger = logging.getLogger(__name__)


def soft_delete_uploaded_log(log: UploadedLog) -> None:
    """Move an uploaded log to trash (soft delete)."""
    log.deleted_at = timezone.now()
    log.save(update_fields=['deleted_at'])


def restore_uploaded_log(log: UploadedLog) -> None:
    """Restore a trashed uploaded log."""
    log.deleted_at = None
    log.save(update_fields=['deleted_at'])


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
    reddit_username: str,
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
            reddit_username=reddit_username,
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
