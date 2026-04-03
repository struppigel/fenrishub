"""Upload merge and soft-delete utilities."""
from django.utils import timezone
from .models import UploadedLog


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


def execute_merge(
    ordered_logs: list[UploadedLog],
    reddit_username: str,
    recipient_user,
    created_by=None,
) -> UploadedLog:
    """
    Execute merge of multiple uploads.
    
    - Retains the upload_id of the first log
    - Moves other logs to trash (rename with -trsh suffix)
    - Creates merged record with combined content
    - Recalculates analysis stats for merged record
    
    Returns the merged UploadedLog instance.
    """
    if not ordered_logs:
        raise ValueError("Cannot merge empty list of logs")
    
    retained_id = ordered_logs[0].upload_id
    merged_content = merge_log_content(ordered_logs)
    now = timezone.now()
    
    # Trash all original uploads
    for log in ordered_logs:
        log.upload_id = f"{log.upload_id}-trsh"
        log.deleted_at = now
        log.save(update_fields=['upload_id', 'deleted_at'])
    
    # Purge uploads older than 30 days marked for deletion
    from datetime import timedelta
    cutoff = timezone.now() - timedelta(days=30)
    UploadedLog.objects.filter(deleted_at__isnull=False, deleted_at__lt=cutoff).delete()
    
    # Create merged record
    merged_log = UploadedLog.objects.create(
        upload_id=retained_id,
        reddit_username=reddit_username,
        original_filename='merged-logs.txt',
        content=merged_content,
        created_by=created_by,
        recipient_user=recipient_user,
    )
    
    # Recalculate analysis stats
    try:
        merged_log.recalculate_log_type()
        merged_log.recalculate_analysis_stats()
    except Exception as e:
        import traceback
        print(f"ERROR recalculating stats for merged upload {retained_id}: {e}")
        traceback.print_exc()
    
    return merged_log
