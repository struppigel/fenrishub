"""Upload merge and soft-delete utilities."""
import logging
import threading

from django.conf import settings
from django.db import IntegrityError, connections, transaction
from django.utils import timezone

from .analyzer import ANALYSIS_PAYLOAD_FORMAT, analyze_log_text
from .models import UploadedLog, UploadedLogAnalysis

logger = logging.getLogger(__name__)


def get_fresh_cached_analysis(uploaded_log: UploadedLog, rule_set_key: str):
    """Return the cached analyzer payload for (upload, rule set), or None if unusable.

    A cache row is unusable when the upload's content changed since it was
    written, or when an older analyzer wrote it in a shape no longer produced.
    """
    cached = UploadedLogAnalysis.objects.filter(
        upload=uploaded_log, rule_set_key=rule_set_key,
    ).first()
    if (
        cached is None
        or cached.source_content_hash != uploaded_log.content_hash
        or not isinstance(cached.payload, dict)
        or cached.payload.get('format') != ANALYSIS_PAYLOAD_FORMAT
    ):
        return None
    return cached.payload


def store_cached_analysis(uploaded_log: UploadedLog, rule_set_key: str, analysis: dict) -> None:
    """Write `analysis` as the cached payload for (upload, rule set), with its line tag matches."""
    from .tagging import compute_line_tags

    UploadedLogAnalysis.objects.update_or_create(
        upload=uploaded_log,
        rule_set_key=rule_set_key,
        defaults={
            'payload': analysis,
            'source_content_hash': uploaded_log.content_hash,
            'line_tags': compute_line_tags(analysis),
        },
    )


def get_or_compute_upload_analysis(uploaded_log: UploadedLog, rule_set_key: str):
    """Return ``(payload, computed)`` for (upload, rule set).

    Serves the cached payload when it is fresh; otherwise runs the analyzer and
    caches the result. Never touches the count_* stats on the upload, which
    reflect the assigned recipient's view only.
    """
    payload = get_fresh_cached_analysis(uploaded_log, rule_set_key)
    if payload is not None:
        return payload, False
    payload = analyze_log_text(uploaded_log.content, rule_set_key)
    try:
        store_cached_analysis(uploaded_log, rule_set_key, payload)
    except Exception:
        logger.exception('Failed to cache analysis for upload_id=%s', uploaded_log.upload_id)
    return payload, True


def _refresh_cached_analysis_in_thread(upload_pk: int, rule_set_key: str) -> None:
    try:
        upload = UploadedLog.objects.get(pk=upload_pk)
        get_or_compute_upload_analysis(upload, rule_set_key)
    except Exception:
        logger.exception('Background analysis cache refresh failed (upload_pk=%s)', upload_pk)
    finally:
        connections.close_all()


def schedule_cached_analysis_refresh(upload: UploadedLog, rule_set_key: str) -> bool:
    """Re-run the analyzer for (upload, rule set) off the request thread and
    cache the result, e.g. when the cached payload predates the current
    analyzer format. Only the cache row is written, never the count_* stats.
    A short cache lock keeps repeated page loads from starting duplicate runs.
    Returns True when a refresh was started."""
    from django.core.cache import cache

    if not cache.add(f'analysis-refresh:{upload.pk}:{rule_set_key}', 1, timeout=300):
        return False
    if getattr(settings, 'TESTING', False):
        get_or_compute_upload_analysis(upload, rule_set_key)
        return True
    thread = threading.Thread(
        target=_refresh_cached_analysis_in_thread,
        args=(upload.pk, rule_set_key),
        name=f'analysis-refresh-{upload.pk}',
        daemon=True,
    )
    thread.start()
    return True


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


def start_reanalysis_process(log_type: str, only_untagged: bool) -> int:
    """Start `manage.py reanalyze_logs` as a separate low-priority process; returns its pid.

    A process of its own, not a thread, so it gets a lower OS priority than
    the web workers and outlives a worker restart. Its output goes to the
    server's own stdout/stderr (the deploy log).
    """
    import subprocess
    import sys

    args = [
        sys.executable, str(settings.BASE_DIR / 'manage.py'), 'reanalyze_logs',
        '--log-type', log_type,
    ]
    if only_untagged:
        args.append('--only-untagged')
    if sys.platform == 'win32':
        platform_kwargs = {
            'creationflags': subprocess.BELOW_NORMAL_PRIORITY_CLASS | subprocess.CREATE_NEW_PROCESS_GROUP,
        }
    else:
        # The command lowers its own priority with os.nice.
        platform_kwargs = {'start_new_session': True}
    process = subprocess.Popen(
        args, stdin=subprocess.DEVNULL, close_fds=True, cwd=str(settings.BASE_DIR), **platform_kwargs,
    )
    return process.pid


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
    - Schedules analysis stats for merged record (best-effort, off-thread)

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
    #
    # A merged log is the largest content in the system (every source log
    # concatenated), and analysis is linear in line count -- running it inline
    # blew Gunicorn's worker timeout and killed the request with a 500 *after*
    # the merge had already committed. Log type and scan date are cheap and are
    # persisted here because the recalc thread re-reads the row by pk and needs
    # log_type to decide whether to analyse at all; the analysis itself goes
    # off-thread, exactly as every upload path already does.
    try:
        merged_log.recalculate_log_type()
        merged_log.recalculate_scan_date()
    except Exception:
        logger.exception("Failed to recalculate log type/scan date for merged upload %s", retained_id)
    schedule_analysis_stats_recalc(merged_log)

    return merged_log
