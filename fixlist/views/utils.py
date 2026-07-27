"""
Shared utility functions for views module.

Contains common helpers, rate limiting, IP resolution, and auxiliary view utilities
used across multiple view domains.
"""

import io
import re
import zipfile

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.conf import settings
from django.core.cache import cache
from django.db.models import Max, Q
from django.urls import reverse
from urllib.parse import urlencode
from datetime import timedelta
from django.utils import timezone

from ..models import InfectionCase, UploadedLog, Fixlist


def _purge_old_trash():
    """Delete soft-deleted records older than 7 days and all records older than 30 days."""
    now = timezone.now()
    trash_cutoff = now - timedelta(days=7)
    hard_cutoff = now - timedelta(days=30)
    UploadedLog.objects.filter(deleted_at__isnull=False, deleted_at__lt=trash_cutoff).delete()
    Fixlist.objects.filter(deleted_at__isnull=False, deleted_at__lt=trash_cutoff).delete()
    UploadedLog.objects.filter(created_at__lt=hard_cutoff).delete()
    Fixlist.objects.filter(created_at__lt=hard_cutoff).delete()


def _autoclose_stale_cases():
    """Close open infection cases with no activity in over 30 days. Excludes training cases.

    Activity mirrors the cases-list view: the latest created_at across the case itself and its
    non-deleted logs, fixlists, and notes. Returns the number of cases closed.
    """
    cutoff = timezone.now() - timedelta(days=30)
    candidates = (
        InfectionCase.objects.filter(
            status=InfectionCase.STATUS_OPEN,
            deleted_at__isnull=True,
            is_training=False,
        )
        .annotate(
            last_log=Max(
                'log_links__uploaded_log__created_at',
                filter=Q(log_links__uploaded_log__deleted_at__isnull=True),
            ),
            last_fixlist=Max(
                'fixlist_links__fixlist__created_at',
                filter=Q(fixlist_links__fixlist__deleted_at__isnull=True),
            ),
            last_note=Max(
                'note_entries__created_at',
                filter=Q(note_entries__deleted_at__isnull=True),
            ),
        )
    )

    stale_ids = []
    for case in candidates:
        last_activity = max(
            ts
            for ts in (case.created_at, case.last_log, case.last_fixlist, case.last_note)
            if ts is not None
        )
        if last_activity < cutoff:
            stale_ids.append(case.pk)

    if not stale_ids:
        return 0
    return InfectionCase.objects.filter(pk__in=stale_ids).update(status=InfectionCase.STATUS_CLOSED)


def _anonymous_upload_limit() -> tuple[int, int]:
    """Get configured anonymous upload rate limit and time window."""
    limit = int(getattr(settings, 'ANON_UPLOAD_RATE_LIMIT_COUNT', 15) or 15)
    window_seconds = int(getattr(settings, 'ANON_UPLOAD_RATE_LIMIT_WINDOW_SECONDS', 3600) or 3600)
    return max(1, limit), max(1, window_seconds)


def _consume_anonymous_upload_slot(client_ip: str) -> bool:
    """Check and consume one anonymous upload slot. Returns True if slot available."""
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


def _resolve_upload_recipient_username(helper_username: str):
    """Resolve helper username from route for recipient channel assignment."""
    normalized_username = (helper_username or '').strip()
    if not normalized_username:
        return None, ''
    recipient_user = User.objects.filter(username__iexact=normalized_username).first()
    if recipient_user:
        return recipient_user, ''
    return None, normalized_username


def get_action_scoped_uploads(user):
    """
    Uploads shown in UI dropdowns and accessible for read/write actions.
    
    Returns: own channel plus general channel.
    """
    return UploadedLog.objects.filter(
        Q(recipient_user=user) | Q(recipient_user__isnull=True)
    )


def get_updatable_uploads(user):
    """
    Logs a user can update analysis stats for.
    
    Returns: own channel plus general channel.
    """
    return UploadedLog.objects.filter(
        Q(recipient_user=user) | Q(recipient_user__isnull=True)
    )


def redirect_preserving_filters(request, target_url_name):
    """Redirect to a listing view, preserving search/filter query params from POST or GET.

    Preserves `q`, `u`, and `page` as-is. Carries the uploads `channel` filter when it is
    non-default (anything other than `mine`); fixlist forms never submit it, so it's harmless
    there.
    """
    params = {}
    for key in ('q', 'u'):
        value = (request.POST.get(key) or request.GET.get(key) or '').strip()
        if value:
            params[key] = value

    channel = (request.POST.get('channel') or request.GET.get('channel') or '').strip()
    if channel and channel != 'mine':
        params['channel'] = channel

    page = (request.POST.get('page') or request.GET.get('page') or '').strip()
    if page.isdigit() and page != '1':
        params['page'] = page

    if params:
        return redirect(f"{reverse(target_url_name)}?{urlencode(params)}")
    return redirect(target_url_name)


def check_missing_ids(request, requested_ids, found_ids, *, item_label, target, in_trash=False):
    """Return an error redirect if any requested IDs are missing from found_ids; else None.

    `requested_ids` is the user-submitted list (preserves order); `found_ids` is the set
    of IDs the queryset actually returned.
    """
    missing = [i for i in requested_ids if i not in found_ids]
    if not missing:
        return None
    location = ' in trash' if in_trash else ''
    messages.error(request, f'Unable to find {item_label}(s){location}: {", ".join(missing)}.')
    return redirect_preserving_filters(request, target)


def safe_log_filename(uploaded_log) -> str:
    """Sanitize an upload's original filename for use as a download/archive entry name."""
    raw_name = uploaded_log.original_filename or f'{uploaded_log.upload_id}.txt'
    return re.sub(r'[\\/:*?"<>|\r\n]', '_', raw_name)[:200] or 'log.txt'


def build_uploaded_logs_zip(uploaded_logs) -> bytes:
    """Bundle uploaded logs into an in-memory zip archive and return its bytes.

    Entry names come from each log's original filename, sanitized; collisions get a
    numeric suffix so no log is silently dropped from the archive.
    """
    buffer = io.BytesIO()
    used_names = set()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for uploaded_log in uploaded_logs:
            safe_name = safe_log_filename(uploaded_log)
            candidate = safe_name
            counter = 2
            while candidate in used_names:
                stem, dot, ext = safe_name.partition('.')
                candidate = f'{stem}_{counter}{dot}{ext}' if dot else f'{safe_name}_{counter}'
                counter += 1
            used_names.add(candidate)
            archive.writestr(candidate, uploaded_log.content)
    return buffer.getvalue()


def get_client_ip(request):
    """Get client IP address from request, accounting for proxies."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def custom_404_view(request, exception):
    """Custom 404 error page."""
    return render(request, '404.html', status=404)
