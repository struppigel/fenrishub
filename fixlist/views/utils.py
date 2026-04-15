"""
Shared utility functions for views module.

Contains common helpers, rate limiting, IP resolution, and auxiliary view utilities
used across multiple view domains.
"""

from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.conf import settings
from django.core.cache import cache
from django.db.models import Q
from django.urls import reverse
from urllib.parse import urlencode
from datetime import timedelta
from django.utils import timezone

from ..models import UploadedLog, Fixlist


def _purge_old_trash():
    """Delete soft-deleted records older than 7 days and all records older than 30 days."""
    now = timezone.now()
    trash_cutoff = now - timedelta(days=7)
    hard_cutoff = now - timedelta(days=30)
    UploadedLog.objects.filter(deleted_at__isnull=False, deleted_at__lt=trash_cutoff).delete()
    Fixlist.objects.filter(deleted_at__isnull=False, deleted_at__lt=trash_cutoff).delete()
    UploadedLog.objects.filter(created_at__lt=hard_cutoff).delete()
    Fixlist.objects.filter(created_at__lt=hard_cutoff).delete()


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


def _uploads_redirect_with_state(request):
    """Redirect to uploaded_logs view preserving query parameters."""
    query_params = {}

    show_all = (request.POST.get('show_all') or request.GET.get('show_all') or '').strip().lower()
    if show_all in {'1', 'true', 'on', 'yes'}:
        query_params['show_all'] = '1'

    username_filter = (request.POST.get('u') or request.GET.get('u') or '').strip()
    if username_filter:
        query_params['u'] = username_filter

    if query_params:
        return redirect(f"{reverse('uploaded_logs')}?{urlencode(query_params)}")

    return redirect('uploaded_logs')


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
