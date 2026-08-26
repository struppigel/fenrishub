import logging
import time
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from .models import UserProfile

logger = logging.getLogger(__name__)

THROTTLE_SECONDS = 30

# Log a completion line only for requests this slow. Gunicorn's worker timeout
# is the hard ceiling; anything approaching it is worth seeing before it starts
# returning 500s.
SLOW_REQUEST_SECONDS = 5.0

# POST fields safe and useful to echo into the log. Deliberately a whitelist:
# request bodies here carry pasted log content, fixlist text and credentials,
# none of which belong in application logs.
LOGGED_POST_FIELDS = (
    'action',
    'upload_id',
    'confirm_action',
    'selected_username',
)

LOGGED_POST_LIST_FIELDS = (
    'selected_upload_ids',
    'selected_pks',
    'selected_fixlist_ids',
)

# Cap the id list so a select-all over hundreds of uploads cannot produce a
# multi-kilobyte log line.
MAX_LOGGED_IDS = 20


class ActionLogMiddleware:
    """Log one breadcrumb per user action (POST), before the view runs.

    Motivation: when a worker is killed mid-request -- Gunicorn's timeout sends
    SIGABRT, which unwinds as SystemExit past every `except Exception` -- the
    only artifact is a truncated traceback with no indication of which button
    was pressed or which upload was involved. A line emitted *before*
    get_response survives that kill; anything emitted after does not.

    Noise is bounded by logging POSTs only: GETs (page views, polling, static)
    produce nothing, so volume tracks user actions rather than traffic. The
    completion line is emitted only for slow requests or non-2xx/3xx responses.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method != 'POST':
            return self.get_response(request)

        descriptor = self._describe(request)
        logger.info('action start %s', descriptor)

        started = time.monotonic()
        try:
            response = self.get_response(request)
        except Exception:
            # Re-raised for Django's own handler; this only guarantees the
            # duration is recorded next to the breadcrumb above.
            logger.warning(
                'action raised %s after %.1fs', descriptor, time.monotonic() - started
            )
            raise

        elapsed = time.monotonic() - started
        if elapsed >= SLOW_REQUEST_SECONDS:
            logger.warning(
                'action slow %s -> %s in %.1fs', descriptor, response.status_code, elapsed
            )
        elif response.status_code >= 400:
            logger.info(
                'action failed %s -> %s in %.1fs', descriptor, response.status_code, elapsed
            )
        return response

    @staticmethod
    def _describe(request) -> str:
        user = getattr(request, 'user', None)
        username = user.username if (user is not None and user.is_authenticated) else 'anon'
        parts = [f'path={request.path}', f'user={username}']

        # Only form posts are inspected. Touching request.POST on a multipart
        # request consumes the upload stream here, in middleware, which both
        # costs the parse for views that never read POST and makes a later
        # request.body raise RawPostDataException -- the JSON API views read
        # request.body directly. Every button-driven action in this app is a
        # plain urlencoded form post, which is what the breadcrumb is for.
        content_type = (request.content_type or '').lower()
        if content_type != 'application/x-www-form-urlencoded':
            parts.append(f'content_type={content_type or "none"}')
            return ' '.join(parts)

        for field in LOGGED_POST_FIELDS:
            value = (request.POST.get(field) or '').strip()
            if value:
                parts.append(f'{field}={value[:80]}')

        for field in LOGGED_POST_LIST_FIELDS:
            values = [value.strip() for value in request.POST.getlist(field) if value.strip()]
            if not values:
                continue
            shown = ','.join(values[:MAX_LOGGED_IDS])
            suffix = f'(+{len(values) - MAX_LOGGED_IDS} more)' if len(values) > MAX_LOGGED_IDS else ''
            parts.append(f'{field}=[{shown}]{suffix}')

        return ' '.join(parts)


class OnlineUsersMiddleware:
    """Stamp UserProfile.last_seen on every authenticated request, throttled."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        user = getattr(request, 'user', None)
        if user is not None and user.is_authenticated:
            self._touch(user)
        return response

    @staticmethod
    def _touch(user):
        now = timezone.now()
        cutoff = now - timedelta(seconds=THROTTLE_SECONDS)
        updated = UserProfile.objects.filter(
            Q(last_seen__lt=cutoff) | Q(last_seen__isnull=True),
            user=user,
        ).update(last_seen=now)
        if updated == 0 and not UserProfile.objects.filter(user=user).exists():
            UserProfile.objects.create(user=user, last_seen=now)
