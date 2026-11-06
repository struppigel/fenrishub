"""
Bearer-token authentication, rate limiting and request logging for /api/v1/.

The token API exists so an LLM client (via the local MCP server in
tools/fenrishub_mcp/) can read logs and verdicts on a user's behalf. Every
request is authenticated by an `ApiToken` in the Authorization header only;
the session cookie is ignored, so a page in the user's browser can never ride
on their login to call the API.

Limits, all per user:
  - API_RATE_LIMIT_PER_MINUTE  cost units per minute (cache counter, per worker)
  - API_RATE_LIMIT_PER_DAY     requests in the last 24 h (ApiRequestLog)
  - API_MAX_UPLOADS_PER_DAY    distinct uploads read in the last 24 h (ApiRequestLog)
  - API_MAX_BYTES_PER_DAY      response bytes in the last 24 h (ApiRequestLog)
and per client IP:
  - API_AUTH_FAIL_PER_MINUTE   failed authentications per minute

The per-minute counter lives in the default cache, which is per process, so it
is a soft limit. The 24 h limits read ApiRequestLog and hold across workers.
"""

import logging
import time
from datetime import timedelta
from functools import wraps

from django.conf import settings
from django.core.cache import cache
from django.db.models import F, Sum
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from ..models import ApiRequestLog, ApiToken, SiteConfig
from ..validators import PayloadValidator
from .utils import get_valid_client_ip

logger = logging.getLogger('fixlist.api')

# Endpoints that hand out one upload's content or verdicts. Distinct uploads
# read through these count against API_MAX_UPLOADS_PER_DAY.
UPLOAD_READ_ENDPOINTS = ('api_v1_upload', 'api_v1_upload_analysis')

TOKEN_QUERY_PARAMS = ('token', 'access_token', 'api_key', 'key')
LAST_USED_REFRESH_SECONDS = 60
USER_AGENT_MAX_CHARS = 200
TARGET_MAX_CHARS = 200


def api_limits() -> dict:
    return {
        'per_minute': max(1, int(getattr(settings, 'API_RATE_LIMIT_PER_MINUTE', 60))),
        'per_day': max(1, int(getattr(settings, 'API_RATE_LIMIT_PER_DAY', 5000))),
        'uploads_per_day': max(1, int(getattr(settings, 'API_MAX_UPLOADS_PER_DAY', 300))),
        'bytes_per_day': max(1, int(getattr(settings, 'API_MAX_BYTES_PER_DAY', 200 * 1024 * 1024))),
        'auth_fail_per_minute': max(1, int(getattr(settings, 'API_AUTH_FAIL_PER_MINUTE', 10))),
    }


def _seconds_to_next_minute() -> int:
    return 60 - int(time.time()) % 60


def _minute_bucket() -> int:
    return int(time.time()) // 60


def _error(message, status, retry_after=None):
    response = PayloadValidator.error_response(message, status=status)
    if retry_after is not None:
        response['Retry-After'] = str(max(1, int(retry_after)))
    return response


def rate_limited_response(retry_after):
    return _error('Rate limit exceeded. Retry later.', 429, retry_after)


def _incr(cache_key, amount, timeout):
    """Add `amount` to a cache counter and return the new value."""
    if cache.add(cache_key, amount, timeout=timeout):
        return amount
    try:
        return cache.incr(cache_key, amount)
    except ValueError:
        # Expired between add() and incr().
        cache.set(cache_key, amount, timeout=timeout)
        return amount


def charge_api_units(request, units) -> bool:
    """Charge `units` against the caller's per-minute budget. False when over it.

    Views call this for work that turns out to be expensive only once it runs,
    e.g. an analysis whose cached payload is stale.
    """
    cache_key = f'api-rate:{request.user.pk}:{_minute_bucket()}'
    return _incr(cache_key, units, timeout=120) <= api_limits()['per_minute']


def _record_auth_failure(ip, endpoint, user_agent) -> int:
    """Count one failed authentication for `ip`; return this minute's total.

    The first failure in a minute writes an ApiRequestLog row; later ones only
    bump its `count`, so a flood of bad tokens costs one row per IP per minute.
    """
    cache_key = f'api-authfail:{ip or "unknown"}:{_minute_bucket()}'
    state = cache.get(cache_key)
    if state is None:
        row = ApiRequestLog.objects.create(
            endpoint=endpoint,
            status_code=401,
            ip_address=ip,
            user_agent=user_agent,
        )
        cache.set(cache_key, {'count': 1, 'row_id': row.pk}, timeout=120)
        return 1
    state['count'] += 1
    cache.set(cache_key, state, timeout=120)
    ApiRequestLog.objects.filter(pk=state['row_id']).update(count=F('count') + 1)
    return state['count']


def _auth_failures_this_minute(ip) -> int:
    state = cache.get(f'api-authfail:{ip or "unknown"}:{_minute_bucket()}')
    return state['count'] if state else 0


def _bearer_token(request) -> str:
    header = request.META.get('HTTP_AUTHORIZATION', '')
    scheme, _, value = header.partition(' ')
    if scheme.lower() != 'bearer':
        return ''
    return value.strip()


def _day_limit_violation(user, upload_id, limits):
    """Return a 429 response if a rolling 24 h limit is exhausted, else None."""
    since = timezone.now() - timedelta(hours=24)
    recent = ApiRequestLog.objects.filter(user=user, created_at__gte=since)
    totals = recent.aggregate(requests=Sum('count'), bytes=Sum('response_bytes'))
    if (totals['requests'] or 0) >= limits['per_day']:
        return rate_limited_response(3600)
    if (totals['bytes'] or 0) >= limits['bytes_per_day']:
        return rate_limited_response(3600)
    if upload_id:
        uploads_read = recent.filter(endpoint__in=UPLOAD_READ_ENDPOINTS, status_code=200)
        already_read = uploads_read.filter(target=upload_id).exists()
        if not already_read:
            distinct_uploads = uploads_read.values('target').distinct().count()
            if distinct_uploads >= limits['uploads_per_day']:
                return rate_limited_response(3600)
    return None


def _target_for(request, kwargs) -> str:
    for key in ('upload_id', 'case_id', 'forum_username', 'snippet_id', 'speech_id', 'rule_id'):
        if kwargs.get(key):
            return str(kwargs[key])[:TARGET_MAX_CHARS]
    for key in ('q', 'username'):
        value = (request.GET.get(key) or '').strip()
        if value:
            return value[:TARGET_MAX_CHARS]
    return ''


def api_token_required(endpoint, *, cost=1, write=False):
    """Decorate an API view: kill switch, HTTPS, token auth, limits, logging.

    `endpoint` names the row in ApiRequestLog; `cost` is how many per-minute
    units one call consumes up front.

    Views are read-only GET endpoints unless `write=True`: those take a POST
    with a JSON body and need a write token (`ApiToken.can_write`) whose user
    is a superuser right now. They are CSRF-exempt, which is safe because the
    API ignores the session entirely - the Authorization header is the only
    identity, so a page in someone's browser cannot ride on their login.
    """

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            started = time.monotonic()

            if not SiteConfig.api_is_enabled():
                return _error('The API is disabled on this server.', 503)
            if not settings.DEBUG and not request.is_secure():
                return _error('HTTPS is required.', 400)
            if write and request.method != 'POST':
                return _error('Only POST is supported.', 405)
            if not write and request.method != 'GET':
                return _error('Only GET is supported.', 405)
            if any(param in request.GET for param in TOKEN_QUERY_PARAMS):
                return _error('Send the token in the Authorization header, never in the URL.', 400)

            limits = api_limits()
            ip = get_valid_client_ip(request)
            user_agent = (request.META.get('HTTP_USER_AGENT') or '')[:USER_AGENT_MAX_CHARS]

            if _auth_failures_this_minute(ip) >= limits['auth_fail_per_minute']:
                _record_auth_failure(ip, endpoint, user_agent)
                return rate_limited_response(_seconds_to_next_minute())

            token = ApiToken.authenticate(_bearer_token(request))
            if token is None:
                _record_auth_failure(ip, endpoint, user_agent)
                return _error('Missing, invalid, expired or revoked API token.', 401)

            # The token is the only identity; whatever the session says is ignored.
            request.user = token.user
            request.api_token = token

            if write and not (token.can_write and token.user.is_superuser):
                response = _error("Write access needs a superuser's write token.", 403)
                response['Cache-Control'] = 'no-store'
                _log_request(request, token, endpoint, kwargs, 403, 0, started, ip, user_agent)
                return response

            upload_id = kwargs.get('upload_id') if endpoint in UPLOAD_READ_ENDPOINTS else None
            response = None
            if not charge_api_units(request, cost):
                response = rate_limited_response(_seconds_to_next_minute())
            else:
                response = _day_limit_violation(token.user, upload_id, limits)

            if response is None:
                try:
                    response = view_func(request, *args, **kwargs)
                except Exception:
                    _log_request(request, token, endpoint, kwargs, 500, 0, started, ip, user_agent)
                    raise

            # Responses carry victims' log data; keep them out of every cache.
            response['Cache-Control'] = 'no-store'
            response_bytes = len(response.content) if not response.streaming else 0
            _log_request(
                request, token, endpoint, kwargs, response.status_code, response_bytes,
                started, ip, user_agent,
            )
            return response

        # Read by the tests that check every /api/v1/ view is either GET-only or write-gated.
        _wrapped.api_write = write
        return csrf_exempt(_wrapped) if write else _wrapped

    return decorator


def _log_request(request, token, endpoint, kwargs, status_code, response_bytes, started, ip, user_agent):
    duration_ms = int((time.monotonic() - started) * 1000)
    target = _target_for(request, kwargs)
    ApiRequestLog.objects.create(
        token=token,
        user=token.user,
        endpoint=endpoint,
        target=target,
        status_code=status_code,
        response_bytes=response_bytes,
        duration_ms=duration_ms,
        ip_address=ip,
        user_agent=user_agent,
    )
    logger.info(
        'api %s user=%s token=%s target=%r status=%s bytes=%s ms=%s',
        endpoint, token.user.username, token.prefix, target, status_code, response_bytes, duration_ms,
    )
    now = timezone.now()
    if token.last_used_at is None or (now - token.last_used_at).total_seconds() >= LAST_USED_REFRESH_SECONDS:
        ApiToken.objects.filter(pk=token.pk).update(last_used_at=now)
