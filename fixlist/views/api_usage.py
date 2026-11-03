"""
Moderator view of /api/v1/ usage: who calls the API how much, and failed logins.

All numbers come from ApiRequestLog. A user is flagged when they approach a
24 h cap or hit a rate limit, so heavy use is visible before it is blocked.
"""

from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.models import User
from django.db.models import Count, Max, Q, Sum
from django.db.models.functions import TruncDate
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from ..models import ApiRequestLog, ApiToken, SiteConfig
from .api_auth import UPLOAD_READ_ENDPOINTS, api_limits
from .guest import moderator_required

RECENT_REQUESTS_SHOWN = 200
FAILED_AUTH_IPS_SHOWN = 50


def _usage_flags(row, limits):
    """Plain-text reasons a usage row deserves a look; empty when it does not."""
    flags = []
    if row['requests_24h'] >= limits['per_day'] / 2:
        flags.append('over half the daily request cap')
    if row['uploads_24h'] >= limits['uploads_per_day'] * 2 / 3:
        flags.append('many distinct uploads')
    if row['bytes_24h'] >= limits['bytes_per_day'] / 2:
        flags.append('over half the daily byte cap')
    if row['limited_24h']:
        flags.append('rate limited')
    return flags


@moderator_required
@require_http_methods(['GET'])
def api_usage_view(request):
    now = timezone.now()
    since_1h = now - timedelta(hours=1)
    since_24h = now - timedelta(hours=24)
    since_7d = now - timedelta(days=7)
    since_30d = now - timedelta(days=30)
    limits = api_limits()

    per_user = (
        ApiRequestLog.objects.filter(user__isnull=False, created_at__gte=since_30d)
        .values('user')
        .annotate(
            requests_1h=Sum('count', filter=Q(created_at__gte=since_1h)),
            requests_24h=Sum('count', filter=Q(created_at__gte=since_24h)),
            requests_7d=Sum('count', filter=Q(created_at__gte=since_7d)),
            requests_30d=Sum('count'),
            bytes_24h=Sum('response_bytes', filter=Q(created_at__gte=since_24h)),
            limited_24h=Count('id', filter=Q(created_at__gte=since_24h, status_code=429)),
            uploads_24h=Count(
                'target',
                filter=Q(created_at__gte=since_24h, endpoint__in=UPLOAD_READ_ENDPOINTS, status_code=200),
                distinct=True,
            ),
            last_request=Max('created_at'),
        )
    )
    rows_by_user = {}
    for row in per_user:
        row = {key: (value or 0) if key != 'last_request' else value for key, value in row.items()}
        rows_by_user[row['user']] = row

    active_tokens = dict(
        ApiToken.objects.filter(revoked_at__isnull=True, expires_at__gt=now)
        .values('user')
        .annotate(n=Count('id'))
        .values_list('user', 'n')
    )
    user_ids = set(rows_by_user) | set(active_tokens)
    usernames = dict(User.objects.filter(pk__in=user_ids).values_list('pk', 'username'))

    empty_row = {
        'requests_1h': 0, 'requests_24h': 0, 'requests_7d': 0, 'requests_30d': 0,
        'bytes_24h': 0, 'limited_24h': 0, 'uploads_24h': 0, 'last_request': None,
    }
    rows = []
    for user_id in user_ids:
        row = {**empty_row, **rows_by_user.get(user_id, {})}
        row.update({
            'user_id': user_id,
            'username': usernames.get(user_id, f'#{user_id}'),
            'active_tokens': active_tokens.get(user_id, 0),
        })
        row['flags'] = _usage_flags(row, limits)
        rows.append(row)
    rows.sort(key=lambda row: (-row['requests_24h'], row['username'].lower()))

    failed_auth = list(
        ApiRequestLog.objects.filter(user__isnull=True, status_code=401, created_at__gte=since_24h)
        .values('ip_address')
        .annotate(attempts=Sum('count'), last_attempt=Max('created_at'))
        .order_by('-attempts')[:FAILED_AUTH_IPS_SHOWN]
    )

    return render(request, 'api_usage.html', {
        'rows': rows,
        'failed_auth': failed_auth,
        'limits': limits,
        'api_enabled': SiteConfig.api_is_enabled(),
    })


@moderator_required
@require_http_methods(['GET', 'POST'])
def api_usage_user_view(request, user_id):
    subject = get_object_or_404(User, pk=user_id)

    if request.method == 'POST':
        action = request.POST.get('action', '')
        if action == 'revoke':
            token_id = (request.POST.get('token_id') or '').strip()
            token = (
                ApiToken.objects.filter(pk=token_id, user=subject).first()
                if token_id.isdigit() else None
            )
            if token is None:
                messages.error(request, 'Token not found.')
            else:
                token.revoke(by=request.user)
                messages.success(request, f'Token {token.prefix}… of {subject.username} revoked.')
        elif action == 'revoke_all':
            revoked = 0
            for token in ApiToken.objects.filter(user=subject, revoked_at__isnull=True):
                revoked += int(token.revoke(by=request.user))
            messages.success(request, f'Revoked {revoked} token(s) of {subject.username}.')
        else:
            messages.error(request, 'Unknown action.')
        return redirect('api_usage_user', user_id=subject.pk)

    since_30d = timezone.now() - timedelta(days=30)
    requests = ApiRequestLog.objects.filter(user=subject)
    recent = list(requests.select_related('token')[:RECENT_REQUESTS_SHOWN])
    daily = list(
        requests.filter(created_at__gte=since_30d)
        .annotate(day=TruncDate('created_at'))
        .values('day')
        .annotate(
            requests=Sum('count'),
            bytes=Sum('response_bytes'),
            uploads=Count(
                'target',
                filter=Q(endpoint__in=UPLOAD_READ_ENDPOINTS, status_code=200),
                distinct=True,
            ),
            limited=Count('id', filter=Q(status_code=429)),
        )
        .order_by('-day')
    )
    tokens = list(ApiToken.objects.filter(user=subject).select_related('revoked_by'))

    return render(request, 'api_usage_user.html', {
        'subject': subject,
        'recent': recent,
        'recent_limit': RECENT_REQUESTS_SHOWN,
        'daily': daily,
        'tokens': tokens,
    })
