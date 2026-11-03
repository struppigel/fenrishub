"""
Personal API tokens for the read-only /api/v1/ endpoints.

Any logged-in helper can mint tokens for their own LLM client. The raw token is
rendered once, directly in the response to the create POST: never through
django.contrib.messages (whose default storage can put it in a cookie) and never
through a redirect URL.
"""

from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db.models import Sum
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from ..models import ApiRequestLog, ApiToken, SiteConfig
from .api_auth import api_limits
from .guest import deny_guests


def _user_usage(user):
    now = timezone.now()
    recent = ApiRequestLog.objects.filter(user=user)
    return {
        'requests_24h': recent.filter(created_at__gte=now - timedelta(hours=24)).aggregate(n=Sum('count'))['n'] or 0,
        'requests_30d': recent.filter(created_at__gte=now - timedelta(days=30)).aggregate(n=Sum('count'))['n'] or 0,
    }


def _render_tokens_page(request, *, new_token_raw='', new_token=None, error=''):
    tokens = list(ApiToken.objects.filter(user=request.user).select_related('revoked_by')[:50])
    response = render(
        request,
        'api_tokens.html',
        {
            'tokens': tokens,
            'active_count': sum(1 for token in tokens if token.is_active),
            'max_active': ApiToken.MAX_ACTIVE_PER_USER,
            'expiry_choices': ApiToken.EXPIRY_DAY_CHOICES,
            'default_expiry': ApiToken.DEFAULT_EXPIRY_DAYS,
            'new_token_raw': new_token_raw,
            'new_token': new_token,
            'error': error,
            'usage': _user_usage(request.user),
            'limits': api_limits(),
            'api_enabled': SiteConfig.api_is_enabled(),
            'api_base_url': request.build_absolute_uri('/api/v1/'),
        },
    )
    response['Cache-Control'] = 'no-store'
    return response


@deny_guests
@login_required
@require_http_methods(['GET', 'POST'])
def api_tokens_view(request):
    if request.method == 'GET':
        return _render_tokens_page(request)

    action = request.POST.get('action', '')
    if action == 'create':
        try:
            expiry_days = int(request.POST.get('expiry_days', ApiToken.DEFAULT_EXPIRY_DAYS))
        except ValueError:
            expiry_days = 0
        try:
            token, raw = ApiToken.issue(request.user, request.POST.get('name', ''), expiry_days)
        except ValidationError as exc:
            return _render_tokens_page(request, error=' '.join(exc.messages))
        return _render_tokens_page(request, new_token_raw=raw, new_token=token)

    if action == 'revoke':
        token_id = (request.POST.get('token_id') or '').strip()
        token = (
            ApiToken.objects.filter(pk=token_id, user=request.user).first()
            if token_id.isdigit() else None
        )
        if token is None:
            messages.error(request, 'Token not found.')
        else:
            token.revoke(by=request.user)
            messages.success(request, f'Token {token.prefix}… revoked.')
        return redirect('api_tokens')

    if action == 'revoke_all':
        revoked = 0
        for token in ApiToken.objects.filter(user=request.user, revoked_at__isnull=True):
            revoked += int(token.revoke(by=request.user))
        messages.success(request, f'Revoked {revoked} token(s).')
        return redirect('api_tokens')

    messages.error(request, 'Unknown action.')
    return redirect('api_tokens')
