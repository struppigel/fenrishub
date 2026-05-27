"""
Guest-access helpers for the log analyzer and help page.

A guest is anyone who hits one of the gated URLs with `?guest=<token>` where
<token> matches the current non-empty `SiteConfig.guest_token`. Guest access is
stateless: every request must carry the token. Setting the token to an empty
string in the admin disables guest access entirely.
"""

from functools import wraps

from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import redirect

from ..models import SiteConfig

MODERATOR_GROUP_NAME = 'moderator'


def _request_guest_token(request) -> str:
    return (request.GET.get('guest', '') or '').strip()


def is_guest_request(request) -> bool:
    """True if the request is unauthenticated and carries a valid guest token."""
    user = getattr(request, 'user', None)
    if user is not None and user.is_authenticated:
        return False
    provided = _request_guest_token(request)
    if not provided:
        return False
    configured = SiteConfig.current_guest_token()
    if not configured:
        return False
    return provided == configured


def guest_or_login_required(view_func):
    """Allow either an authenticated user or a verified guest token."""
    login_protected = login_required(view_func)

    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if is_guest_request(request):
            return view_func(request, *args, **kwargs)
        return login_protected(request, *args, **kwargs)

    return _wrapped


def deny_guests(view_func):
    """Hard-block guests even if the underlying view loosens its login gate later."""

    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if is_guest_request(request):
            return HttpResponseForbidden('Guest access is read-only.')
        return view_func(request, *args, **kwargs)

    return _wrapped


def is_moderator(user) -> bool:
    """True if the user is a superuser or a member of the moderator Group."""
    if user is None or not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    return user.groups.filter(name=MODERATOR_GROUP_NAME).exists()


def moderator_required(view_func):
    """Allow only superusers and members of the moderator Group."""

    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        user = getattr(request, 'user', None)
        if user is None or not user.is_authenticated:
            return redirect('login')
        if not is_moderator(user):
            return HttpResponseForbidden('Moderator access required.')
        return view_func(request, *args, **kwargs)

    return _wrapped
