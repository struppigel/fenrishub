from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from .models import UserProfile

THROTTLE_SECONDS = 30


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
