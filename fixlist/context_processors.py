from datetime import timedelta

from django.utils import timezone

from .models import LogTypeBadge, UserProfile, log_type_css_slug
from .views.guest import is_guest_request, is_moderator

ONLINE_WINDOW_MINUTES = 5


def user_display_prefs(request):
    user = getattr(request, 'user', None)
    guest = is_guest_request(request)
    guest_token = (request.GET.get('guest', '') or '').strip() if guest else ''

    if user is None or not user.is_authenticated:
        return {
            'word_wrap': False,
            'is_guest': guest,
            'guest_token': guest_token,
        }
    profile = getattr(user, 'fenris_profile', None)
    return {
        'word_wrap': False if profile is None else profile.word_wrap,
        'is_guest': False,
        'guest_token': '',
    }


def moderator_status(request):
    user = getattr(request, 'user', None)
    return {'is_moderator': is_moderator(user)}


def log_type_badges(request):
    """Provide all log-type → CSS-slug → color mappings for dynamic badge styling.

    De-dupes by css_slug so two names that collapse to the same slug don't fight.
    """
    seen = {}
    try:
        for name, color in LogTypeBadge.objects.values_list('name', 'color'):
            slug = log_type_css_slug(name)
            if slug and slug not in seen:
                seen[slug] = color
    except Exception:
        return {'log_type_badges': []}
    return {'log_type_badges': [{'slug': s, 'color': c} for s, c in sorted(seen.items())]}


def online_users(request):
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        return {'online_users': {'count': 0, 'names': []}}
    cutoff = timezone.now() - timedelta(minutes=ONLINE_WINDOW_MINUTES)
    names = list(
        UserProfile.objects
        .filter(last_seen__gte=cutoff)
        .exclude(user_id=user.id)
        .order_by('user__username')
        .values_list('user__username', flat=True)
    )
    return {'online_users': {'count': len(names), 'names': names}}
