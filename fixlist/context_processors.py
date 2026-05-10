from .views.guest import is_guest_request


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
