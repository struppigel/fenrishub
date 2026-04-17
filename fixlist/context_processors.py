def user_display_prefs(request):
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        return {'word_wrap': False}
    profile = getattr(user, 'fenris_profile', None)
    return {'word_wrap': False if profile is None else profile.word_wrap}
