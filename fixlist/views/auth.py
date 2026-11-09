"""
Authentication and user account views for FenrisHub.

Handles: login, password changes, dashboard, logout.
"""

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.views.decorators.http import require_http_methods

# The fix message lives in the user's flagged FRST fix speech; the default is
# defined in fix_message.py and re-exported here for existing importers.
from ..fix_message import (
    DEFAULT_FRST_FIX_MESSAGE_TEMPLATE,
    effective_fix_message,
    ensure_fix_message_speech,
)
from ..models import UserProfile
from ..rule_sets import on_user_rule_set_mode_changed
from .guest import guest_or_login_required


DEFAULT_ANALYZER_FIXLIST_TEMPLATE = """Start::
CreateRestorePoint:
CloseProcesses:

EmptyTemp:
End::"""


def effective_analyzer_fixlist_template(user):
    """The user's log analyzer fixlist starter, or the default when they have none."""
    profile = getattr(user, 'fenris_profile', None)
    return (
        (profile.analyzer_fixlist_template if profile else '').strip()
        or DEFAULT_ANALYZER_FIXLIST_TEMPLATE
    )


@require_http_methods(["GET", "POST"])
def login_view(request):
    """User login view."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})
    
    return render(request, 'login.html')


@login_required
@require_http_methods(["GET", "POST"])
def change_password_view(request):
    """Allow authenticated users to change their password without email input."""
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            updated_user = form.save()
            # Keep the current session active after password update.
            update_session_auth_hash(request, updated_user)
            messages.success(request, 'Password updated successfully.')
            return redirect('change_password')
    else:
        form = PasswordChangeForm(request.user)

    return render(request, 'change_password.html', {'form': form})


@login_required
@require_http_methods(["GET", "POST"])
def profile_view(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        # The profile edits the flagged FRST fix speech, the same entry the
        # speeches page lists. Empty means the default, as it always did.
        ensure_fix_message_speech(request.user, request.POST.get('frst_fix_message', ''))
        profile.word_wrap = 'word_wrap' in request.POST
        profile.uploads_all_channels_default = 'uploads_all_channels_default' in request.POST
        profile.analyzer_fixlist_template = request.POST.get('analyzer_fixlist_template', '')
        old_rule_set_mode = profile.rule_set_mode
        new_rule_set_mode = request.POST.get('rule_set_mode', UserProfile.RULE_SET_MODE_SHARED)
        if new_rule_set_mode not in dict(UserProfile.RULE_SET_MODE_CHOICES):
            new_rule_set_mode = UserProfile.RULE_SET_MODE_SHARED
        profile.rule_set_mode = new_rule_set_mode
        profile.save(update_fields=[
            'word_wrap', 'uploads_all_channels_default', 'analyzer_fixlist_template', 'rule_set_mode',
        ])
        if old_rule_set_mode != new_rule_set_mode:
            on_user_rule_set_mode_changed(request.user, old_rule_set_mode, new_rule_set_mode)
        messages.success(request, 'Profile settings updated successfully.')
        return redirect('profile')

    effective_frst_fix_message = effective_fix_message(request.user)
    effective_analyzer_fixlist_template = (profile.analyzer_fixlist_template or '').strip() or DEFAULT_ANALYZER_FIXLIST_TEMPLATE

    return render(
        request,
        'profile.html',
        {
            'frst_fix_message': effective_frst_fix_message,
            'default_frst_fix_message': DEFAULT_FRST_FIX_MESSAGE_TEMPLATE,
            'analyzer_fixlist_template': effective_analyzer_fixlist_template,
            'default_analyzer_fixlist_template': DEFAULT_ANALYZER_FIXLIST_TEMPLATE,
            'profile_word_wrap': profile.word_wrap,
            'profile_uploads_all_channels_default': profile.uploads_all_channels_default,
            'profile_rule_set_mode': profile.rule_set_mode,
            'rule_set_mode_choices': UserProfile.RULE_SET_MODE_CHOICES,
        },
    )


@require_http_methods(["POST"])
@login_required
def logout_view(request):
    """User logout view."""
    logout(request)
    return redirect('login')


@guest_or_login_required
@require_http_methods(["GET"])
def help_view(request):
    return render(request, 'help.html')


@require_http_methods(["GET"])
def frst_download_view(request):
    """Public, unlisted page offering the FRST scan tool for download."""
    return render(request, 'frst_download.html')


@require_http_methods(["GET"])
def about_view(request):
    """Public about page, linked from the footer."""
    return render(request, 'about.html')


@require_http_methods(["GET"])
def privacy_view(request):
    """Public privacy policy, linked from the footer."""
    return render(request, 'privacy.html')
