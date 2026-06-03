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

from ..models import UserProfile
from ..rule_sets import on_user_rule_set_mode_changed
from .guest import guest_or_login_required


DEFAULT_FRST_FIX_MESSAGE_TEMPLATE = """**FRST Fix**

* Open the following link and press on the **Copy contents** button to copy the entire text: [fixlist for {USERNAME}]({FIXLISTLINK})
* Run **FRST64.exe** and click on **Fix**. Note: FRST reads the fixlist directly from your clipboard, so you don't need to paste or save it anywhere.
* A log (Fixlog.txt) will open on your desktop.
* Copy & paste the contents of the Fixlog.txt to [https://malwareanalysis.cc/upload/{HELPERNAME}/?u={USERNAME}](https://malwareanalysis.cc/upload/{HELPERNAME}/?u={USERNAME}) and press **\"save log\"**. Reply back with the keyword

I have included the EmptyTemp: command. Note: This will remove cookies and may result in some websites (like banking) indicating they do not recognize your computer. It may be necessary to receive and apply a verification code.

It is normal for your system to reboot as a result of the fix."""


DEFAULT_ANALYZER_FIXLIST_TEMPLATE = """Start::
CreateRestorePoint:
CloseProcesses:

EmptyTemp:
End::"""


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
        profile.frst_fix_message = request.POST.get('frst_fix_message', '')
        profile.word_wrap = 'word_wrap' in request.POST
        profile.analyzer_fixlist_template = request.POST.get('analyzer_fixlist_template', '')
        old_rule_set_mode = profile.rule_set_mode
        new_rule_set_mode = request.POST.get('rule_set_mode', UserProfile.RULE_SET_MODE_SHARED)
        if new_rule_set_mode not in dict(UserProfile.RULE_SET_MODE_CHOICES):
            new_rule_set_mode = UserProfile.RULE_SET_MODE_SHARED
        profile.rule_set_mode = new_rule_set_mode
        profile.save(update_fields=[
            'frst_fix_message', 'word_wrap', 'analyzer_fixlist_template', 'rule_set_mode',
        ])
        if old_rule_set_mode != new_rule_set_mode:
            on_user_rule_set_mode_changed(request.user, old_rule_set_mode, new_rule_set_mode)
        messages.success(request, 'Profile settings updated successfully.')
        return redirect('profile')

    effective_frst_fix_message = (profile.frst_fix_message or '').strip() or DEFAULT_FRST_FIX_MESSAGE_TEMPLATE
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
