"""
Authentication and user account views for FenrisHub.

Handles: login, password changes, dashboard, logout.
"""

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods

from ..models import Fixlist, UserProfile


DEFAULT_FRST_FIX_MESSAGE_TEMPLATE = """FRST  Fix

* Open the following link and press on the **Copy contents** button to copy the entire text: [fixlist]({FIXLISTLINK})
* Run **FRST64.exe** and click on **Fix**. Note: FRST reads the fixlist directly from your clipboard, so you don't need to paste or save it anywhere.
* A log (Fixlog.txt) will open on your desktop.
* Copy & paste the contents of the Fixlog.txt to [https://malwareanalysis.cc/upload/{HELPERNAME}/?u={USERNAME}](https://malwareanalysis.cc/upload/{HELPERNAME}/?u={USERNAME}) and press **\"save log\"**. Reply back with the keyword"""


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
@require_http_methods(["GET"])
def dashboard_view(request):
    """List all fixlists for the logged-in user."""
    fixlists_qs = Fixlist.objects.filter(owner=request.user, deleted_at__isnull=True)
    fixlist_trash_count = Fixlist.objects.filter(owner=request.user, deleted_at__isnull=False).count()
    page_obj = Paginator(fixlists_qs, 10).get_page(request.GET.get('page'))
    return render(request, 'dashboard.html', {'fixlists': page_obj, 'fixlist_trash_count': fixlist_trash_count, 'page_obj': page_obj})


@login_required
@require_http_methods(["GET", "POST"])
def profile_view(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        profile.frst_fix_message = request.POST.get('frst_fix_message', '')
        profile.save(update_fields=['frst_fix_message'])
        messages.success(request, 'Canned speech settings updated successfully.')
        return redirect('profile')

    effective_frst_fix_message = (profile.frst_fix_message or '').strip() or DEFAULT_FRST_FIX_MESSAGE_TEMPLATE

    return render(
        request,
        'canned_speeches.html',
        {
            'frst_fix_message': effective_frst_fix_message,
            'default_frst_fix_message': DEFAULT_FRST_FIX_MESSAGE_TEMPLATE,
        },
    )


@require_http_methods(["POST"])
@login_required
def logout_view(request):
    """User logout view."""
    logout(request)
    return redirect('login')
