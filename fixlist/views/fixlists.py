"""
Fixlist management views.

Handles: creating, editing, sharing, downloading, and managing fixlists.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponse, Http404
from django.db.models import F
from django.utils import timezone

from ..models import Fixlist, AccessLog, UploadedLog
from .utils import _purge_old_trash, get_client_ip


@login_required
@require_http_methods(["GET", "POST"])
def create_fixlist_view(request):
    """Create a new fixlist on a dedicated page."""
    if request.method == 'POST':
        username = request.POST.get('username', 'Unknown')
        content = request.POST.get('content', '')
        internal_note = request.POST.get('internal_note', '')

        fixlist = Fixlist.objects.create(
            owner=request.user,
            username=username,
            content=content,
            internal_note=internal_note,
        )

        return redirect('view_fixlist', pk=fixlist.pk)

    prefill_username = (request.session.pop('analyzer_last_reddit_username', '') or '').strip()
    prefill_upload_id = (request.session.pop('analyzer_last_upload_id', '') or '').strip()

    if not prefill_username and prefill_upload_id:
        prefill_upload = UploadedLog.objects.filter(
            upload_id=prefill_upload_id,
            deleted_at__isnull=True,
        ).only('reddit_username').first()
        if prefill_upload and prefill_upload.reddit_username:
            prefill_username = prefill_upload.reddit_username

    return render(request, 'create_fixlist.html', {
        'prefill_username': prefill_username,
    })


@login_required
@require_http_methods(["GET", "POST"])
def fixlists_trash_view(request):
    """Trash bin for soft-deleted fixlists."""
    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'restore':
            pk = request.POST.get('pk', '').strip()
            fixlist = get_object_or_404(Fixlist, pk=pk, owner=request.user, deleted_at__isnull=False)
            fixlist.deleted_at = None
            fixlist.save(update_fields=['deleted_at'])
            messages.success(request, f'Fixlist "{fixlist.username}" restored.')
            return redirect('fixlists_trash')

        if action == 'delete_permanent':
            pk = request.POST.get('pk', '').strip()
            fixlist = get_object_or_404(Fixlist, pk=pk, owner=request.user, deleted_at__isnull=False)
            username = fixlist.username
            fixlist.delete()
            messages.success(request, f'Fixlist "{username}" permanently deleted.')
            return redirect('fixlists_trash')

        if action == 'empty_trash':
            count, _ = Fixlist.objects.filter(owner=request.user, deleted_at__isnull=False).delete()
            messages.success(request, f'Trash emptied ({count} fixlist(s) permanently deleted).')
            return redirect('fixlists_trash')

        messages.error(request, 'Invalid action.')
        return redirect('fixlists_trash')

    trashed = Fixlist.objects.filter(owner=request.user, deleted_at__isnull=False).order_by('-deleted_at')
    return render(request, 'fixlists_trash.html', {'fixlists': trashed})


@login_required
@require_http_methods(["GET", "POST"])
def view_fixlist(request, pk):
    """View and edit a fixlist."""
    fixlist = get_object_or_404(Fixlist, pk=pk, owner=request.user)
    
    if request.method == 'POST':
        action = request.POST.get('action', '')
        
        if action == 'update':
            fixlist.username = request.POST.get('username', fixlist.username)
            fixlist.content = request.POST.get('content', fixlist.content)
            fixlist.internal_note = request.POST.get('internal_note', fixlist.internal_note)
            fixlist.save()
            return redirect('view_fixlist', pk=fixlist.pk)
        
        elif action == 'delete':
            fixlist.deleted_at = timezone.now()
            fixlist.save(update_fields=['deleted_at'])
            _purge_old_trash()
            messages.success(request, f'Fixlist "{fixlist.username}" moved to trash.')
            return redirect('dashboard')
    
    share_url = request.build_absolute_uri(f'/share/{fixlist.share_token}/')

    context = {
        'fixlist': fixlist,
        'share_url': share_url,
        'guest_preview_url': f'{share_url}?preview=guest',
    }
    return render(request, 'view_fixlist.html', context)


@require_http_methods(["GET"])
def shared_fixlist_view(request, token):
    """View a shared fixlist (non-authenticated access)."""
    fixlist = get_object_or_404(Fixlist, share_token=token)

    # Trashed fixlists are not accessible by guests.
    if fixlist.deleted_at is not None and not (
        request.user.is_authenticated and request.user == fixlist.owner
    ):
        raise Http404

    # Log access
    AccessLog.objects.create(
        fixlist=fixlist,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )

    # Let the owner preview the page as a guest with ?preview=guest.
    preview_as_guest = (
        request.GET.get('preview') == 'guest'
        and request.user.is_authenticated
        and request.user == fixlist.owner
    )

    # Check if user should be treated as owner for UI behavior.
    is_owner = request.user.is_authenticated and request.user == fixlist.owner and not preview_as_guest
    
    context = {
        'fixlist': fixlist,
        'is_owner': is_owner,
        'preview_as_guest': preview_as_guest,
        'hide_authenticated_chrome': preview_as_guest,
    }
    return render(request, 'shared_fixlist.html', context)


@require_http_methods(["GET"])
def download_fixlist(request, token):
    """Download a fixlist as a text file."""
    fixlist = get_object_or_404(Fixlist, share_token=token)
    if fixlist.deleted_at is not None and not (
        request.user.is_authenticated and request.user == fixlist.owner
    ):
        raise Http404
    Fixlist.objects.filter(pk=fixlist.pk).update(download_count=F('download_count') + 1)
    
    # Log access
    AccessLog.objects.create(
        fixlist=fixlist,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    response = HttpResponse(fixlist.content, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="Fixlist.txt"'
    return response


@require_http_methods(["POST"])
@csrf_exempt
def copy_to_clipboard_api(request, token):
    """API endpoint for copying fixlist content."""
    fixlist = get_object_or_404(Fixlist, share_token=token)
    if fixlist.deleted_at is not None and not (
        request.user.is_authenticated and request.user == fixlist.owner
    ):
        raise Http404

    AccessLog.objects.create(
        fixlist=fixlist,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    return JsonResponse({'content': fixlist.content})
