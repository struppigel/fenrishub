"""
Fixlist snippet management views.

Handles: creating, editing, deleting, and listing code snippets for reuse in fixlists.
"""

from urllib.parse import urlencode

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.db.models import Q

from ..models import FixlistSnippet


@login_required
@require_http_methods(["GET", "POST"])
def snippets_view(request):
    """Manage fixlist snippets: create, edit, delete."""
    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'create':
            name = request.POST.get('name', '').strip()
            content = request.POST.get('content', '').strip()
            if not name:
                messages.error(request, 'Snippet name is required.')
            elif not content:
                messages.error(request, 'Snippet content is required.')
            elif FixlistSnippet.objects.filter(owner=request.user, name=name).exists():
                messages.error(request, f'A snippet named "{name}" already exists.')
            else:
                is_shared = request.POST.get('is_shared') == 'on'
                FixlistSnippet.objects.create(owner=request.user, name=name, content=content, is_shared=is_shared)
                messages.success(request, f'Snippet "{name}" created.')
            return redirect('snippets')

        if action == 'edit':
            pk = request.POST.get('pk', '').strip()
            snippet = get_object_or_404(FixlistSnippet, pk=pk, owner=request.user)
            name = request.POST.get('name', '').strip()
            content = request.POST.get('content', '').strip()
            if not name:
                messages.error(request, 'Snippet name is required.')
            elif not content:
                messages.error(request, 'Snippet content is required.')
            else:
                duplicate = FixlistSnippet.objects.filter(owner=request.user, name=name).exclude(pk=snippet.pk).exists()
                if duplicate:
                    messages.error(request, f'A snippet named "{name}" already exists.')
                else:
                    snippet.name = name
                    snippet.content = content
                    snippet.is_shared = request.POST.get('is_shared') == 'on'
                    snippet.save(update_fields=['name', 'content', 'is_shared', 'updated_at'])
                    messages.success(request, f'Snippet "{name}" updated.')
            return redirect('snippets')

        if action == 'delete':
            pk = request.POST.get('pk', '').strip()
            snippet = get_object_or_404(FixlistSnippet, pk=pk, owner=request.user)
            name = snippet.name
            snippet.delete()
            messages.success(request, f'Snippet "{name}" deleted.')
            return redirect('snippets')

    show_all = request.GET.get('show_all', '').strip() in {'1', 'true', 'on', 'yes'}
    search_query = request.GET.get('q', '').strip()

    if show_all:
        snippets = FixlistSnippet.objects.filter(Q(owner=request.user) | Q(is_shared=True)).select_related('owner')
    else:
        snippets = FixlistSnippet.objects.filter(owner=request.user).select_related('owner')

    if search_query:
        snippets = snippets.filter(
            Q(name__icontains=search_query)
            | Q(content__icontains=search_query)
            | Q(owner__username__icontains=search_query)
        )

    snippets = snippets.order_by('name')
    page_obj = Paginator(snippets, 8).get_page(request.GET.get('page'))

    pagination_params = {}
    if search_query:
        pagination_params['q'] = search_query
    if show_all:
        pagination_params['show_all'] = '1'

    return render(request, 'snippets.html', {
        'snippets': page_obj,
        'page_obj': page_obj,
        'show_all': show_all,
        'search_query': search_query,
        'pagination_query': urlencode(pagination_params),
    })


@login_required
@require_http_methods(["GET"])
def snippets_api(request):
    """Return own snippets plus shared snippets from other users."""
    qs = FixlistSnippet.objects.filter(
        Q(owner=request.user) | Q(is_shared=True)
    ).select_related('owner').order_by('name')
    snippets = [
        {
            'id': s.id,
            'name': s.name if s.owner_id == request.user.id else f"{s.name} ({s.owner.username})",
            'content': s.content,
        }
        for s in qs
    ]
    return JsonResponse({'snippets': snippets})
