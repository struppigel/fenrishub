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

from django.contrib.auth.models import User

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
                category = request.POST.get('category', '').strip() or FixlistSnippet.DEFAULT_CATEGORY
                snippet = FixlistSnippet.objects.create(
                    owner=request.user, name=name, content=content,
                    is_shared=is_shared, category=category,
                )
                snippet.analyzer_users.add(request.user)
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
                    snippet.category = request.POST.get('category', '').strip() or FixlistSnippet.DEFAULT_CATEGORY
                    snippet.save(update_fields=['name', 'content', 'is_shared', 'category', 'updated_at'])
                    messages.success(request, f'Snippet "{name}" updated.')
            return redirect('snippets')

        if action == 'delete':
            pk = request.POST.get('pk', '').strip()
            snippet = get_object_or_404(FixlistSnippet, pk=pk, owner=request.user)
            name = snippet.name
            snippet.delete()
            messages.success(request, f'Snippet "{name}" deleted.')
            return redirect('snippets')


    shared_by = request.GET.get('shared_by', '').strip()
    search_query = request.GET.get('q', '').strip()
    category_filter = request.GET.get('category', '').strip()

    # users who share snippets (excluding current user)
    sharing_users = (
        User.objects.filter(fixlist_snippets__is_shared=True)
        .exclude(pk=request.user.pk)
        .distinct()
        .order_by('username')
    )

    if shared_by:
        snippets = FixlistSnippet.objects.filter(
            Q(owner=request.user) | Q(owner__username=shared_by, is_shared=True)
        ).select_related('owner').distinct()
    else:
        snippets = FixlistSnippet.objects.filter(owner=request.user).select_related('owner')

    # collect categories before text search so all categories remain visible in the dropdown
    categories = sorted(set(snippets.values_list('category', flat=True)))

    if category_filter:
        snippets = snippets.filter(category=category_filter)

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
    if shared_by:
        pagination_params['shared_by'] = shared_by
    if category_filter:
        pagination_params['category'] = category_filter

    analyzer_snippet_ids = set(
        request.user.analyzer_snippets.values_list('pk', flat=True)
    )

    return render(request, 'snippets.html', {
        'snippets': page_obj,
        'page_obj': page_obj,
        'shared_by': shared_by,
        'sharing_users': sharing_users,
        'search_query': search_query,
        'category_filter': category_filter,
        'categories': categories,
        'pagination_query': urlencode(pagination_params),
        'analyzer_snippet_ids': analyzer_snippet_ids,
    })


@login_required
@require_http_methods(["POST"])
def snippets_toggle_analyzer_api(request):
    """Toggle whether a snippet is selected for the log analyzer."""
    pk = request.POST.get('pk', '').strip()
    snippet = get_object_or_404(
        FixlistSnippet,
        Q(owner=request.user) | Q(is_shared=True),
        pk=pk,
    )
    if snippet.analyzer_users.filter(pk=request.user.pk).exists():
        snippet.analyzer_users.remove(request.user)
        selected = False
    else:
        snippet.analyzer_users.add(request.user)
        selected = True
    return JsonResponse({'selected': selected})


@login_required
@require_http_methods(["GET"])
def snippets_api(request):
    """Return snippets selected for the log analyzer by the current user."""
    qs = FixlistSnippet.objects.filter(
        analyzer_users=request.user,
    ).select_related('owner').order_by('category', 'name')
    snippets = [
        {
            'id': s.id,
            'name': s.name if s.owner_id == request.user.id else f"{s.name} ({s.owner.username})",
            'category': s.category,
            'content': s.content,
        }
        for s in qs
    ]
    return JsonResponse({'snippets': snippets})
