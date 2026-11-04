"""
Fixlist snippet management views.

Handles: creating, editing (full-page editor), deleting, and listing code snippets for reuse in fixlists.
"""

from urllib.parse import urlencode

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.db.models import Q
from django.urls import reverse

from django.contrib.auth.models import User

from ..models import FixlistSnippet, RuleTag
from ..tagging import parse_tag_ids, serialize_tag
from .rules import _sanitize_return_q


def _snippets_redirect(return_q):
    """Back to the snippets list, keeping the filter/search the user came from."""
    safe_query = _sanitize_return_q(return_q)
    if safe_query:
        return redirect(f"{reverse('snippets')}?{safe_query}")
    return redirect('snippets')


def serialize_snippet_for_analyzer(snippet, user):
    """The shape the analyzer's snippets menu reads.

    Shared by the analyzer page and the snippets API. Expects `trigger_tags`
    prefetched when serializing many snippets.
    """
    return {
        'id': snippet.id,
        'name': snippet.name if snippet.owner_id == user.id else f"{snippet.name} ({snippet.owner.username})",
        'category': snippet.category,
        'content': snippet.content,
        'trigger_tag_ids': [tag.pk for tag in snippet.trigger_tags.all()],
    }


def analyzer_snippets_for(user):
    """Serialized snippets the user selected for the analyzer, in menu order."""
    qs = FixlistSnippet.objects.filter(
        analyzer_users=user,
    ).select_related('owner').prefetch_related('trigger_tags').order_by('category', 'name')
    return [serialize_snippet_for_analyzer(snippet, user) for snippet in qs]


def shared_tag_snippets_for(user):
    """Other helpers' shared snippets that suggest at least one tag and that the
    user has not selected - the analyzer's fallback when a tag found in a log
    has no snippet of the user's own."""
    qs = (
        FixlistSnippet.objects.filter(is_shared=True, trigger_tags__isnull=False)
        .exclude(owner=user)
        .exclude(analyzer_users=user)
        .distinct()
        .select_related('owner')
        .prefetch_related('trigger_tags')
        .order_by('category', 'name')
    )
    return [serialize_snippet_for_analyzer(snippet, user) for snippet in qs]


def _trigger_tag_ids_from_post(request):
    """The tag ids picked in the snippet form, built-in tags included."""
    return parse_tag_ids(request.POST.getlist('trigger_tag_ids'))


def _snippet_form_from_post(request) -> dict:
    return {
        'name': request.POST.get('name', '').strip(),
        'content': request.POST.get('content', '').strip(),
        'category': request.POST.get('category', '').strip() or FixlistSnippet.DEFAULT_CATEGORY,
        'is_shared': request.POST.get('is_shared') == 'on',
    }


def _validate_snippet_form(user, form: dict, exclude_pk=None):
    """Return an error message for the submitted snippet form, or None if valid."""
    if not form['name']:
        return 'Snippet name is required.'
    if not form['content']:
        return 'Snippet content is required.'
    duplicates = FixlistSnippet.objects.filter(owner=user, name=form['name'])
    if exclude_pk is not None:
        duplicates = duplicates.exclude(pk=exclude_pk)
    if duplicates.exists():
        return f'A snippet named "{form["name"]}" already exists.'
    return None


def _snippet_form_context(user, form: dict, *, editing: bool, return_q: str = '', snippet=None, tag_ids=()) -> dict:
    """Context for snippet_editor.html, which serves both the add page and the editor."""
    cancel_url = reverse('snippets')
    if return_q:
        cancel_url = f"{cancel_url}?{return_q}"

    categories = sorted(set(
        FixlistSnippet.objects.filter(owner=user).values_list('category', flat=True)
    ))

    return {
        'editing': editing,
        'snippet': snippet,
        'form': form,
        'categories': categories,
        'return_q': return_q,
        'cancel_url': cancel_url,
        # Seeds the "suggest in the analyzer when" tag picker.
        'trigger_tags_json': [
            serialize_tag(tag) for tag in RuleTag.objects.filter(pk__in=tag_ids).select_related('category')
        ],
    }


@login_required
@require_http_methods(["GET", "POST"])
def add_snippet_view(request):
    """Full-page editor for creating a snippet."""
    if request.method == 'POST':
        return_q = request.POST.get('return_q', '')
        form = _snippet_form_from_post(request)
        tag_ids = _trigger_tag_ids_from_post(request)
        error = _validate_snippet_form(request.user, form)
        if error:
            # Re-render instead of redirecting so long snippet content is not lost.
            messages.error(request, error)
        else:
            snippet = FixlistSnippet.objects.create(owner=request.user, **form)
            snippet.trigger_tags.set(tag_ids)
            snippet.analyzer_users.add(request.user)
            messages.success(request, f'Snippet "{form["name"]}" created.')
            return _snippets_redirect(return_q)
    else:
        return_q = request.GET.get('return_q', '')
        form = {
            'name': '', 'content': '',
            'category': FixlistSnippet.DEFAULT_CATEGORY, 'is_shared': True,
        }
        tag_ids = []

    return render(request, 'snippet_editor.html', _snippet_form_context(
        request.user, form, editing=False, return_q=_sanitize_return_q(return_q), tag_ids=tag_ids,
    ))


@login_required
@require_http_methods(["GET", "POST"])
def edit_snippet_view(request, pk: int):
    """Full-page editor for one of the user's own snippets."""
    snippet = get_object_or_404(FixlistSnippet, pk=pk, owner=request.user)

    if request.method == 'POST':
        return_q = request.POST.get('return_q', '')
        form = _snippet_form_from_post(request)
        # A form without the tag picker must not clear them.
        tags_present = bool(request.POST.get('tags_present'))
        if tags_present:
            tag_ids = _trigger_tag_ids_from_post(request)
        else:
            tag_ids = list(snippet.trigger_tags.values_list('pk', flat=True))
        error = _validate_snippet_form(request.user, form, exclude_pk=snippet.pk)
        if error:
            messages.error(request, error)
        else:
            for field, value in form.items():
                setattr(snippet, field, value)
            snippet.save(update_fields=['name', 'content', 'is_shared', 'category', 'updated_at'])
            if tags_present:
                snippet.trigger_tags.set(tag_ids)
            messages.success(request, f'Snippet "{form["name"]}" updated.')
            return _snippets_redirect(return_q)
    else:
        return_q = request.GET.get('return_q', '')
        form = {
            'name': snippet.name, 'content': snippet.content,
            'category': snippet.category, 'is_shared': snippet.is_shared,
        }
        tag_ids = list(snippet.trigger_tags.values_list('pk', flat=True))

    return render(request, 'snippet_editor.html', _snippet_form_context(
        request.user, form, editing=True, return_q=_sanitize_return_q(return_q), snippet=snippet,
        tag_ids=tag_ids,
    ))


@login_required
@require_http_methods(["GET", "POST"])
def snippets_view(request):
    """List fixlist snippets; handles deletion. Adding/editing live on their own pages."""
    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'delete':
            pk = request.POST.get('pk', '').strip()
            snippet = get_object_or_404(FixlistSnippet, pk=pk, owner=request.user)
            name = snippet.name
            snippet.delete()
            messages.success(request, f'Snippet "{name}" deleted.')
            return _snippets_redirect(request.POST.get('return_q', ''))

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
            owner__username=shared_by, is_shared=True,
        ).select_related('owner')
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

    snippets = snippets.order_by('name').prefetch_related('trigger_tags__category')
    compact_view = request.COOKIES.get('fenrishub_snippets_compact') == '1'
    per_page = 14 if compact_view else 7
    page_obj = Paginator(snippets, per_page).get_page(request.GET.get('page'))

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
        'current_query_string': request.GET.urlencode(),
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
    return JsonResponse({
        'snippets': analyzer_snippets_for(request.user),
        'shared_tag_snippets': shared_tag_snippets_for(request.user),
    })
