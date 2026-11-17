"""
Fixlist snippet management views.

Handles: creating, editing (full-page editor), deleting, and listing code snippets for reuse in fixlists.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.urls import reverse

from ..models import FixlistSnippet, RuleTag
from ..tagging import serialize_tag
from .library_items import (
    analyzer_items_for, library_list_context, library_validation_error, shared_tag_items_for,
    toggle_analyzer_selection, trigger_tag_ids_from_post,
)
from .utils import redirect_with_return_q, sanitize_return_q


def analyzer_snippets_for(user):
    """Serialized snippets the user selected for the analyzer, in menu order."""
    return analyzer_items_for(FixlistSnippet, user)


def shared_tag_snippets_for(user):
    """Other helpers' shared snippets suggesting a tag (the analyzer's fallback)."""
    return shared_tag_items_for(FixlistSnippet, user)


def _snippet_form_from_post(request) -> dict:
    return {
        'name': request.POST.get('name', '').strip(),
        'content': request.POST.get('content', '').strip(),
        'category': request.POST.get('category', '').strip() or FixlistSnippet.DEFAULT_CATEGORY,
        'is_shared': request.POST.get('is_shared') == 'on',
    }


def _validate_snippet_form(user, form: dict, exclude_pk=None):
    """Return an error message for the submitted snippet form, or None if valid.

    Shared by the snippet editor and the token API's snippet writes.
    """
    return library_validation_error(
        FixlistSnippet, user, form['name'], form['content'], form['category'], exclude_pk=exclude_pk,
    )


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
        tag_ids = trigger_tag_ids_from_post(request)
        error = _validate_snippet_form(request.user, form)
        if error:
            # Re-render instead of redirecting so long snippet content is not lost.
            messages.error(request, error)
        else:
            snippet = FixlistSnippet.objects.create(owner=request.user, **form)
            snippet.trigger_tags.set(tag_ids)
            snippet.analyzer_users.add(request.user)
            messages.success(request, f'Snippet "{form["name"]}" created.')
            return redirect_with_return_q('snippets', return_q)
    else:
        return_q = request.GET.get('return_q', '')
        form = {
            'name': '', 'content': '',
            'category': FixlistSnippet.DEFAULT_CATEGORY, 'is_shared': True,
        }
        tag_ids = []

    return render(request, 'snippet_editor.html', _snippet_form_context(
        request.user, form, editing=False, return_q=sanitize_return_q(return_q), tag_ids=tag_ids,
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
            tag_ids = trigger_tag_ids_from_post(request)
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
            return redirect_with_return_q('snippets', return_q)
    else:
        return_q = request.GET.get('return_q', '')
        form = {
            'name': snippet.name, 'content': snippet.content,
            'category': snippet.category, 'is_shared': snippet.is_shared,
        }
        tag_ids = list(snippet.trigger_tags.values_list('pk', flat=True))

    return render(request, 'snippet_editor.html', _snippet_form_context(
        request.user, form, editing=True, return_q=sanitize_return_q(return_q), snippet=snippet,
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
            return redirect_with_return_q('snippets', request.POST.get('return_q', ''))

        return redirect('snippets')


    context = library_list_context(request, FixlistSnippet)
    return render(request, 'snippets.html', {
        **context,
        'snippets': context['page_obj'],
        'analyzer_snippet_ids': context['analyzer_item_ids'],
        'current_query_string': request.GET.urlencode(),
    })


@login_required
@require_http_methods(["POST"])
def snippets_toggle_analyzer_api(request):
    """Toggle whether a snippet is selected for the log analyzer."""
    return toggle_analyzer_selection(request, FixlistSnippet)


@login_required
@require_http_methods(["GET"])
def snippets_api(request):
    """Return snippets selected for the log analyzer by the current user."""
    return JsonResponse({
        'snippets': analyzer_snippets_for(request.user),
        'shared_tag_snippets': shared_tag_snippets_for(request.user),
    })
