"""Shared code for the two "library" models: fixlist snippets and speeches.

Both are a helper's named, categorised blocks of text that can be shared with
other helpers, selected for the log analyzer and suggested there by rule tags.
Everything here takes the model (`FixlistSnippet` or `Speech`) as a parameter,
so the snippets and speeches views, the analyzer and the token API all apply
the same rules to both.
"""
from urllib.parse import urlencode

from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404

from ..models import FixlistSnippet, Speech
from ..tagging import parse_tag_ids
from .utils import non_empty_params

# Matches the models' CharField(max_length=255) on name and category. The web
# forms are bounded by the widget, but a JSON client is not, and an over-long
# value would surface as a database error instead of a 400.
LIBRARY_FIELD_MAX_LENGTH = 255

# How each model is named in messages, and the related name of its `owner`.
_LABELS = {FixlistSnippet: 'Snippet', Speech: 'Speech'}
_OWNER_RELATED_NAMES = {FixlistSnippet: 'fixlist_snippets', Speech: 'speeches'}

# What library_list.html needs to know about each list page. `compact_key` is
# both the localStorage key and the cookie the server reads for the page size.
LIBRARY_PAGES = {
    FixlistSnippet: {
        'noun': 'snippet', 'plural': 'snippets', 'list_url': 'snippets',
        'toggle_url': 'snippets_toggle_analyzer_api', 'compact_key': 'fenrishub_snippets_compact',
    },
    Speech: {
        'noun': 'speech', 'plural': 'speeches', 'list_url': 'speeches',
        'toggle_url': 'speeches_toggle_analyzer_api', 'compact_key': 'fenrishub_speeches_compact',
    },
}


def serialize_for_analyzer(item, user):
    """The shape the analyzer's snippets menu and speeches picker read.

    Expects `trigger_tags` prefetched when serializing many items.
    """
    return {
        'id': item.id,
        'name': item.name if item.owner_id == user.id else f"{item.name} ({item.owner.username})",
        'category': item.category,
        'content': item.content,
        'trigger_tag_ids': [tag.pk for tag in item.trigger_tags.all()],
    }


def analyzer_items_for(model, user):
    """Serialized items the user selected for the analyzer, in menu order."""
    qs = model.objects.filter(
        analyzer_users=user,
    ).select_related('owner').prefetch_related('trigger_tags').order_by('category', 'name')
    return [serialize_for_analyzer(item, user) for item in qs]


def shared_tag_items_for(model, user):
    """Other helpers' shared items that suggest at least one tag and that the
    user has not selected. The analyzer suggests shared snippets for every tag
    found in a log, shared speeches only for tags no own speech covers."""
    qs = (
        model.objects.filter(is_shared=True, trigger_tags__isnull=False)
        .exclude(owner=user)
        .exclude(analyzer_users=user)
        .distinct()
        .select_related('owner')
        .prefetch_related('trigger_tags')
        .order_by('category', 'name')
    )
    return [serialize_for_analyzer(item, user) for item in qs]


def trigger_tag_ids_from_post(request):
    """The tag ids picked in a snippet or speech form, built-in tags included."""
    return parse_tag_ids(request.POST.getlist('trigger_tag_ids'))


def library_validation_error(model, owner, name, content, category='', exclude_pk=None):
    """An error message for invalid fields of a snippet or speech, or None.

    Shared by the web pages, the analyzer's speech capture and the token API so
    they never drift apart on what counts as valid.
    """
    label = _LABELS[model]
    if not name:
        return f'{label} name is required.'
    if not content:
        return f'{label} content is required.'
    if len(name) > LIBRARY_FIELD_MAX_LENGTH:
        return f'{label} name must be at most {LIBRARY_FIELD_MAX_LENGTH} characters.'
    if len(category) > LIBRARY_FIELD_MAX_LENGTH:
        return f'{label} category must be at most {LIBRARY_FIELD_MAX_LENGTH} characters.'
    duplicates = model.objects.filter(owner=owner, name=name)
    if exclude_pk is not None:
        duplicates = duplicates.exclude(pk=exclude_pk)
    if duplicates.exists():
        return f'A {label.lower()} named "{name}" already exists.'
    return None


def library_list_context(request, model) -> dict:
    """The filters, page and selection state of a snippets or speeches list page.

    Lists the user's own items, or one other helper's shared ones (`shared_by`),
    filtered by category and a text search; 7 per page, 14 in compact view.
    """
    shared_by = request.GET.get('shared_by', '').strip()
    search_query = request.GET.get('q', '').strip()
    category_filter = request.GET.get('category', '').strip()

    # users who share items of this kind (excluding the current user)
    related_name = _OWNER_RELATED_NAMES[model]
    sharing_users = (
        User.objects.filter(**{f'{related_name}__is_shared': True})
        .exclude(pk=request.user.pk)
        .distinct()
        .order_by('username')
    )

    if shared_by:
        items = model.objects.filter(owner__username=shared_by, is_shared=True).select_related('owner')
    else:
        items = model.objects.filter(owner=request.user).select_related('owner')

    # collect categories before text search so all categories remain visible in the dropdown
    categories = sorted(set(items.values_list('category', flat=True)))

    if category_filter:
        items = items.filter(category=category_filter)
    if search_query:
        items = items.filter(
            Q(name__icontains=search_query)
            | Q(content__icontains=search_query)
            | Q(owner__username__icontains=search_query)
        )

    items = items.order_by('name').prefetch_related('trigger_tags__category')
    page = LIBRARY_PAGES[model]
    per_page = 14 if request.COOKIES.get(page['compact_key']) == '1' else 7
    page_obj = Paginator(items, per_page).get_page(request.GET.get('page'))

    return {
        'library': page,
        'page_obj': page_obj,
        'shared_by': shared_by,
        'sharing_users': sharing_users,
        'search_query': search_query,
        'category_filter': category_filter,
        'categories': categories,
        'pagination_query': urlencode(non_empty_params(
            q=search_query, shared_by=shared_by, category=category_filter,
        )),
        'analyzer_item_ids': set(
            model.objects.filter(analyzer_users=request.user).values_list('pk', flat=True)
        ),
    }


def toggle_analyzer_selection(request, model):
    """Toggle whether a snippet or speech (own or shared) is selected for the analyzer."""
    pk = request.POST.get('pk', '').strip()
    item = get_object_or_404(model, Q(owner=request.user) | Q(is_shared=True), pk=pk)
    if item.analyzer_users.filter(pk=request.user.pk).exists():
        item.analyzer_users.remove(request.user)
        selected = False
    else:
        item.analyzer_users.add(request.user)
        selected = True
    return JsonResponse({'selected': selected})
