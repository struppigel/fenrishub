"""
Speech management views.

Handles: creating, editing, deleting, and listing canned speeches — the reusable
prose blocks inserted into the analyzer's response panel. The list, selection and
validation code is shared with fixlist snippets (views/library_items.py).
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse

from ..models import Speech
from ..tagging import serialize_tag
from ..validators import PayloadValidator
from .library_items import (
    analyzer_items_for, library_list_context, library_validation_error, serialize_for_analyzer,
    shared_tag_items_for, toggle_analyzer_selection, trigger_tag_ids_from_post,
)

def analyzer_speeches_for(user):
    """Serialized speeches the user selected for the analyzer, in picker order."""
    return analyzer_items_for(Speech, user)


def shared_tag_speeches_for(user):
    """Other helpers' shared speeches suggesting a tag (the analyzer's fallback)."""
    return shared_tag_items_for(Speech, user)


def speeches_for_tags(user, tag_ids):
    """``(suggested, shared_fallback)`` speeches for the rule tags in `tag_ids`.

    The analyzer's choice (speech_suggestions.js): `suggested` are the user's
    selected speeches naming any of the tags; `shared_fallback` are other
    helpers' shared speeches for the tags none of the user's selected speeches
    names. Both lists of Speech objects with `trigger_tags` prefetched, by name.
    """
    found = set(tag_ids)
    if not found:
        return [], []

    def by_name(speeches):
        return sorted(speeches, key=lambda speech: (speech.name.casefold(), speech.pk))

    def names_any(speech, ids):
        return any(tag.pk in ids for tag in speech.trigger_tags.all())

    selected = list(
        Speech.objects.filter(analyzer_users=user)
        .select_related('owner').prefetch_related('trigger_tags')
    )
    covered = {tag.pk for speech in selected for tag in speech.trigger_tags.all()}
    suggested = [speech for speech in selected if names_any(speech, found)]

    uncovered = found - covered
    shared_fallback = []
    if uncovered:
        shared = (
            Speech.objects.filter(is_shared=True, trigger_tags__in=uncovered)
            .exclude(owner=user)
            .exclude(analyzer_users=user)
            .distinct()
            .select_related('owner')
            .prefetch_related('trigger_tags')
        )
        shared_fallback = list(shared)
    return by_name(suggested), by_name(shared_fallback)


def _speech_validation_error(owner, name, content, category='', exclude_pk=None):
    """Return an error message for invalid speech fields, or None if they are ok.

    Shared by the speeches page, the analyzer's create API and the token API.
    """
    return library_validation_error(Speech, owner, name, content, category, exclude_pk=exclude_pk)


@login_required
@require_http_methods(["GET", "POST"])
def speeches_view(request):
    """Manage speeches: create, edit, delete."""
    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'create':
            name = request.POST.get('name', '').strip()
            content = request.POST.get('content', '').strip()
            category = request.POST.get('category', '').strip() or Speech.DEFAULT_CATEGORY
            error = _speech_validation_error(request.user, name, content, category)
            if error:
                messages.error(request, error)
            else:
                is_shared = request.POST.get('is_shared') == 'on'
                speech = Speech.objects.create(
                    owner=request.user, name=name, content=content,
                    is_shared=is_shared, category=category,
                )
                speech.trigger_tags.set(trigger_tag_ids_from_post(request))
                speech.analyzer_users.add(request.user)
                messages.success(request, f'Speech "{name}" created.')
            return redirect('speeches')

        if action == 'edit':
            pk = request.POST.get('pk', '').strip()
            speech = get_object_or_404(Speech, pk=pk, owner=request.user)
            name = request.POST.get('name', '').strip()
            content = request.POST.get('content', '').strip()
            category = request.POST.get('category', '').strip() or Speech.DEFAULT_CATEGORY
            error = _speech_validation_error(
                request.user, name, content, category, exclude_pk=speech.pk,
            )
            if error:
                messages.error(request, error)
            else:
                speech.name = name
                speech.content = content
                speech.is_shared = request.POST.get('is_shared') == 'on'
                speech.category = category
                speech.save(update_fields=['name', 'content', 'is_shared', 'category', 'updated_at'])
                # A form without the tag picker must not clear them.
                if request.POST.get('tags_present'):
                    speech.trigger_tags.set(trigger_tag_ids_from_post(request))
                messages.success(request, f'Speech "{name}" updated.')
            return redirect('speeches')

        if action == 'delete':
            pk = request.POST.get('pk', '').strip()
            speech = get_object_or_404(Speech, pk=pk, owner=request.user)
            name = speech.name
            # The FRST fix message is also the profile's fix message and the
            # fixlist page's "copy fix message"; it is edited, never deleted.
            if speech.is_fix_message:
                messages.error(request, f'Speech "{name}" is your FRST fix message and cannot be deleted.')
                return redirect('speeches')
            speech.delete()
            messages.success(request, f'Speech "{name}" deleted.')
            return redirect('speeches')

    context = library_list_context(request, Speech)
    page_obj = context['page_obj']
    return render(request, 'speeches.html', {
        **context,
        'speeches': page_obj,
        'analyzer_speech_ids': context['analyzer_item_ids'],
        'speech_triggers_json': {
            str(speech.pk): {'tags': [serialize_tag(tag) for tag in speech.trigger_tags.all()]}
            for speech in page_obj
        },
    })


@login_required
@require_http_methods(["POST"])
def speeches_toggle_analyzer_api(request):
    """Toggle whether a speech is selected for the log analyzer."""
    return toggle_analyzer_selection(request, Speech)


@login_required
@require_http_methods(["POST"])
def speech_create_api(request):
    """Create a speech from text marked in the analyzer's response panel.

    Lets an analyst keep a paragraph worth reusing without leaving the analyzer.
    The new speech is selected for the analyzer immediately, so it can be used
    in the very next reply.
    """
    payload, error = PayloadValidator.json_object(request)
    if error:
        return error

    for field in ('name', 'content', 'category'):
        if field in payload and not isinstance(payload[field], str):
            return PayloadValidator.error_response(f'Field "{field}" must be a string.')

    is_shared = payload.get('is_shared', False)
    if not isinstance(is_shared, bool):
        return PayloadValidator.error_response('Field "is_shared" must be a boolean.')

    name = payload.get('name', '').strip()
    content = payload.get('content', '').strip()
    category = payload.get('category', '').strip() or Speech.DEFAULT_CATEGORY

    error = _speech_validation_error(request.user, name, content, category)
    if error:
        return PayloadValidator.error_response(error)

    speech = Speech.objects.create(
        owner=request.user, name=name, content=content,
        is_shared=is_shared, category=category,
    )
    speech.analyzer_users.add(request.user)

    # Same shape speeches_api returns, so the analyzer can drop it straight into
    # its speeches config and rebuild the dropdown without a refetch.
    return JsonResponse({'speech': serialize_for_analyzer(speech, request.user)})


@login_required
@require_http_methods(["GET"])
def speeches_api(request):
    """Return speeches selected for the log analyzer by the current user."""
    return JsonResponse({
        'speeches': analyzer_speeches_for(request.user),
        'shared_tag_speeches': shared_tag_speeches_for(request.user),
    })
