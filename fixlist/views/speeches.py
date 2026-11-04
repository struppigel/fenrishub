"""
Speech management views.

Handles: creating, editing, deleting, and listing canned speeches — the reusable
prose blocks inserted into the analyzer's response panel. Mirrors views/snippets.py.
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

from ..models import Speech
from ..tagging import parse_tag_ids, serialize_tag
from ..validators import BadJsonError, PayloadTooLargeError, PayloadValidator

# Matches the model's CharField(max_length=255) on name and category. The forms
# on the speeches page are bounded by the widget, but a JSON client is not, and
# an over-long value would surface as a database error instead of a 400.
SPEECH_FIELD_MAX_LENGTH = 255


def _trigger_tag_ids_from_post(request):
    """The tag ids picked in the speech form, built-in tags included."""
    return parse_tag_ids(request.POST.getlist('trigger_tag_ids'))


def serialize_speech_for_analyzer(speech, user):
    """The shape the analyzer's speeches picker reads.

    One place for it, because the analyzer page, the speeches API and the
    capture API all hand speeches to the same picker. Expects `trigger_tags`
    prefetched when serializing many speeches.
    """
    return {
        'id': speech.id,
        'name': speech.name if speech.owner_id == user.id else f"{speech.name} ({speech.owner.username})",
        'category': speech.category,
        'content': speech.content,
        'trigger_tag_ids': [tag.pk for tag in speech.trigger_tags.all()],
    }


def analyzer_speeches_for(user):
    """Serialized speeches the user selected for the analyzer, in picker order."""
    qs = Speech.objects.filter(
        analyzer_users=user,
    ).select_related('owner').prefetch_related('trigger_tags').order_by('category', 'name')
    return [serialize_speech_for_analyzer(speech, user) for speech in qs]


def shared_tag_speeches_for(user):
    """Other helpers' shared speeches that suggest at least one tag and that the
    user has not selected - the analyzer's fallback when a tag found in a log
    has no speech of the user's own."""
    qs = (
        Speech.objects.filter(is_shared=True, trigger_tags__isnull=False)
        .exclude(owner=user)
        .exclude(analyzer_users=user)
        .distinct()
        .select_related('owner')
        .prefetch_related('trigger_tags')
        .order_by('category', 'name')
    )
    return [serialize_speech_for_analyzer(speech, user) for speech in qs]


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

    Shared by the speeches page and the analyzer's create API so the two can
    never drift apart on what counts as a valid speech.
    """
    if not name:
        return 'Speech name is required.'
    if not content:
        return 'Speech content is required.'
    if len(name) > SPEECH_FIELD_MAX_LENGTH:
        return f'Speech name must be at most {SPEECH_FIELD_MAX_LENGTH} characters.'
    if len(category) > SPEECH_FIELD_MAX_LENGTH:
        return f'Speech category must be at most {SPEECH_FIELD_MAX_LENGTH} characters.'

    duplicates = Speech.objects.filter(owner=owner, name=name)
    if exclude_pk is not None:
        duplicates = duplicates.exclude(pk=exclude_pk)
    if duplicates.exists():
        return f'A speech named "{name}" already exists.'
    return None


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
                speech.trigger_tags.set(_trigger_tag_ids_from_post(request))
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
                    speech.trigger_tags.set(_trigger_tag_ids_from_post(request))
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

    shared_by = request.GET.get('shared_by', '').strip()
    search_query = request.GET.get('q', '').strip()
    category_filter = request.GET.get('category', '').strip()

    # users who share speeches (excluding current user)
    sharing_users = (
        User.objects.filter(speeches__is_shared=True)
        .exclude(pk=request.user.pk)
        .distinct()
        .order_by('username')
    )

    if shared_by:
        speeches = Speech.objects.filter(
            owner__username=shared_by, is_shared=True,
        ).select_related('owner')
    else:
        speeches = Speech.objects.filter(owner=request.user).select_related('owner')

    # collect categories before text search so all categories remain visible in the dropdown
    categories = sorted(set(speeches.values_list('category', flat=True)))

    if category_filter:
        speeches = speeches.filter(category=category_filter)

    if search_query:
        speeches = speeches.filter(
            Q(name__icontains=search_query)
            | Q(content__icontains=search_query)
            | Q(owner__username__icontains=search_query)
        )

    speeches = speeches.order_by('name').prefetch_related('trigger_tags__category')
    compact_view = request.COOKIES.get('fenrishub_speeches_compact') == '1'
    per_page = 14 if compact_view else 7
    page_obj = Paginator(speeches, per_page).get_page(request.GET.get('page'))

    pagination_params = {}
    if search_query:
        pagination_params['q'] = search_query
    if shared_by:
        pagination_params['shared_by'] = shared_by
    if category_filter:
        pagination_params['category'] = category_filter

    analyzer_speech_ids = set(
        request.user.analyzer_speeches.values_list('pk', flat=True)
    )

    return render(request, 'speeches.html', {
        'speeches': page_obj,
        'page_obj': page_obj,
        'shared_by': shared_by,
        'sharing_users': sharing_users,
        'search_query': search_query,
        'category_filter': category_filter,
        'categories': categories,
        'pagination_query': urlencode(pagination_params),
        'analyzer_speech_ids': analyzer_speech_ids,
        'speech_triggers_json': {
            str(speech.pk): {'tags': [serialize_tag(tag) for tag in speech.trigger_tags.all()]}
            for speech in page_obj
        },
    })


@login_required
@require_http_methods(["POST"])
def speeches_toggle_analyzer_api(request):
    """Toggle whether a speech is selected for the log analyzer."""
    pk = request.POST.get('pk', '').strip()
    speech = get_object_or_404(
        Speech,
        Q(owner=request.user) | Q(is_shared=True),
        pk=pk,
    )
    if speech.analyzer_users.filter(pk=request.user.pk).exists():
        speech.analyzer_users.remove(request.user)
        selected = False
    else:
        speech.analyzer_users.add(request.user)
        selected = True
    return JsonResponse({'selected': selected})


@login_required
@require_http_methods(["POST"])
def speech_create_api(request):
    """Create a speech from text marked in the analyzer's response panel.

    Lets an analyst keep a paragraph worth reusing without leaving the analyzer.
    The new speech is selected for the analyzer immediately, so it can be used
    in the very next reply.
    """
    try:
        payload = PayloadValidator.json_payload(request)
    except PayloadTooLargeError as exc:
        return PayloadValidator.error_response(str(exc), status=413)
    except BadJsonError:
        return PayloadValidator.error_response('Invalid JSON payload.')

    if not isinstance(payload, dict):
        return PayloadValidator.error_response('Invalid JSON payload.')

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
    return JsonResponse({'speech': serialize_speech_for_analyzer(speech, request.user)})


@login_required
@require_http_methods(["GET"])
def speeches_api(request):
    """Return speeches selected for the log analyzer by the current user."""
    return JsonResponse({
        'speeches': analyzer_speeches_for(request.user),
        'shared_tag_speeches': shared_tag_speeches_for(request.user),
    })
