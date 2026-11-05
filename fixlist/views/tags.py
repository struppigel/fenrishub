"""
Rule tag views.

Handles: the tag list (delete), the tag editor page (add, edit), and the JSON
endpoints behind them and behind the tag pickers on the rule forms, the
analyzer and the speeches page: listing tags, creating/updating a tag
(optionally applying it to rules in the same request), previewing a regex over
all rule descriptions, and suggesting tags for a description. Tags are shared
and any logged-in helper may edit them; built-in tags cannot be deleted.
"""

from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Q
from django.db.models.functions import Lower
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from ..analyzer import parse_rule_line
from ..models import DEFAULT_TAG_CATEGORY_COLOR, ClassificationRule, RuleTag, TagCategory
from ..tagging import (
    CONDITION_STATUSES,
    TagConditions,
    apply_tag,
    conditions_error,
    conditions_from_payload,
    linkable_snippets,
    linkable_speeches,
    parse_tag_category_priority,
    save_tag,
    matching_rule_ids,
    preview_conditions,
    serialize_tag,
    suggest_tags,
    tag_category_error,
    tag_fields_error,
    tag_rule_counts,
    unmatched_tagged_rule_ids,
)
from ..validators import BadJsonError, PayloadTooLargeError, PayloadValidator
from .rules import _sanitize_return_q

TAGS_PER_PAGE = 12

# ?usage= on the tag list: {value: (label, filter on the list's count annotations)}.
TAG_USAGE_FILTERS = {
    'unused': ('unused', {'rule_count': 0, 'speech_count': 0, 'snippet_count': 0}),
    'no_speech': ('without speech', {'speech_count': 0}),
    'no_rules': ('without rules', {'rule_count': 0}),
}


def _json_payload(request):
    """The request's JSON object, or a JsonResponse error to return instead."""
    try:
        payload = PayloadValidator.json_payload(request)
    except PayloadTooLargeError as exc:
        return None, PayloadValidator.error_response(str(exc), status=413)
    except BadJsonError:
        return None, PayloadValidator.error_response('Invalid JSON payload.')
    if not isinstance(payload, dict):
        return None, PayloadValidator.error_response('Invalid JSON payload.')
    return payload, None


def _id_list(payload, field):
    value = payload.get(field, [])
    if not isinstance(value, list):
        return None
    ids = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            return None
        ids.append(item)
    return ids


@login_required
@require_http_methods(["GET", "POST"])
def rule_tags_view(request):
    """List tags with their rule, speech, snippet, pending and unmatched counts; delete tags."""
    if request.method == 'POST':
        if request.POST.get('action') == 'delete':
            tag = get_object_or_404(RuleTag, pk=request.POST.get('pk', '').strip() or 0)
            if tag.builtin_code is not None:
                messages.error(request, f'"{tag.name}" is a built-in tag and cannot be deleted.')
            else:
                name = tag.name
                tag.delete()
                messages.success(request, f'Tag "{name}" deleted.')
        # Back to the page and filters the delete came from.
        safe_query = _sanitize_return_q(request.POST.get('return_q'))
        if safe_query:
            return redirect(f"{reverse('rule_tags')}?{safe_query}")
        return redirect('rule_tags')

    # Older ?edit=<id> links open the editor page.
    edit_id = request.GET.get('edit', '').strip()
    if edit_id.isdigit():
        return redirect('rule_tag_edit', pk=int(edit_id))

    search_query = request.GET.get('q', '').strip()
    category_filter = request.GET.get('category', '').strip()
    if not category_filter.isdigit():
        category_filter = ''
    usage_filter = request.GET.get('usage', '').strip()
    if usage_filter not in TAG_USAGE_FILTERS:
        usage_filter = ''

    has_any_tags = RuleTag.objects.exists()
    tags_qs = RuleTag.objects.annotate(
        rule_count=Count('rules', distinct=True),
        speech_count=Count('speeches', distinct=True),
        snippet_count=Count('snippets', distinct=True),
    ).select_related('updated_by', 'category')
    if search_query:
        tags_qs = tags_qs.filter(
            Q(name__icontains=search_query)
            | Q(description__icontains=search_query)
            | Q(builtin_code__icontains=search_query)
        )
    if category_filter:
        tags_qs = tags_qs.filter(category_id=int(category_filter))
    if usage_filter:
        tags_qs = tags_qs.filter(**TAG_USAGE_FILTERS[usage_filter][1])
    tags_qs = tags_qs.order_by(Lower('name'), 'pk')

    page_obj = Paginator(tags_qs, TAGS_PER_PAGE).get_page(request.GET.get('page'))
    # The pending/unmatched counts run every tag's conditions over every
    # rule, so only the tags on this page get them.
    tags = list(page_obj.object_list)
    counts = tag_rule_counts(tags)
    for tag in tags:
        tag.pending_count, tag.unmatched_count = counts.get(tag.pk, (0, 0))

    pagination_params = {}
    if search_query:
        pagination_params['q'] = search_query
    if category_filter:
        pagination_params['category'] = category_filter
    if usage_filter:
        pagination_params['usage'] = usage_filter

    return render(request, 'tags.html', {
        'tags': tags,
        'page_obj': page_obj,
        'has_any_tags': has_any_tags,
        'search_query': search_query,
        'category_filter': category_filter,
        'usage_filter': usage_filter,
        'categories': TagCategory.objects.order_by(Lower('name')),
        'usage_choices': [(key, label) for key, (label, _filter) in TAG_USAGE_FILTERS.items()],
        'pagination_query': urlencode(pagination_params),
        'has_filters': bool(pagination_params),
        'current_query_string': request.GET.urlencode(),
    })


@login_required
@require_http_methods(["GET", "POST"])
def tag_categories_view(request):
    """List, add, rename, recolour, reprioritise and delete tag categories.

    A category sets the colour of its tags' badges and, by its priority, their
    order on uploads list and case log rows (0 hides them there). Every tag has
    one: deleting a category moves its tags to the default category, which
    itself can be edited but not deleted.
    """
    if request.method == 'POST':
        action = request.POST.get('action', '')
        name = request.POST.get('name', '').strip()
        color = request.POST.get('color', '').strip().lower()
        raw_priority = request.POST.get('priority', '')
        if action == 'add':
            priority, message = parse_tag_category_priority(raw_priority, TagCategory.DEFAULT_PRIORITY)
            message = message or tag_category_error(name, color)
            if message:
                messages.error(request, message)
            else:
                TagCategory.objects.create(
                    name=name, color=color, priority=priority, created_by=request.user, updated_by=request.user,
                )
                messages.success(request, f'Category "{name}" added.')
        elif action in ('edit', 'delete'):
            category = get_object_or_404(TagCategory, pk=request.POST.get('pk', '').strip() or 0)
            if action == 'delete':
                if category.is_default:
                    messages.error(request, f'"{category.name}" is the default category and cannot be deleted.')
                    return redirect('tag_categories')
                default = TagCategory.get_default()
                with transaction.atomic():
                    count = category.tags.update(category=default)
                    category.delete()
                moved = '1 tag moved' if count == 1 else f'{count} tags moved'
                messages.success(request, f'Category "{category.name}" deleted; {moved} to "{default.name}".')
            else:
                priority, message = parse_tag_category_priority(raw_priority, category.priority)
                message = message or tag_category_error(name, color, exclude_pk=category.pk)
                if message:
                    messages.error(request, message)
                else:
                    category.name = name
                    category.color = color
                    category.priority = priority
                    category.updated_by = request.user
                    category.save()
                    messages.success(request, f'Category "{name}" saved.')
        else:
            messages.error(request, 'Invalid action.')
        return redirect('tag_categories')

    TagCategory.get_default()  # make sure the default row exists to be listed first
    categories = (
        TagCategory.objects.annotate(tag_count=Count('tags'))
        .select_related('updated_by')
        .order_by('-is_default', 'name')
    )
    return render(request, 'tag_categories.html', {
        'categories': categories,
        'default_color': DEFAULT_TAG_CATEGORY_COLOR,
        'default_priority': TagCategory.DEFAULT_PRIORITY,
        'priority_choices': range(TagCategory.PRIORITY_MIN, TagCategory.PRIORITY_MAX + 1),
    })


def _entry_type_choices():
    """(value, label) for every parsed entry type the rules actually have."""
    values = (
        ClassificationRule.objects.exclude(entry_type='')
        .values_list('entry_type', flat=True).distinct().order_by('entry_type')
    )
    return [(value, value.replace('_', ' ')) for value in values]


def _tag_editor(request, tag):
    status_labels = dict(ClassificationRule.STATUS_CHOICES)
    linked_ids = set(tag.speeches.values_list('pk', flat=True)) if tag else set()
    linked_snippet_ids = set(tag.snippets.values_list('pk', flat=True)) if tag else set()
    return render(request, 'rule_tag_editor.html', {
        # Every speech the user can link, for the search box; there can be
        # many, so the page shows only the linked ones and finds the rest by
        # name or category. Speeches using the tag that the user cannot link
        # are listed read-only.
        'linkable_speeches_json': [
            {
                'id': speech.pk,
                'name': speech.name if speech.owner_id == request.user.id else f'{speech.name} ({speech.owner.username})',
                'category': speech.category,
                'linked': speech.pk in linked_ids,
            }
            for speech in linkable_speeches(request.user).select_related('owner').order_by('category', 'name')
        ],
        'others_speeches': (
            tag.speeches.exclude(pk__in=linkable_speeches(request.user).values('pk'))
            .select_related('owner').order_by('name')
            if tag else []
        ),
        # The same for snippets.
        'linkable_snippets_json': [
            {
                'id': snippet.pk,
                'name': snippet.name if snippet.owner_id == request.user.id else f'{snippet.name} ({snippet.owner.username})',
                'category': snippet.category,
                'linked': snippet.pk in linked_snippet_ids,
            }
            for snippet in linkable_snippets(request.user).select_related('owner').order_by('category', 'name')
        ],
        'others_snippets': (
            tag.snippets.exclude(pk__in=linkable_snippets(request.user).values('pk'))
            .select_related('owner').order_by('name')
            if tag else []
        ),
        'tag': tag,
        'tag_json': serialize_tag(tag) if tag else None,
        'run_preview': bool(tag and not TagConditions.of(tag).is_empty),
        # "more options" opens by itself when the tag uses any of them, so
        # nothing that affects matching is hidden.
        'advanced_open': bool(tag and (
            tag.exclude_pattern or tag.match_statuses or tag.match_entry_types
            or tag.match_scope != RuleTag.SCOPE_ANY
        )),
        'scope_choices': RuleTag.SCOPE_CHOICES,
        # The default first; get_default() makes sure there is one to preselect.
        'categories': [TagCategory.get_default()] + list(
            TagCategory.objects.filter(is_default=False).order_by('name')
        ),
        # (code, label, colour variable suffix) - '!' is styled as 'w'.
        'status_choices': [
            (code, status_labels.get(code, code), 'w' if code == '!' else code.lower())
            for code in CONDITION_STATUSES
        ],
        'entry_type_choices': _entry_type_choices(),
    })


@login_required
@require_http_methods(["GET"])
def rule_tag_add_view(request):
    """Full-page editor for a new tag. Saving goes through rule_tag_save_api."""
    return _tag_editor(request, None)


@login_required
@require_http_methods(["GET"])
def rule_tag_edit_view(request, pk):
    """Full-page editor for one tag; the regex preview runs on load."""
    return _tag_editor(request, get_object_or_404(RuleTag, pk=pk))


@login_required
@require_http_methods(["GET"])
def rule_tags_api(request):
    """All tags, for the pickers. There are few enough to filter client-side."""
    return JsonResponse({'tags': [serialize_tag(tag) for tag in RuleTag.objects.select_related('category')]})


@login_required
@require_http_methods(["POST"])
def rule_tag_save_api(request):
    """Create a tag (no id) or update one (id), then optionally apply it to rules.

    Body: {id?, name, description, match_pattern?, exclude_pattern?, match_scope?,
    match_statuses?, match_entry_types?, auto_apply?, add_rule_ids?,
    remove_rule_ids?, remove_unmatched?, apply_to_existing?, speech_ids?, snippet_ids?}.
    `apply_to_existing` tags every existing rule that meets the conditions - the
    editor asks first when an auto-apply tag is saved. `speech_ids` and
    `snippet_ids` set which of the speeches and snippets the caller can link
    (own or selected for the analyzer) suggest the tag. `remove_unmatched` takes the tag off
    every tagged rule the saved conditions do not match - all of them, not only
    those a capped preview listed. Used by the tag editor, the analyzer's tag
    popover and the rule forms' "create tag" dialog, so all of them validate
    the same way.
    """
    payload, error = _json_payload(request)
    if error:
        return error

    add_ids = _id_list(payload, 'add_rule_ids')
    remove_ids = _id_list(payload, 'remove_rule_ids')
    if add_ids is None or remove_ids is None:
        return PayloadValidator.error_response('Rule id lists must contain integers.')
    for field in ('remove_unmatched', 'apply_to_existing'):
        if field in payload and not isinstance(payload[field], bool):
            return PayloadValidator.error_response(f'Field "{field}" must be a boolean.')

    tag = None
    raw_id = payload.get('id')
    if raw_id not in (None, ''):
        if isinstance(raw_id, bool) or not isinstance(raw_id, int):
            return PayloadValidator.error_response('Field "id" must be an integer.')
        tag = get_object_or_404(RuleTag, pk=raw_id)

    tag, message = save_tag(request.user, tag, payload)
    if message:
        return PayloadValidator.error_response(message)
    conditions = TagConditions.of(tag)

    if payload.get('remove_unmatched'):
        remove_ids = list(remove_ids) + unmatched_tagged_rule_ids(tag, conditions)
    if payload.get('apply_to_existing'):
        add_ids = list(add_ids) + matching_rule_ids(conditions)
    added, removed = apply_tag(tag, add_ids, remove_ids)
    return JsonResponse({'tag': serialize_tag(tag), 'added': added, 'removed': removed})


@login_required
@require_http_methods(["POST"])
def rule_tag_preview_api(request):
    """Run (possibly unsaved) tag conditions over every rule.

    Body: {pattern?, exclude_pattern?, match_scope?, match_statuses?,
    match_entry_types?, tag_id?}. `pattern` is the regex, as before.
    """
    payload, error = _json_payload(request)
    if error:
        return error

    tag = None
    tag_id = payload.get('tag_id')
    if tag_id not in (None, ''):
        if isinstance(tag_id, bool) or not isinstance(tag_id, int):
            return PayloadValidator.error_response('Field "tag_id" must be an integer.')
        tag = get_object_or_404(RuleTag, pk=tag_id)

    if 'pattern' in payload:
        payload = {**payload, 'match_pattern': payload['pattern']}
    # Unsaved editor fields are the whole condition set; nothing falls back to the tag.
    payload = {
        'match_pattern': '', 'exclude_pattern': '', 'match_scope': RuleTag.SCOPE_ANY,
        'match_statuses': [], 'match_entry_types': [], **payload,
    }
    conditions, message = conditions_from_payload(payload)
    if not message:
        message = conditions_error(conditions)
    if message:
        return PayloadValidator.error_response(message)

    return JsonResponse(preview_conditions(conditions, tag=tag))


@login_required
@require_http_methods(["POST"])
def rule_tag_suggest_api(request):
    """Tags whose conditions a rule being written meets.

    Body: {description, source_text?, status?, match_type?, exclude_ids?}. The
    entry type is derived from the (first) source line the way rule creation
    does it.
    """
    payload, error = _json_payload(request)
    if error:
        return error

    fields = {}
    for field in ('description', 'source_text', 'status', 'match_type'):
        value = payload.get(field, '')
        if not isinstance(value, str):
            return PayloadValidator.error_response(f'Field "{field}" must be a string.')
        fields[field] = value.strip()
    exclude_ids = _id_list(payload, 'exclude_ids')
    if exclude_ids is None:
        return PayloadValidator.error_response('Field "exclude_ids" must contain integers.')

    source_text = fields['source_text'].splitlines()[0].strip() if fields['source_text'] else ''
    entry_type = ''
    if source_text:
        parsed = parse_rule_line(source_text, status=fields['status'] or '?')
        entry_type = (parsed or {}).get('entry_type') or ''

    tags = suggest_tags(
        description=fields['description'], source_text=source_text,
        status=fields['status'], entry_type=entry_type, exclude_ids=exclude_ids,
    )
    return JsonResponse({'tags': [serialize_tag(tag) for tag in tags]})
