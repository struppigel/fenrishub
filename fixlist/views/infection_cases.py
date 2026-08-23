from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Prefetch
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import urlencode
from django.views.decorators.http import require_http_methods

from ..models import (
    Fixlist,
    InfectionCase,
    InfectionCaseFixlist,
    InfectionCaseLog,
    InfectionCaseNote,
    InfectionCaseResponse,
    UploadedLog,
)
from ..upload_utils import execute_merge, resolve_ordered_logs_for_merge
from .utils import (
    _autoclose_stale_cases,
    _purge_old_trash,
    build_uploaded_logs_zip,
    get_action_scoped_uploads,
)


def _case_queryset_for_user(user):
    return InfectionCase.objects.filter(owner=user, deleted_at__isnull=True)


def _available_case_usernames_for_user(user):
    return list(
        get_action_scoped_uploads(user)
        .filter(deleted_at__isnull=True)
        .values_list('forum_username', flat=True)
        .distinct()
        .order_by('forum_username')
    )


def _build_case_timeline(case):
    base_items = []

    # InfectionCaseLog pks whose log is still present (not soft-deleted). A note
    # anchored to a log not in this set has lost its anchor and floats instead.
    present_log_link_pks = set()

    for link in case.log_links.select_related('uploaded_log').defer('uploaded_log__content').all():
        uploaded_log = link.uploaded_log
        if uploaded_log.deleted_at is not None:
            continue
        present_log_link_pks.add(link.pk)
        base_items.append(
            {
                'item_type': 'log',
                'created_at': uploaded_log.created_at,
                'uploaded_log': uploaded_log,
                '_log_link_pk': link.pk,
            }
        )

    # InfectionCaseFixlist / InfectionCaseResponse pks whose target is still
    # present, for the same anchor-resolution reason as the logs above.
    present_fixlist_link_pks = set()
    present_response_link_pks = set()

    for link in case.fixlist_links.select_related('fixlist').defer('fixlist__content').all():
        fixlist = link.fixlist
        if fixlist.deleted_at is not None:
            continue
        present_fixlist_link_pks.add(link.pk)
        base_items.append(
            {
                'item_type': 'fixlist',
                'created_at': fixlist.created_at,
                'fixlist': fixlist,
                'line_count': fixlist.line_count,
                '_fixlist_link_pk': link.pk,
            }
        )

    # A response is its own item: it has its own link row and sorts by when it was
    # written, not by anything about the fixlist it belongs to.
    for link in case.response_links.select_related('fixlist').defer('fixlist__content').all():
        fixlist = link.fixlist
        if fixlist.deleted_at is not None or not (fixlist.response or '').strip():
            continue
        present_response_link_pks.add(link.pk)
        # A response cannot predate the fixlist it belongs to, so clamp to the
        # fixlist's creation time. Without this a response saved together with a
        # brand-new fixlist sorts microseconds ahead of it, because the stamp is
        # taken just before the row gets its auto_now_add created_at.
        written_at = fixlist.response_created_at or fixlist.updated_at
        base_items.append(
            {
                'item_type': 'response',
                'created_at': max(written_at, fixlist.created_at),
                'fixlist': fixlist,
                '_response_link_pk': link.pk,
            }
        )

    # All notes, including soft-deleted ones: deleted notes are never rendered
    # themselves, but act as transparent pass-throughs when resolving anchors so
    # their children re-home to the nearest surviving item instead of vanishing.
    notes_by_pk = {
        note.pk: note
        for note in case.note_entries.select_related(
            'anchor_log', 'anchor_fixlist', 'anchor_response', 'anchor_note'
        ).all()
    }

    def _resolve_anchor(note, seen):
        # -> ('log'|'fixlist'|'response', link_pk) | ('note', live_note_pk) | ('float', None)
        if note.anchor_log_id is not None:
            if note.anchor_log_id in present_log_link_pks:
                return ('log', note.anchor_log_id)
            return ('float', None)
        if note.anchor_fixlist_id is not None:
            if note.anchor_fixlist_id in present_fixlist_link_pks:
                return ('fixlist', note.anchor_fixlist_id)
            return ('float', None)
        if note.anchor_response_id is not None:
            if note.anchor_response_id in present_response_link_pks:
                return ('response', note.anchor_response_id)
            return ('float', None)
        if note.anchor_note_id is not None:
            parent = notes_by_pk.get(note.anchor_note_id)
            if parent is None or note.anchor_note_id in seen:
                return ('float', None)
            if parent.deleted_at is None:
                return ('note', parent.pk)
            seen.add(note.anchor_note_id)
            return _resolve_anchor(parent, seen)  # skip over the deleted ancestor
        return ('float', None)

    # Separate anchored and unanchored notes by their *effective* anchor.
    log_anchored_notes = {}  # InfectionCaseLog pk -> list of note dicts
    fixlist_anchored_notes = {}  # InfectionCaseFixlist pk -> list of note dicts
    response_anchored_notes = {}  # InfectionCaseResponse pk -> list of note dicts
    note_anchored_notes = {}  # live InfectionCaseNote pk -> list of note dicts
    unanchored_notes = []

    anchored_by_kind = {
        'log': log_anchored_notes,
        'fixlist': fixlist_anchored_notes,
        'response': response_anchored_notes,
        'note': note_anchored_notes,
    }

    for note in notes_by_pk.values():
        if note.deleted_at is not None:
            continue
        note_dict = {
            'item_type': 'note',
            'created_at': note.created_at,
            'note': note,
        }
        kind, target_pk = _resolve_anchor(note, set())
        if kind in anchored_by_kind:
            anchored_by_kind[kind].setdefault(target_pk, []).append(note_dict)
        else:
            unanchored_notes.append(note_dict)

    base_items.extend(unanchored_notes)
    base_items.sort(key=lambda item: item['created_at'])

    # Promoted children and original children share a sibling list, so sort each
    # by creation time to keep the spliced order chronological.
    for anchored_notes in anchored_by_kind.values():
        for pinned_notes in anchored_notes.values():
            pinned_notes.sort(key=lambda item: item['created_at'])

    # Recursively collect notes anchored to a given note.
    def _collect_note_children(note_pk):
        children = []
        for pinned in note_anchored_notes.get(note_pk, []):
            children.append(pinned)
            children.extend(_collect_note_children(pinned['note'].pk))
        return children

    # Splice anchored notes immediately after their anchor entry.
    anchor_key_by_type = {
        'log': ('_log_link_pk', log_anchored_notes),
        'fixlist': ('_fixlist_link_pk', fixlist_anchored_notes),
        'response': ('_response_link_pk', response_anchored_notes),
    }

    timeline_items = []
    for item in base_items:
        timeline_items.append(item)
        anchor = anchor_key_by_type.get(item['item_type'])
        if anchor is not None:
            link_key, anchored_notes = anchor
            for pinned in anchored_notes.get(item[link_key], []):
                timeline_items.append(pinned)
                timeline_items.extend(_collect_note_children(pinned['note'].pk))
        if item['item_type'] == 'note':
            timeline_items.extend(_collect_note_children(item['note'].pk))

    # Strip internal helper keys before returning.
    for item in timeline_items:
        item.pop('_log_link_pk', None)
        item.pop('_fixlist_link_pk', None)
        item.pop('_response_link_pk', None)

    return timeline_items


def _link_case_items(case, logs, fixlists, added_by):
    InfectionCaseLog.objects.bulk_create(
        [
            InfectionCaseLog(case=case, uploaded_log=uploaded_log, added_by=added_by)
            for uploaded_log in logs
        ],
        ignore_conflicts=True,
    )
    InfectionCaseFixlist.objects.bulk_create(
        [
            InfectionCaseFixlist(case=case, fixlist=fixlist, added_by=added_by)
            for fixlist in fixlists
        ],
        ignore_conflicts=True,
    )
    if not case.is_training:
        unassigned_log_pks = [log.pk for log in logs if log.recipient_user_id is None]
        if unassigned_log_pks:
            UploadedLog.objects.filter(pk__in=unassigned_log_pks).update(recipient_user=case.owner)


def _selected_response_ids(request):
    """Fixlist pks whose response entry should be put back on the timeline.

    Non-numeric values are dropped rather than passed to the ORM, which would
    raise ValueError on the pk lookup.
    """
    return [
        value.strip()
        for value in request.POST.getlist('selected_response_ids')
        if value.strip().isdigit()
    ]


def _link_case_responses(case, response_ids, added_by):
    """Link responses to a case. The response text itself is never touched."""
    if not response_ids:
        return 0
    fixlists = Fixlist.objects.filter(
        owner=case.owner,
        deleted_at__isnull=True,
        pk__in=response_ids,
    ).exclude(response='').only('id')
    created = InfectionCaseResponse.objects.bulk_create(
        [InfectionCaseResponse(case=case, fixlist=fixlist, added_by=added_by) for fixlist in fixlists],
        ignore_conflicts=True,
    )
    return len(created)


def _case_log_queryset(case):
    """Logs currently linked to `case` and not soft-deleted. Used as the
    scope queryset for merge actions launched from the case detail view."""
    return UploadedLog.objects.filter(
        infection_case_links__case=case,
        deleted_at__isnull=True,
    )


def _execute_case_merge(case, ordered_logs, forum_username, user):
    """Run a merge for logs linked to `case` and ensure the result lands on the timeline."""
    merged_log = execute_merge(
        ordered_logs=ordered_logs,
        forum_username=forum_username,
        recipient_user=case.owner,
        created_by=user,
    )
    InfectionCaseLog.objects.get_or_create(
        case=case,
        uploaded_log=merged_log,
        defaults={'added_by': user},
    )
    _purge_old_trash()
    return merged_log


def _selected_items_for_case_request(request, case):
    selected_upload_ids = [value.strip() for value in request.POST.getlist('selected_upload_ids') if value.strip()]
    selected_fixlist_ids = [value.strip() for value in request.POST.getlist('selected_fixlist_ids') if value.strip()]

    if case.is_training:
        scoped_uploads = UploadedLog.objects.filter(
            deleted_at__isnull=True,
            upload_id__in=selected_upload_ids,
        ).defer('content')
    else:
        scoped_uploads = get_action_scoped_uploads(request.user).filter(
            deleted_at__isnull=True,
            upload_id__in=selected_upload_ids,
        ).defer('content')
    scoped_fixlists = Fixlist.objects.filter(
        owner=request.user,
        deleted_at__isnull=True,
        pk__in=selected_fixlist_ids,
    ).defer('content')

    logs = list(scoped_uploads)
    fixlists = list(scoped_fixlists)

    mismatched_logs = [log for log in logs if log.forum_username != case.username]
    mismatched_fixlists = [fixlist for fixlist in fixlists if fixlist.username != case.username]

    return {
        'logs': logs,
        'fixlists': fixlists,
        'selected_upload_ids': selected_upload_ids,
        'selected_fixlist_ids': selected_fixlist_ids,
        'mismatched_logs': mismatched_logs,
        'mismatched_fixlists': mismatched_fixlists,
    }


@login_required
@require_http_methods(['GET'])
def infection_cases_view(request):
    _autoclose_stale_cases()
    cases = list(
        _case_queryset_for_user(request.user)
        .prefetch_related(
            Prefetch('log_links__uploaded_log', queryset=UploadedLog.objects.defer('content')),
            Prefetch('fixlist_links__fixlist', queryset=Fixlist.objects.defer('content')),
            Prefetch('response_links__fixlist', queryset=Fixlist.objects.defer('content')),
            'note_entries',
        )
    )

    for case in cases:
        visible_logs = [
            link.uploaded_log
            for link in case.log_links.all()
            if link.uploaded_log.deleted_at is None
        ]
        visible_fixlists = [
            link.fixlist
            for link in case.fixlist_links.all()
            if link.fixlist.deleted_at is None
        ]
        # Responses are timeline items of their own, so they must count here too
        # or this number disagrees with the "N linked items" on the case itself.
        visible_responses = [
            link.fixlist
            for link in case.response_links.all()
            if link.fixlist.deleted_at is None and (link.fixlist.response or '').strip()
        ]
        visible_notes = [
            note
            for note in case.note_entries.all()
            if note.deleted_at is None
        ]
        case.item_count = (
            len(visible_logs) + len(visible_fixlists) + len(visible_responses) + len(visible_notes)
        )
        case.last_activity = max(
            [
                case.created_at,
                *[item.created_at for item in visible_logs],
                *[item.created_at for item in visible_fixlists],
                *[item.created_at for item in visible_notes],
            ]
        )

    return render(request, 'infection_cases.html', {'cases': cases})


@login_required
@require_http_methods(['GET', 'POST'])
def create_infection_case_view(request):
    username_choices = _available_case_usernames_for_user(request.user)
    all_username_choices = list(
        UploadedLog.objects.filter(deleted_at__isnull=True)
        .values_list('forum_username', flat=True)
        .distinct()
        .order_by('forum_username')
    )

    if request.method == 'POST':
        username = (request.POST.get('username') or '').strip()
        symptom_description = (request.POST.get('symptom_description') or '').strip()
        reference_url = (request.POST.get('reference_url') or '').strip()
        auto_assign_new_items = (request.POST.get('auto_assign_new_items') or '').strip().lower() in {'1', 'true', 'on', 'yes'}
        is_training = (request.POST.get('is_training') or '').strip().lower() in {'1', 'true', 'on', 'yes'}

        infection_case = InfectionCase(
            owner=request.user,
            username=username,
            symptom_description=symptom_description,
            reference_url=reference_url,
            auto_assign_new_items=auto_assign_new_items,
            is_training=is_training,
        )

        try:
            infection_case.full_clean()
        except ValidationError as exc:
            for field_errors in exc.message_dict.values():
                for message in field_errors:
                    messages.error(request, message)
            return render(
                request,
                'create_infection_case.html',
                {
                    'prefill_username': username,
                    'prefill_symptom_description': symptom_description,
                    'prefill_reference_url': reference_url,
                    'prefill_auto_assign_new_items': auto_assign_new_items,
                    'prefill_is_training': is_training,
                    'username_choices': username_choices,
                    'all_username_choices': all_username_choices,
                },
            )

        infection_case.save()
        messages.success(request, f'Infection case {infection_case.case_id} created.')
        return redirect('view_infection_case', case_id=infection_case.case_id)

    return render(
        request,
        'create_infection_case.html',
        {
            'username_choices': username_choices,
            'all_username_choices': all_username_choices,
            'prefill_auto_assign_new_items': True,
            'prefill_is_training': True,
        },
    )


@login_required
@require_http_methods(['GET', 'POST'])
def view_infection_case(request, case_id):
    # Any authenticated helper holding the link can read a case; only the owner
    # can mutate. Soft-deleted cases stay hidden from non-owners.
    infection_case = get_object_or_404(
        InfectionCase.objects.filter(deleted_at__isnull=True),
        case_id=case_id,
    )
    can_edit = infection_case.owner_id == request.user.id
    show_metadata_edit = can_edit and (request.GET.get('edit_meta') or '').strip().lower() in {'1', 'true', 'on', 'yes'}

    if request.method == 'POST':
        if not can_edit:
            messages.error(request, 'Only the owner of this case can modify it.')
            return redirect('view_infection_case', case_id=infection_case.case_id)
        action = (request.POST.get('action') or '').strip()

        if action == 'update_case':
            infection_case.symptom_description = (request.POST.get('symptom_description') or '').strip()
            infection_case.reference_url = (request.POST.get('reference_url') or '').strip()
            requested_status = (request.POST.get('status') or '').strip()
            infection_case.auto_assign_new_items = (request.POST.get('auto_assign_new_items') or '').strip().lower() in {'1', 'true', 'on', 'yes'}
            if requested_status in {InfectionCase.STATUS_OPEN, InfectionCase.STATUS_CLOSED}:
                infection_case.status = requested_status
            try:
                infection_case.full_clean()
            except ValidationError as exc:
                for field_errors in exc.message_dict.values():
                    for message in field_errors:
                        messages.error(request, message)
            else:
                infection_case.save()
                messages.success(request, 'Case details updated.')
            return redirect('view_infection_case', case_id=infection_case.case_id)

        if action == 'seed_username_items':
            if infection_case.is_training:
                scoped_logs = list(
                    UploadedLog.objects.filter(
                        deleted_at__isnull=True,
                        forum_username=infection_case.username,
                    ).defer('content')
                )
            else:
                scoped_logs = list(
                    get_action_scoped_uploads(request.user).filter(
                        deleted_at__isnull=True,
                        forum_username=infection_case.username,
                    ).defer('content')
                )
            owned_fixlists = list(
                Fixlist.objects.filter(
                    owner=request.user,
                    deleted_at__isnull=True,
                    username=infection_case.username,
                )
            )
            # Responses are separate items, so seeding has to link them too or
            # "add all items" quietly leaves them out.
            response_ids = [fixlist.pk for fixlist in owned_fixlists if (fixlist.response or '').strip()]
            with transaction.atomic():
                _link_case_items(infection_case, scoped_logs, owned_fixlists, request.user)
                _link_case_responses(infection_case, response_ids, request.user)
            messages.success(
                request,
                f'Added logs, fixlists and responses for u/{infection_case.username} to this case.',
            )
            return redirect('view_infection_case', case_id=infection_case.case_id)

        if action == 'add_note':
            note_content = (request.POST.get('note_content') or '').strip()
            if not note_content:
                messages.error(request, 'Note cannot be empty.')
                return redirect('view_infection_case', case_id=infection_case.case_id)
            anchor_log_upload_id = (request.POST.get('anchor_log_upload_id') or '').strip()
            anchor_fixlist_id = (request.POST.get('anchor_fixlist_id') or '').strip()
            anchor_response_id = (request.POST.get('anchor_response_id') or '').strip()
            anchor_note_id = (request.POST.get('anchor_note_id') or '').strip()
            anchor_log = None
            anchor_fixlist = None
            anchor_response = None
            anchor_note = None
            if anchor_log_upload_id:
                anchor_log = InfectionCaseLog.objects.filter(
                    case=infection_case,
                    uploaded_log__upload_id=anchor_log_upload_id,
                ).first()
            elif anchor_fixlist_id.isdigit():
                anchor_fixlist = InfectionCaseFixlist.objects.filter(
                    case=infection_case,
                    fixlist__pk=anchor_fixlist_id,
                ).first()
            elif anchor_response_id.isdigit():
                anchor_response = InfectionCaseResponse.objects.filter(
                    case=infection_case,
                    fixlist__pk=anchor_response_id,
                ).first()
            elif anchor_note_id:
                anchor_note = InfectionCaseNote.objects.filter(
                    case=infection_case,
                    pk=anchor_note_id,
                    deleted_at__isnull=True,
                ).first()
            InfectionCaseNote.objects.create(
                case=infection_case,
                content=note_content,
                anchor_log=anchor_log,
                anchor_fixlist=anchor_fixlist,
                anchor_response=anchor_response,
                anchor_note=anchor_note,
                created_by=request.user,
            )
            messages.success(request, 'Note added to timeline.')
            return redirect('view_infection_case', case_id=infection_case.case_id)

        if action == 'unlink_log':
            upload_id = (request.POST.get('upload_id') or '').strip()
            deleted_count, _ = InfectionCaseLog.objects.filter(
                case=infection_case,
                uploaded_log__upload_id=upload_id,
            ).delete()
            if deleted_count:
                messages.success(request, f'Log {upload_id} was removed from this case.')
            else:
                messages.error(request, 'The selected log is not linked to this case.')
            return redirect('view_infection_case', case_id=infection_case.case_id)

        if action == 'unlink_fixlist':
            fixlist_id = (request.POST.get('fixlist_id') or '').strip()
            deleted_count, _ = InfectionCaseFixlist.objects.filter(
                case=infection_case,
                fixlist__pk=fixlist_id,
            ).delete()
            if deleted_count:
                messages.success(request, f'Fixlist #{fixlist_id} was removed from this case.')
            else:
                messages.error(request, 'The selected fixlist is not linked to this case.')
            return redirect('view_infection_case', case_id=infection_case.case_id)

        if action == 'unlink_response':
            # Detaches only the response. The fixlist stays in the case and the
            # response text itself is never touched.
            fixlist_id = (request.POST.get('fixlist_id') or '').strip()
            updated, _ = InfectionCaseResponse.objects.filter(
                case=infection_case,
                fixlist__pk=fixlist_id,
            ).delete()
            if updated:
                messages.success(request, f'Response of fixlist #{fixlist_id} was removed from this case.')
            else:
                messages.error(request, 'The selected response is not linked to this case.')
            return redirect('view_infection_case', case_id=infection_case.case_id)

        if action == 'edit_note':
            note_id = (request.POST.get('note_id') or '').strip()
            note_content = (request.POST.get('note_content') or '').strip()
            if not note_content:
                messages.error(request, 'Note cannot be empty.')
                return redirect('view_infection_case', case_id=infection_case.case_id)
            try:
                note = InfectionCaseNote.objects.get(
                    case=infection_case,
                    pk=note_id,
                    deleted_at__isnull=True,
                )
                note.content = note_content
                note.save()
                messages.success(request, 'Note updated.')
            except InfectionCaseNote.DoesNotExist:
                messages.error(request, 'The selected note does not exist or has already been deleted.')
            return redirect('view_infection_case', case_id=infection_case.case_id)

        if action in {'merge_logs', 'confirm_merge_logs'}:
            selected_ids = []
            seen_ids = set()
            for upload_id in request.POST.getlist('selected_upload_ids'):
                normalized_id = str(upload_id).strip()
                if not normalized_id or normalized_id in seen_ids:
                    continue
                seen_ids.add(normalized_id)
                selected_ids.append(normalized_id)

            case_logs_qs = _case_log_queryset(infection_case)
            ordered_logs, error_message = resolve_ordered_logs_for_merge(selected_ids, case_logs_qs)
            if error_message:
                messages.error(request, error_message)
                return redirect('view_infection_case', case_id=infection_case.case_id)

            case_url = reverse('view_infection_case', args=[infection_case.case_id])

            if action == 'merge_logs':
                usernames = sorted({log.forum_username for log in ordered_logs})
                if len(usernames) > 1:
                    return render(
                        request,
                        'merge_username_selection.html',
                        {
                            'selected_logs': ordered_logs,
                            'selected_upload_ids': selected_ids,
                            'usernames': usernames,
                            'confirm_action': 'confirm_merge_logs',
                            'submit_url': case_url,
                            'cancel_url': case_url,
                        },
                    )
                merged_log = _execute_case_merge(
                    infection_case, ordered_logs, usernames[0], request.user,
                )
                messages.success(request, f'Merged log created with id {merged_log.upload_id}.')
                return redirect('view_infection_case', case_id=infection_case.case_id)

            selected_username = (request.POST.get('selected_username') or '').strip()
            if not selected_username:
                messages.error(request, 'Please select a username.')
                return redirect('view_infection_case', case_id=infection_case.case_id)
            available_usernames = {log.forum_username for log in ordered_logs}
            if selected_username not in available_usernames:
                messages.error(request, 'Invalid username selection.')
                return redirect('view_infection_case', case_id=infection_case.case_id)
            merged_log = _execute_case_merge(
                infection_case, ordered_logs, selected_username, request.user,
            )
            messages.success(request, f'Merged log created with id {merged_log.upload_id}.')
            return redirect('view_infection_case', case_id=infection_case.case_id)

        if action == 'delete_note':
            note_id = (request.POST.get('note_id') or '').strip()
            try:
                note = InfectionCaseNote.objects.get(
                    case=infection_case,
                    pk=note_id,
                    deleted_at__isnull=True,
                )
                note.deleted_at = timezone.now()
                note.save()
                messages.success(request, 'Note deleted.')
            except InfectionCaseNote.DoesNotExist:
                messages.error(request, 'The selected note does not exist or has already been deleted.')
            return redirect('view_infection_case', case_id=infection_case.case_id)

    linked_logs = list(
        UploadedLog.objects.filter(
            infection_case_links__case=infection_case,
            deleted_at__isnull=True,
        )
        .defer('content')
        .distinct()
        .order_by('-created_at')
    )
    linked_fixlists = list(
        Fixlist.objects.filter(
            infection_case_links__case=infection_case,
            deleted_at__isnull=True,
        )
        .defer('content')
        .distinct()
        .order_by('-created_at')
    )

    timeline_items = _build_case_timeline(infection_case)

    selectable_uploads = UploadedLog.objects.none()
    selectable_fixlists = Fixlist.objects.none()
    selectable_responses = Fixlist.objects.none()
    if can_edit:
        if infection_case.is_training:
            available_uploads = UploadedLog.objects.filter(deleted_at__isnull=True).defer('content')
        else:
            available_uploads = get_action_scoped_uploads(request.user).filter(deleted_at__isnull=True).defer('content')
        available_fixlists = Fixlist.objects.filter(owner=request.user, deleted_at__isnull=True).defer('content')

        linked_upload_ids = {uploaded_log.upload_id for uploaded_log in linked_logs}
        linked_fixlist_ids = {fixlist.pk for fixlist in linked_fixlists}

        selectable_uploads = available_uploads.exclude(upload_id__in=linked_upload_ids)
        selectable_fixlists = available_fixlists.exclude(pk__in=linked_fixlist_ids)

        # Any of the helper's responses that this case does not hold yet. Listed
        # separately from fixlists because the two are linked independently.
        linked_response_ids = set(
            infection_case.response_links.values_list('fixlist_id', flat=True)
        )
        selectable_responses = (
            available_fixlists.exclude(response='').exclude(pk__in=linked_response_ids)
        )

    # Upload link handed to the affected user: it targets the case owner's
    # channel so new logs land with the helper who owns the case, and prefills
    # the forum username the case is tracked under.
    helper_upload_url = request.build_absolute_uri(
        reverse('upload_log_for_helper', args=[infection_case.owner.username])
        + '?' + urlencode({'u': infection_case.username})
    )

    return render(
        request,
        'view_infection_case.html',
        {
            'infection_case': infection_case,
            'helper_upload_url': helper_upload_url,
            'timeline_items': timeline_items,
            'selectable_uploads': selectable_uploads,
            'selectable_fixlists': selectable_fixlists,
            'selectable_responses': selectable_responses,
            'case_status_choices': InfectionCase.STATUS_CHOICES,
            'show_metadata_edit': show_metadata_edit,
            'can_edit': can_edit,
        },
    )


@login_required
@require_http_methods(['GET'])
def infection_case_download_logs_view(request, case_id):
    """Download every log linked to a case bundled into a single zip archive."""
    infection_case = get_object_or_404(
        InfectionCase.objects.filter(deleted_at__isnull=True),
        case_id=case_id,
    )

    linked_logs = list(
        UploadedLog.objects.filter(
            infection_case_links__case=infection_case,
            deleted_at__isnull=True,
        )
        .distinct()
        .order_by('created_at')
    )

    if not linked_logs:
        messages.error(request, 'This case has no logs to download.')
        return redirect('view_infection_case', case_id=infection_case.case_id)

    response = HttpResponse(build_uploaded_logs_zip(linked_logs), content_type='application/zip')
    response['Content-Disposition'] = f'attachment; filename="{infection_case.case_id}_logs.zip"'
    return response


@login_required
@require_http_methods(['POST'])
def infection_case_add_items_view(request, case_id):
    infection_case = get_object_or_404(_case_queryset_for_user(request.user), case_id=case_id)
    selection = _selected_items_for_case_request(request, infection_case)

    # Re-attaching a previously unlinked response only flips a flag on a link row
    # that already exists, so it needs none of the username-mismatch handling below.
    # It is applied with the rest of the selection, never before it: bailing out to
    # the confirm screen must not leave a half-applied change behind.
    response_ids = _selected_response_ids(request)

    if not selection['logs'] and not selection['fixlists'] and not response_ids:
        messages.error(request, 'Select at least one item to add.')
        return redirect('view_infection_case', case_id=infection_case.case_id)

    if not infection_case.is_training and (selection['mismatched_logs'] or selection['mismatched_fixlists']):
        return render(
            request,
            'confirm_case_username_change.html',
            {
                'infection_case': infection_case,
                'selected_upload_ids': selection['selected_upload_ids'],
                'selected_fixlist_ids': selection['selected_fixlist_ids'],
                'selected_response_ids': response_ids,
                'mismatched_logs': selection['mismatched_logs'],
                'mismatched_fixlists': selection['mismatched_fixlists'],
            },
        )

    with transaction.atomic():
        _link_case_items(infection_case, selection['logs'], selection['fixlists'], request.user)
        _link_case_responses(infection_case, response_ids, request.user)

    messages.success(request, 'Selected items were added to this infection case.')
    return redirect('view_infection_case', case_id=infection_case.case_id)


@login_required
@require_http_methods(['POST'])
def infection_case_confirm_username_change_view(request, case_id):
    infection_case = get_object_or_404(_case_queryset_for_user(request.user), case_id=case_id)
    selection = _selected_items_for_case_request(request, infection_case)

    if not selection['logs'] and not selection['fixlists']:
        messages.error(request, 'No valid items selected.')
        return redirect('view_infection_case', case_id=infection_case.case_id)

    with transaction.atomic():
        for uploaded_log in selection['mismatched_logs']:
            uploaded_log.forum_username = infection_case.username
            uploaded_log.save(update_fields=['forum_username', 'updated_at'])

        for fixlist in selection['mismatched_fixlists']:
            fixlist.username = infection_case.username
            fixlist.save(update_fields=['username', 'updated_at'])

        _link_case_items(infection_case, selection['logs'], selection['fixlists'], request.user)
        _link_case_responses(infection_case, _selected_response_ids(request), request.user)

    messages.success(
        request,
        f'Updated selected usernames to u/{infection_case.username} and added items to the case.',
    )
    return redirect('view_infection_case', case_id=infection_case.case_id)


@login_required
@require_http_methods(['GET', 'POST'])
def infection_case_delete_view(request, case_id):
    infection_case = get_object_or_404(_case_queryset_for_user(request.user), case_id=case_id)

    linked_log_ids = list(
        UploadedLog.objects.filter(
            infection_case_links__case=infection_case,
            deleted_at__isnull=True,
        )
        .values_list('pk', flat=True)
        .distinct()
    )
    linked_fixlist_ids = list(
        Fixlist.objects.filter(
            infection_case_links__case=infection_case,
            deleted_at__isnull=True,
        )
        .values_list('pk', flat=True)
        .distinct()
    )

    if request.method == 'POST':
        move_linked_to_trash = (request.POST.get('move_linked_to_trash') or '').strip().lower() in {'1', 'true', 'on', 'yes'}
        deleted_at = timezone.now()

        trashed_logs = 0
        trashed_fixlists = 0
        with transaction.atomic():
            if move_linked_to_trash:
                # Deletion-protected items stay put; the case itself is still deleted.
                trashed_logs = UploadedLog.objects.filter(
                    pk__in=linked_log_ids, deleted_at__isnull=True, is_protected=False,
                ).update(deleted_at=deleted_at)
                trashed_fixlists = Fixlist.objects.filter(
                    pk__in=linked_fixlist_ids, deleted_at__isnull=True, is_protected=False,
                ).update(deleted_at=deleted_at)

            infection_case.deleted_at = deleted_at
            infection_case.save(update_fields=['deleted_at', 'updated_at'])

        if move_linked_to_trash:
            messages.success(
                request,
                f'Case {infection_case.case_id} deleted. Moved {trashed_logs} log(s) and {trashed_fixlists} fixlist(s) to trash.',
            )
        else:
            messages.success(request, f'Case {infection_case.case_id} deleted.')
        return redirect('infection_cases')

    return render(
        request,
        'confirm_delete_infection_case.html',
        {
            'infection_case': infection_case,
            'linked_log_count': len(linked_log_ids),
            'linked_fixlist_count': len(linked_fixlist_ids),
        },
    )
