from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods

from ..models import (
    Fixlist,
    InfectionCase,
    InfectionCaseFixlist,
    InfectionCaseLog,
    UploadedLog,
)
from .utils import get_action_scoped_uploads


def _case_queryset_for_user(user):
    return InfectionCase.objects.filter(owner=user, deleted_at__isnull=True)


def _available_case_usernames_for_user(user):
    return list(
        get_action_scoped_uploads(user)
        .filter(deleted_at__isnull=True)
        .values_list('reddit_username', flat=True)
        .distinct()
        .order_by('reddit_username')
    )


def _build_case_timeline(case):
    timeline_items = []

    for link in case.log_links.select_related('uploaded_log').all():
        uploaded_log = link.uploaded_log
        if uploaded_log.deleted_at is not None:
            continue
        timeline_items.append(
            {
                'item_type': 'log',
                'created_at': uploaded_log.created_at,
                'uploaded_log': uploaded_log,
            }
        )

    for link in case.fixlist_links.select_related('fixlist').all():
        fixlist = link.fixlist
        if fixlist.deleted_at is not None:
            continue
        timeline_items.append(
            {
                'item_type': 'fixlist',
                'created_at': fixlist.created_at,
                'fixlist': fixlist,
                'line_count': len([line for line in (fixlist.content or '').splitlines() if line.strip()]),
            }
        )

    timeline_items.sort(key=lambda item: item['created_at'])
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


def _selected_items_for_case_request(request, case):
    selected_upload_ids = [value.strip() for value in request.POST.getlist('selected_upload_ids') if value.strip()]
    selected_fixlist_ids = [value.strip() for value in request.POST.getlist('selected_fixlist_ids') if value.strip()]

    scoped_uploads = get_action_scoped_uploads(request.user).filter(
        deleted_at__isnull=True,
        upload_id__in=selected_upload_ids,
    )
    scoped_fixlists = Fixlist.objects.filter(
        owner=request.user,
        deleted_at__isnull=True,
        pk__in=selected_fixlist_ids,
    )

    logs = list(scoped_uploads)
    fixlists = list(scoped_fixlists)

    mismatched_logs = [log for log in logs if log.reddit_username != case.username]
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
    cases = list(
        _case_queryset_for_user(request.user)
        .prefetch_related('log_links__uploaded_log', 'fixlist_links__fixlist')
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
        case.item_count = len(visible_logs) + len(visible_fixlists)
        case.last_activity = max(
            [case.created_at, *[item.created_at for item in visible_logs], *[item.created_at for item in visible_fixlists]]
        )

    return render(request, 'infection_cases.html', {'cases': cases})


@login_required
@require_http_methods(['GET', 'POST'])
def create_infection_case_view(request):
    username_choices = _available_case_usernames_for_user(request.user)

    if request.method == 'POST':
        username = (request.POST.get('username') or '').strip()
        symptom_description = (request.POST.get('symptom_description') or '').strip()
        reference_url = (request.POST.get('reference_url') or '').strip()
        auto_assign_new_items = (request.POST.get('auto_assign_new_items') or '').strip().lower() in {'1', 'true', 'on', 'yes'}

        infection_case = InfectionCase(
            owner=request.user,
            username=username,
            symptom_description=symptom_description,
            reference_url=reference_url,
            auto_assign_new_items=auto_assign_new_items,
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
                    'username_choices': username_choices,
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
            'prefill_auto_assign_new_items': True,
        },
    )


@login_required
@require_http_methods(['GET', 'POST'])
def view_infection_case(request, case_id):
    infection_case = get_object_or_404(_case_queryset_for_user(request.user), case_id=case_id)
    show_add_picker = (request.GET.get('add') or '').strip().lower() in {'1', 'true', 'on', 'yes'}
    show_metadata_edit = (request.GET.get('edit_meta') or '').strip().lower() in {'1', 'true', 'on', 'yes'}

    if request.method == 'POST':
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
            scoped_logs = list(
                get_action_scoped_uploads(request.user).filter(
                    deleted_at__isnull=True,
                    reddit_username=infection_case.username,
                )
            )
            owned_fixlists = list(
                Fixlist.objects.filter(
                    owner=request.user,
                    deleted_at__isnull=True,
                    username=infection_case.username,
                )
            )
            _link_case_items(infection_case, scoped_logs, owned_fixlists, request.user)
            messages.success(
                request,
                f'Added logs/fixlists for u/{infection_case.username} to this case.',
            )
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

    linked_logs = list(
        UploadedLog.objects.filter(
            infection_case_links__case=infection_case,
            deleted_at__isnull=True,
        )
        .distinct()
        .order_by('-created_at')
    )
    linked_fixlists = list(
        Fixlist.objects.filter(
            infection_case_links__case=infection_case,
            deleted_at__isnull=True,
        )
        .distinct()
        .order_by('-created_at')
    )

    timeline_items = _build_case_timeline(infection_case)

    selectable_uploads = []
    selectable_fixlists = []
    if show_add_picker:
        available_uploads = get_action_scoped_uploads(request.user).filter(deleted_at__isnull=True)
        available_fixlists = Fixlist.objects.filter(owner=request.user, deleted_at__isnull=True)

        linked_upload_ids = {uploaded_log.upload_id for uploaded_log in linked_logs}
        linked_fixlist_ids = {fixlist.pk for fixlist in linked_fixlists}

        selectable_uploads = available_uploads.exclude(upload_id__in=linked_upload_ids)
        selectable_fixlists = available_fixlists.exclude(pk__in=linked_fixlist_ids)

    return render(
        request,
        'view_infection_case.html',
        {
            'infection_case': infection_case,
            'timeline_items': timeline_items,
            'selectable_uploads': selectable_uploads,
            'selectable_fixlists': selectable_fixlists,
            'case_status_choices': InfectionCase.STATUS_CHOICES,
            'show_add_picker': show_add_picker,
            'show_metadata_edit': show_metadata_edit,
        },
    )


@login_required
@require_http_methods(['POST'])
def infection_case_add_items_view(request, case_id):
    infection_case = get_object_or_404(_case_queryset_for_user(request.user), case_id=case_id)
    selection = _selected_items_for_case_request(request, infection_case)

    if not selection['logs'] and not selection['fixlists']:
        messages.error(request, 'Select at least one item to add.')
        return redirect('view_infection_case', case_id=infection_case.case_id)

    if selection['mismatched_logs'] or selection['mismatched_fixlists']:
        return render(
            request,
            'confirm_case_username_change.html',
            {
                'infection_case': infection_case,
                'selected_upload_ids': selection['selected_upload_ids'],
                'selected_fixlist_ids': selection['selected_fixlist_ids'],
                'mismatched_logs': selection['mismatched_logs'],
                'mismatched_fixlists': selection['mismatched_fixlists'],
            },
        )

    with transaction.atomic():
        _link_case_items(infection_case, selection['logs'], selection['fixlists'], request.user)

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
            uploaded_log.reddit_username = infection_case.username
            uploaded_log.save(update_fields=['reddit_username', 'updated_at'])

        for fixlist in selection['mismatched_fixlists']:
            fixlist.username = infection_case.username
            fixlist.save(update_fields=['username', 'updated_at'])

        _link_case_items(infection_case, selection['logs'], selection['fixlists'], request.user)

    messages.success(
        request,
        f'Updated selected usernames to u/{infection_case.username} and added items to the case.',
    )
    return redirect('view_infection_case', case_id=infection_case.case_id)
