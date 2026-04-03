"""
Uploaded log management views.

Handles: uploading logs, viewing, diffing, merging, trashing, restoring, and managing uploaded logs.
"""

import difflib
import traceback
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.urls import reverse
from django.db.models import Count
from urllib.parse import urlencode

from ..forms import UploadedLogForm
from ..models import UploadedLog
from ..permissions import user_can_delete_uploaded_log
from ..upload_utils import soft_delete_uploaded_log, restore_uploaded_log, execute_merge
from .upload_actions import (
    handle_delete_action, handle_assign_to_me_action, handle_unassign_to_general_action,
    handle_delete_selected_action, handle_merge_action, handle_confirm_merge_action,
    handle_rescan_stats_all_action,
)
from .utils import (
    _anonymous_upload_limit, _consume_anonymous_upload_slot, _resolve_upload_recipient_username,
    get_action_scoped_uploads, get_updatable_uploads, get_client_ip, _purge_old_trash,
)


@require_http_methods(["GET", "POST"])
def upload_log_view(request, helper_username=None):
    """Public upload endpoint for text logs."""
    uploaded_log_id = None
    uploaded_original_filename = None
    upload_limit, upload_window_seconds = _anonymous_upload_limit()
    recipient_user, invalid_helper_username = _resolve_upload_recipient_username(helper_username)

    if request.method == 'POST':
        form = UploadedLogForm(request.POST, request.FILES)
        if not request.user.is_authenticated:
            client_ip = get_client_ip(request)
            if not _consume_anonymous_upload_slot(client_ip):
                minutes = max(1, (upload_window_seconds + 59) // 60)
                form.add_error(
                    None,
                    (
                        f'Anonymous upload rate limit reached: {upload_limit} upload(s) '
                        f'per {minutes} minute(s). Please wait and try again.'
                    ),
                )
                return render(
                    request,
                    'upload_log.html',
                    {
                        'form': form,
                        'uploaded_log_id': uploaded_log_id,
                        'uploaded_original_filename': uploaded_original_filename,
                    },
                )

        if form.is_valid():
            log_file = form.cleaned_data.get('log_file')
            if log_file:
                filename = log_file.name
                content = getattr(log_file, 'decoded_content', '')
            else:
                filename = 'pasted.txt'
                content = form.cleaned_data['log_text']
            created_log = UploadedLog.objects.create(
                reddit_username=form.cleaned_data['reddit_username'],
                original_filename=filename,
                content=content,
                recipient_user=recipient_user,
            )
            created_log.recalculate_log_type()
            try:
                created_log.recalculate_analysis_stats()
            except Exception as e:
                print(f"ERROR calculating stats for {created_log.upload_id}: {e}")
                traceback.print_exc()
            request.session['upload_success_id'] = created_log.upload_id
            request.session['upload_success_filename'] = created_log.original_filename
            request.session['upload_success_channel'] = recipient_user.username if recipient_user else 'general'
            if helper_username and invalid_helper_username:
                messages.warning(
                    request,
                    f'Could not find helper "{invalid_helper_username}". Upload was saved to the general channel.',
                )
            return redirect('upload_log')
    else:
        prefill = request.GET.get('u', '')
        form = UploadedLogForm(initial={'reddit_username': prefill} if prefill else None)

    uploaded_log_id = request.session.pop('upload_success_id', None)
    uploaded_original_filename = request.session.pop('upload_success_filename', None)
    uploaded_channel = request.session.pop('upload_success_channel', None)

    return render(
        request,
        'upload_log.html',
        {
            'form': form,
            'uploaded_log_id': uploaded_log_id,
            'uploaded_original_filename': uploaded_original_filename,
            'uploaded_channel': uploaded_channel,
            'target_helper': recipient_user,
            'invalid_helper_username': invalid_helper_username,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def uploaded_logs_view(request):
    """List uploaded logs for authenticated users and support merge/delete actions."""
    action_scope_uploads = get_action_scoped_uploads(request.user)

    if request.method == 'POST':
        action = request.POST.get('action', '')

        selected_ids = []
        seen_ids = set()
        for upload_id in request.POST.getlist('selected_upload_ids'):
            normalized_id = str(upload_id).strip()
            if not normalized_id or normalized_id in seen_ids:
                continue
            seen_ids.add(normalized_id)
            selected_ids.append(normalized_id)

        # Dispatch to action handlers
        upload_id = request.POST.get('upload_id', '').strip()
        
        if action == 'delete':
            return handle_delete_action(request, upload_id, action_scope_uploads)
        elif action == 'assign_to_me':
            return handle_assign_to_me_action(request, upload_id, action_scope_uploads)
        elif action == 'unassign_to_general':
            return handle_unassign_to_general_action(request, upload_id, action_scope_uploads)
        elif action == 'delete_selected':
            return handle_delete_selected_action(request, selected_ids, action_scope_uploads)
        elif action == 'merge':
            return handle_merge_action(request, selected_ids, action_scope_uploads)
        elif action == 'confirm_merge':
            return handle_confirm_merge_action(request, selected_ids, action_scope_uploads)
        elif action == 'rescan_stats_all':
            return handle_rescan_stats_all_action(request, action_scope_uploads)
        else:
            messages.error(request, 'Invalid action.')
            return redirect('uploaded_logs')

    username_filter = request.GET.get('u', '').strip()
    show_all = request.GET.get('show_all', '').strip() in {'1', 'true', 'on', 'yes'}

    list_visible_uploads = (
        UploadedLog.objects.all()
        if show_all
        else UploadedLog.objects.filter(recipient_user=request.user)
    )

    uploads = list_visible_uploads.filter(deleted_at__isnull=True).select_related('recipient_user').defer('content')
    if username_filter:
        uploads = uploads.filter(reddit_username=username_filter)
    page_obj = Paginator(uploads, 25).get_page(request.GET.get('page'))
    pagination_params = {}
    if username_filter:
        pagination_params['u'] = username_filter
    if show_all:
        pagination_params['show_all'] = '1'
    all_usernames = list_visible_uploads.filter(deleted_at__isnull=True).values_list('reddit_username', flat=True).distinct().order_by('reddit_username')
    trash_count = get_updatable_uploads(request.user).filter(deleted_at__isnull=False).count()
    page_content_hashes = {
        uploaded_log.content_hash
        for uploaded_log in page_obj.object_list
        if uploaded_log.content_hash
    }
    duplicate_hashes = set()
    if page_content_hashes:
        duplicate_hashes = set(
            list_visible_uploads.filter(deleted_at__isnull=True, content_hash__in=page_content_hashes)
            .values('content_hash')
            .annotate(cnt=Count('id'))
            .filter(cnt__gt=1)
            .values_list('content_hash', flat=True)
        )
    helper_upload_url = request.build_absolute_uri(reverse('upload_log_for_helper', args=[request.user.username]))
    return render(request, 'uploaded_logs.html', {
        'uploads': page_obj.object_list,
        'page_obj': page_obj,
        'username_filter': username_filter,
        'all_usernames': all_usernames,
        'trash_count': trash_count,
        'duplicate_hashes': duplicate_hashes,
        'helper_upload_url': helper_upload_url,
        'show_all': show_all,
        'pagination_query': urlencode(pagination_params),
    })


@login_required
@require_http_methods(["GET", "POST"])
def view_uploaded_log(request, upload_id):
    """View a single uploaded log by memorable ID."""
    uploaded_log = get_object_or_404(UploadedLog, upload_id=upload_id, deleted_at__isnull=True)

    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'delete':
            if not user_can_delete_uploaded_log(request.user, uploaded_log):
                messages.error(request, f'Only the assigned helper can delete {upload_id}.')
                return redirect('view_uploaded_log', upload_id=upload_id)
            soft_delete_uploaded_log(uploaded_log)
            _purge_old_trash()
            messages.success(request, f'Upload {upload_id} moved to trash.')
            return redirect('uploaded_logs')

        if action == 'rename_reddit':
            new_username = request.POST.get('reddit_username', '').strip()
            if new_username:
                uploaded_log.reddit_username = new_username
                uploaded_log.save(update_fields=['reddit_username'])
            return redirect('view_uploaded_log', upload_id=upload_id)

        if action == 'assign_to_me':
            if uploaded_log.recipient_user_id is not None:
                messages.error(request, f'Upload {upload_id} is already assigned.')
                return redirect('view_uploaded_log', upload_id=upload_id)

            uploaded_log.recipient_user = request.user
            uploaded_log.save(update_fields=['recipient_user', 'updated_at'])
            messages.success(request, f'Upload {upload_id} assigned to {request.user.username}.')
            return redirect('view_uploaded_log', upload_id=upload_id)

        if action == 'unassign_to_general':
            if uploaded_log.recipient_user_id is None:
                messages.error(request, f'Upload {upload_id} is already unassigned.')
                return redirect('view_uploaded_log', upload_id=upload_id)
            if not user_can_delete_uploaded_log(request.user, uploaded_log):
                messages.error(request, f'Only the assigned helper can unassign {upload_id}.')
                return redirect('view_uploaded_log', upload_id=upload_id)

            uploaded_log.recipient_user = None
            uploaded_log.save(update_fields=['recipient_user', 'updated_at'])
            messages.success(request, f'{upload_id} was unassigned')
            return redirect('view_uploaded_log', upload_id=upload_id)

    return render(request, 'view_uploaded_log.html', {'uploaded_log': uploaded_log})


@login_required
@require_http_methods(["GET"])
def diff_uploaded_logs_view(request, id1, id2):
    """Show a side-by-side diff of two uploaded logs. All users can diff any logs."""
    log1 = get_object_or_404(UploadedLog.objects.all(), upload_id=id1, deleted_at__isnull=True)
    log2 = get_object_or_404(UploadedLog.objects.all(), upload_id=id2, deleted_at__isnull=True)

    lines1 = log1.content.splitlines()
    lines2 = log2.content.splitlines()

    matcher = difflib.SequenceMatcher(None, lines1, lines2, autojunk=False)
    rows = []
    left_lineno = 0
    right_lineno = 0

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        left_chunk = lines1[i1:i2]
        right_chunk = lines2[j1:j2]

        if tag == 'equal':
            for left, right in zip(left_chunk, right_chunk):
                left_lineno += 1
                right_lineno += 1
                rows.append({'tag': 'equal', 'left': left, 'right': right,
                             'left_lineno': left_lineno, 'right_lineno': right_lineno})
        elif tag == 'replace':
            for k in range(max(len(left_chunk), len(right_chunk))):
                has_left = k < len(left_chunk)
                has_right = k < len(right_chunk)
                if has_left:
                    left_lineno += 1
                if has_right:
                    right_lineno += 1
                rows.append({
                    'tag': 'replace',
                    'left': left_chunk[k] if has_left else None,
                    'right': right_chunk[k] if has_right else None,
                    'left_lineno': left_lineno if has_left else None,
                    'right_lineno': right_lineno if has_right else None,
                })
        elif tag == 'delete':
            for line in left_chunk:
                left_lineno += 1
                rows.append({'tag': 'delete', 'left': line, 'right': None,
                             'left_lineno': left_lineno, 'right_lineno': None})
        elif tag == 'insert':
            for line in right_chunk:
                right_lineno += 1
                rows.append({'tag': 'insert', 'left': None, 'right': line,
                             'left_lineno': None, 'right_lineno': right_lineno})

    equal_count = sum(1 for r in rows if r['tag'] == 'equal')
    changed_count = len(rows) - equal_count

    return render(request, 'diff_uploaded_logs.html', {
        'log1': log1,
        'log2': log2,
        'rows': rows,
        'equal_count': equal_count,
        'changed_count': changed_count,
    })


@login_required
@require_http_methods(["GET", "POST"])
def uploads_trash_view(request):
    """Trash bin for soft-deleted uploaded logs."""
    action_scope_uploads = get_action_scoped_uploads(request.user)

    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'restore':
            upload_id = request.POST.get('upload_id', '').strip()
            uploaded_log = get_object_or_404(action_scope_uploads, upload_id=upload_id, deleted_at__isnull=False)
            if not user_can_delete_uploaded_log(request.user, uploaded_log):
                messages.error(request, f'Only the assigned helper can restore {upload_id}.')
                return redirect('uploads_trash')
            restore_uploaded_log(uploaded_log)
            messages.success(request, f'Upload {upload_id} restored.')
            return redirect('uploads_trash')

        if action == 'delete_permanent':
            upload_id = request.POST.get('upload_id', '').strip()
            uploaded_log = get_object_or_404(action_scope_uploads, upload_id=upload_id, deleted_at__isnull=False)
            if not user_can_delete_uploaded_log(request.user, uploaded_log):
                messages.error(request, f'Only the assigned helper can permanently delete {upload_id}.')
                return redirect('uploads_trash')
            uploaded_log.delete()
            messages.success(request, f'Upload {upload_id} permanently deleted.')
            return redirect('uploads_trash')

        if action == 'empty_trash':
            deletable_logs = [log for log in action_scope_uploads.filter(deleted_at__isnull=False) 
                            if user_can_delete_uploaded_log(request.user, log)]
            if not deletable_logs:
                messages.error(request, 'You have no deleted uploads to clean from trash.')
                return redirect('uploads_trash')
            count = len(deletable_logs)
            for log in deletable_logs:
                log.delete()
            messages.success(request, f'Trash emptied ({count} upload(s) permanently deleted).')
            return redirect('uploads_trash')

        messages.error(request, 'Invalid action.')
        return redirect('uploads_trash')

    trashed = action_scope_uploads.filter(deleted_at__isnull=False).order_by('-deleted_at')
    page_obj = Paginator(trashed, 25).get_page(request.GET.get('page'))
    return render(request, 'uploads_trash.html', {'uploads': page_obj.object_list, 'page_obj': page_obj})


@login_required
@require_http_methods(["GET"])
def uploaded_log_content_api(request, upload_id):
    """Return upload content for analyzer prefill. All users can fetch any log."""
    uploaded_log = get_object_or_404(
        UploadedLog.objects.all(),
        upload_id=upload_id,
        deleted_at__isnull=True,
    )
    return JsonResponse(
        {
            'upload_id': uploaded_log.upload_id,
            'content': uploaded_log.content,
            'original_filename': uploaded_log.original_filename,
            'reddit_username': uploaded_log.reddit_username,
        }
    )
