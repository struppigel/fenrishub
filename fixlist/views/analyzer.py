"""
Log analyzer views and APIs.

Handles: analyzing logs, inspecting lines, previewing rules, persisting rule changes, and status updates.
"""

from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.shortcuts import render

from ..analyzer import (
    analyze_log_text, parse_rule_line, inspect_line_matches,
    VALID_STATUSES,
)
from ..models import ClassificationRule, UploadedLog
from ..validators import PayloadValidator, BadJsonError
from ..rule_utils import (
    _normalize_pending_changes, _build_pending_rule_preview,
    _persist_selected_pending_rules,
)
from .utils import get_action_scoped_uploads, get_updatable_uploads


@login_required
@require_http_methods(["GET"])
def log_analyzer_view(request):
    """Render log analyzer tool."""
    uploads = get_action_scoped_uploads(request.user).filter(deleted_at__isnull=True)[:200]
    requested_upload_id = (request.GET.get('upload_id') or '').strip()
    initial_upload_id = requested_upload_id if requested_upload_id else ''
    return render(
        request,
        'log_analyzer.html',
        {
            'uploaded_logs': uploads,
            'initial_upload_id': initial_upload_id,
            'is_superuser': request.user.is_superuser,
        },
    )


@login_required
@require_http_methods(["POST"])
def analyze_log_api(request):
    """Analyze pasted FRST log content and return line-level classifications."""
    try:
        payload = PayloadValidator.json_payload(request)
    except BadJsonError:
        return PayloadValidator.error_response('Invalid JSON payload.')

    log_text = payload.get('log', '')
    if not isinstance(log_text, str):
        return PayloadValidator.error_response('Field "log" must be a string.')
    upload_id = payload.get('upload_id', '')
    if upload_id is None:
        upload_id = ''
    if not isinstance(upload_id, str):
        return PayloadValidator.error_response('Field "upload_id" must be a string when provided.')
    upload_id = upload_id.strip()

    analysis = analyze_log_text(log_text)
    if upload_id:
        uploaded_log = get_updatable_uploads(request.user).filter(upload_id=upload_id).first()
        if uploaded_log:
            try:
                uploaded_log.apply_analysis_summary(analysis.get('summary', {}))
                uploaded_log.save(update_fields=UploadedLog.analysis_stat_update_fields())
            except Exception as e:
                print(f"ERROR updating stats for {upload_id} during parse: {e}")
                import traceback
                traceback.print_exc()
    return JsonResponse(analysis)


@login_required
@require_http_methods(["POST"])
def analyze_line_details_api(request):
    """Inspect a single line and return parsed metadata plus matching rule details."""
    try:
        payload = PayloadValidator.json_payload(request)
    except BadJsonError:
        return PayloadValidator.error_response('Invalid JSON payload.')

    line = payload.get('line', '')
    requested_status = payload.get('status', ClassificationRule.STATUS_UNKNOWN)

    if not isinstance(line, str):
        return PayloadValidator.error_response('Field "line" must be a string.')
    if not isinstance(requested_status, str):
        return PayloadValidator.error_response('Field "status" must be a string.')

    line = line.strip()
    requested_status = requested_status.strip() or ClassificationRule.STATUS_UNKNOWN

    if not line:
        return JsonResponse({'error': 'Field "line" cannot be empty.'}, status=400)
    if requested_status not in VALID_STATUSES:
        requested_status = ClassificationRule.STATUS_UNKNOWN

    parsed_rule = parse_rule_line(
        line,
        status=requested_status,
        source_name=f'analyzer-inspect:{request.user.username}',
    )
    inspection = inspect_line_matches(line)

    return JsonResponse(
        {
            'line': line,
            'parsed_rule': parsed_rule,
            'inspection': inspection,
        }
    )


@login_required
@require_http_methods(["POST"])
def preview_pending_rule_changes_api(request):
    """Preview optional rule persistence before creating a fixlist."""
    try:
        payload = PayloadValidator.json_payload(request)
    except BadJsonError:
        return PayloadValidator.error_response('Invalid JSON payload.')

    pending_changes = payload.get('pending_changes', [])
    normalized_changes, invalid_changes = _normalize_pending_changes(pending_changes)
    if pending_changes is not None and not isinstance(pending_changes, list):
        return PayloadValidator.error_response('Field "pending_changes" must be a list.')

    preview = _build_pending_rule_preview(normalized_changes, request.user.username, request.user)
    preview['invalid_changes'] = invalid_changes
    return JsonResponse(preview)


@login_required
@require_http_methods(["POST"])
def persist_pending_rule_changes_api(request):
    """Persist selected pending analyzer changes as classification rules immediately."""
    try:
        payload = PayloadValidator.json_payload(request)
    except BadJsonError:
        return PayloadValidator.error_response('Invalid JSON payload.')

    pending_changes = payload.get('pending_changes', [])
    selected_ids = payload.get('selected_rule_change_ids', [])
    conflict_resolutions = payload.get('conflict_resolutions', [])

    if pending_changes is not None and not isinstance(pending_changes, list):
        return PayloadValidator.error_response('Field "pending_changes" must be a list.')
    if selected_ids is not None and not isinstance(selected_ids, list):
        return PayloadValidator.error_response('Field "selected_rule_change_ids" must be a list.')
    if conflict_resolutions is not None and not isinstance(conflict_resolutions, list):
        return PayloadValidator.error_response('Field "conflict_resolutions" must be a list.')

    result = _persist_selected_pending_rules(
        raw_pending_changes=pending_changes,
        raw_selected_ids=selected_ids,
        raw_conflict_resolutions=conflict_resolutions,
        username=request.user.username,
        source_prefix='analyzer-persist',
        owner=request.user,
    )

    return JsonResponse({'ok': True, **result})


@login_required
@require_http_methods(["POST"])
def update_analyzed_line_status_api(request):
    """Validate a status override payload without persisting it to the database."""
    try:
        payload = PayloadValidator.json_payload(request)
    except BadJsonError:
        return PayloadValidator.error_response('Invalid JSON payload.')

    line = payload.get('line', '')
    status = payload.get('status', '')
    current_status = payload.get('current_status', '')

    if not isinstance(line, str):
        return PayloadValidator.error_response('Field "line" must be a string.')
    if not isinstance(status, str):
        return PayloadValidator.error_response('Field "status" must be a string.')
    if current_status and not isinstance(current_status, str):
        return PayloadValidator.error_response('Field "current_status" must be a string when provided.')

    line = line.strip()
    status = status.strip()
    current_status = current_status.strip()

    if not line:
        return JsonResponse({'error': 'Field "line" cannot be empty.'}, status=400)
    if status not in VALID_STATUSES:
        return JsonResponse({'error': f'Invalid status: {status}'}, status=400)
    if current_status == ClassificationRule.STATUS_INFO:
        return JsonResponse({'error': 'Informational lines cannot be edited.'}, status=400)
    if current_status == ClassificationRule.STATUS_ALERT:
        return JsonResponse({'error': 'Alert lines cannot be edited.'}, status=400)
    if status == ClassificationRule.STATUS_INFO:
        return JsonResponse({'error': 'Setting informational status from analyzer is not allowed.'}, status=400)
    if status == ClassificationRule.STATUS_ALERT:
        return JsonResponse({'error': 'Setting alert status from analyzer is not allowed.'}, status=400)

    source_name = f'analyzer-ui:{request.user.username}'
    parsed = parse_rule_line(line, status=status, source_name=source_name)
    if not parsed:
        return JsonResponse({'error': 'Unable to parse line into a classification rule.'}, status=400)

    return JsonResponse(
        {
            'persisted': False,
            'status': parsed['status'],
            'match_type': parsed['match_type'],
            'source_text': parsed['source_text'],
        }
    )
