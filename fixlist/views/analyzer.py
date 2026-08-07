"""
Log analyzer views and APIs.

Handles: analyzing logs, inspecting lines, previewing rules, persisting rule changes, and status updates.
"""

import json
import logging
import re
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import HttpResponseBadRequest, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils.safestring import mark_safe

from ..analyzer import (
    analyze_log_text, parse_rule_line, inspect_line_matches,
    VALID_STATUSES,
)
from ..models import ClassificationRule, Fixlist, FixlistSnippet, Speech, UploadedLog, UploadedLogAnalysis
from ..rule_sets import (
    SHARED_RULE_SET_KEY,
    resolve_effective_rule_set_key,
    resolve_user_rule_set_key,
)
from ..validators import PayloadValidator, BadJsonError, PayloadTooLargeError
from ..rule_utils import (
    _normalize_pending_changes, _build_pending_rule_preview,
    _persist_selected_pending_rules,
)
from .auth import DEFAULT_ANALYZER_FIXLIST_TEMPLATE
from .guest import deny_guests, guest_or_login_required, is_guest_request
from .utils import get_action_scoped_uploads, get_updatable_uploads


@guest_or_login_required
@require_http_methods(["GET"])
def log_analyzer_view(request):
    """Render log analyzer tool."""
    if is_guest_request(request):
        return render(
            request,
            'log_analyzer.html',
            {
                'uploaded_logs': [],
                'initial_upload_id': '',
                'initial_fixlist_id': '',
                'initial_selected_lines': DEFAULT_ANALYZER_FIXLIST_TEMPLATE,
                'is_superuser': False,
                'snippets_json': mark_safe('[]'),
                'speeches_json': mark_safe('[]'),
                # A guest has no username, so there is no per-helper upload link
                # and {UPLOADLINK_USER} stays literal for them.
                'upload_link_helper_base': '',
                'upload_link_general': request.build_absolute_uri(reverse('upload_log')),
                'fixlist_template': DEFAULT_ANALYZER_FIXLIST_TEMPLATE,
            },
        )

    uploads = get_action_scoped_uploads(request.user).filter(deleted_at__isnull=True).defer('content')[:200]
    requested_upload_id = (request.GET.get('upload_id') or '').strip()
    initial_upload_id = requested_upload_id if requested_upload_id else ''
    snippets_qs = FixlistSnippet.objects.filter(
        analyzer_users=request.user,
    ).select_related('owner').order_by('category', 'name')
    snippets_json = mark_safe(json.dumps([
        {
            'id': s.id,
            'name': s.name if s.owner_id == request.user.id else f"{s.name} ({s.owner.username})",
            'category': s.category,
            'content': s.content,
        }
        for s in snippets_qs
    ]))
    speeches_qs = Speech.objects.filter(
        analyzer_users=request.user,
    ).select_related('owner').order_by('category', 'name')
    speeches_json = mark_safe(json.dumps([
        {
            'id': s.id,
            'name': s.name if s.owner_id == request.user.id else f"{s.name} ({s.owner.username})",
            'category': s.category,
            'content': s.content,
        }
        for s in speeches_qs
    ]))
    # Bases for the {UPLOADLINK_*} speech placeholders. The per-user link needs a
    # forum username that only the browser knows, so the client appends ?u=.
    upload_link_helper_base = request.build_absolute_uri(
        reverse('upload_log_for_helper', args=[request.user.username])
    )
    upload_link_general = request.build_absolute_uri(reverse('upload_log'))
    profile = getattr(request.user, 'fenris_profile', None)
    fixlist_template = (
        (profile.analyzer_fixlist_template if profile else '').strip()
        or DEFAULT_ANALYZER_FIXLIST_TEMPLATE
    )

    # Editing an existing fixlist from the analyzer: preload its content into the fixlist
    # panel and, absent an explicit upload_id, auto-load its source log for re-analysis.
    initial_fixlist_id = ''
    initial_selected_lines = fixlist_template
    requested_fixlist_id = (request.GET.get('fixlist_id') or '').strip()
    if requested_fixlist_id.isdigit():
        editing_fixlist = Fixlist.objects.filter(
            pk=int(requested_fixlist_id),
            owner=request.user,
            deleted_at__isnull=True,
        ).select_related('source_uploaded_log').first()
        if editing_fixlist is not None:
            initial_fixlist_id = str(editing_fixlist.pk)
            initial_selected_lines = editing_fixlist.content
            if not initial_upload_id and editing_fixlist.source_uploaded_log:
                initial_upload_id = editing_fixlist.source_uploaded_log.upload_id

    return render(
        request,
        'log_analyzer.html',
        {
            'uploaded_logs': uploads,
            'initial_upload_id': initial_upload_id,
            'initial_fixlist_id': initial_fixlist_id,
            'initial_selected_lines': initial_selected_lines,
            'is_superuser': request.user.is_superuser,
            'snippets_json': snippets_json,
            'speeches_json': speeches_json,
            'upload_link_helper_base': upload_link_helper_base,
            'upload_link_general': upload_link_general,
            'fixlist_template': fixlist_template,
        },
    )


@guest_or_login_required
@require_http_methods(["POST"])
def analyze_log_api(request):
    """Analyze pasted FRST log content and return line-level classifications."""
    try:
        payload = PayloadValidator.json_payload(request)
    except PayloadTooLargeError as exc:
        return PayloadValidator.error_response(str(exc), status=413)
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

    if is_guest_request(request):
        viewer_key = SHARED_RULE_SET_KEY
    else:
        viewer_key = resolve_user_rule_set_key(request.user)

    analysis = analyze_log_text(log_text, viewer_key)
    if upload_id and not is_guest_request(request):
        # Cache row is per-(upload, rule_set_key), so populating it for an
        # arbitrary viewer's key can't step on the recipient's row. Look the
        # upload up by id directly rather than via the updatable-uploads
        # filter — otherwise viewers who aren't the assigned recipient never
        # get a cache row of their own and re-pay the full analysis cost on
        # every visit. Read access to the cached payload is already permitted
        # for any authenticated user by uploaded_log_cached_analysis_api.
        uploaded_log = UploadedLog.objects.filter(
            upload_id=upload_id, deleted_at__isnull=True,
        ).first()
        if uploaded_log:
            try:
                UploadedLogAnalysis.objects.update_or_create(
                    upload=uploaded_log,
                    rule_set_key=viewer_key,
                    defaults={
                        'payload': analysis,
                        'source_content_hash': uploaded_log.content_hash,
                    },
                )
                # count_* on the upload reflects the assigned recipient's view.
                # Only update it when this viewer's ruleset matches the
                # upload's effective ruleset AND the viewer is the recipient
                # (or the upload is unassigned). Otherwise an uninvolved
                # viewer would overwrite the recipient's listing stats.
                if (
                    viewer_key == resolve_effective_rule_set_key(uploaded_log)
                    and get_updatable_uploads(request.user).filter(pk=uploaded_log.pk).exists()
                ):
                    uploaded_log.apply_analysis_summary(analysis.get('summary', {}))
                    uploaded_log.save(update_fields=UploadedLog.analysis_stat_update_fields())
            except Exception:
                logger.exception('Failed to refresh cached analysis for upload_id=%s', upload_id)
    return JsonResponse(analysis)


@deny_guests
@login_required
@require_http_methods(["GET"])
def uploaded_log_cached_analysis_api(request, upload_id):
    """Return the most recent cached analyzer payload for an upload, if any.

    Lets the analyzer page render verdicts instantly while a background re-scan
    runs. Marks the cache as missing when the upload's content has changed since
    the cache was written, so callers never display verdicts for different text.
    """
    uploaded_log = get_object_or_404(
        UploadedLog.objects.all(),
        upload_id=upload_id,
        deleted_at__isnull=True,
    )
    viewer_key = resolve_user_rule_set_key(request.user)
    cached = UploadedLogAnalysis.objects.filter(
        upload=uploaded_log, rule_set_key=viewer_key,
    ).first()
    if cached is None or cached.source_content_hash != uploaded_log.content_hash:
        return JsonResponse({'has_cache': False, 'payload': None, 'source_content_hash': None})
    return JsonResponse({
        'has_cache': True,
        'payload': cached.payload,
        'source_content_hash': cached.source_content_hash,
    })


@guest_or_login_required
@require_http_methods(["POST"])
def analyze_line_details_api(request):
    """Inspect a single line and return parsed metadata plus matching rule details."""
    try:
        payload = PayloadValidator.json_payload(request)
    except PayloadTooLargeError as exc:
        return PayloadValidator.error_response(str(exc), status=413)
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

    actor_label = 'guest' if is_guest_request(request) else request.user.username
    parsed_rule = parse_rule_line(
        line,
        status=requested_status,
        source_name=f'analyzer-inspect:{actor_label}',
    )
    inspection = inspect_line_matches(line)

    return JsonResponse(
        {
            'line': line,
            'parsed_rule': parsed_rule,
            'inspection': inspection,
        }
    )


@deny_guests
@login_required
@require_http_methods(["POST"])
def preview_pending_rule_changes_api(request):
    """Preview optional rule persistence before creating a fixlist."""
    try:
        payload = PayloadValidator.json_payload(request)
    except PayloadTooLargeError as exc:
        return PayloadValidator.error_response(str(exc), status=413)
    except BadJsonError:
        return PayloadValidator.error_response('Invalid JSON payload.')

    pending_changes = payload.get('pending_changes', [])
    normalized_changes, invalid_changes = _normalize_pending_changes(pending_changes)
    if pending_changes is not None and not isinstance(pending_changes, list):
        return PayloadValidator.error_response('Field "pending_changes" must be a list.')

    preview = _build_pending_rule_preview(normalized_changes, request.user.username, request.user)
    preview['invalid_changes'] = invalid_changes
    return JsonResponse(preview)


@deny_guests
@login_required
@require_http_methods(["POST"])
def persist_pending_rule_changes_api(request):
    """Persist selected pending analyzer changes as classification rules immediately."""
    try:
        payload = PayloadValidator.json_payload(request)
    except PayloadTooLargeError as exc:
        return PayloadValidator.error_response(str(exc), status=413)
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

    from ..rule_sets import invalidate_for_rule_owner
    invalidate_for_rule_owner(request.user)

    return JsonResponse({'ok': True, **result})


@guest_or_login_required
@require_http_methods(["POST"])
def update_analyzed_line_status_api(request):
    """Validate a status override payload without persisting it to the database."""
    try:
        payload = PayloadValidator.json_payload(request)
    except PayloadTooLargeError as exc:
        return PayloadValidator.error_response(str(exc), status=413)
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

    actor_label = 'guest' if is_guest_request(request) else request.user.username
    source_name = f'analyzer-ui:{actor_label}'
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


_EDGE_CRXID_RE = re.compile(r'^[a-p]{32}$')
_EDGE_API_TEMPLATE = 'https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/{crxid}'
# Edge's SPA accepts any non-empty slug as long as the trailing crxid matches a
# real Edge-store extension; '_' avoids the need to parse the API response.
_EDGE_DETAIL_TEMPLATE = 'https://microsoftedge.microsoft.com/addons/detail/_/{crxid}'
# Sideloaded-Chrome-extension fallback — many extensions in Edge logs were
# originally installed from Chrome Web Store and aren't on the Edge store at
# all, so an Edge 404 is more usefully redirected here than to a generic page.
_CHROME_STORE_DETAIL_TEMPLATE = 'https://chromewebstore.google.com/detail/{crxid}'


@guest_or_login_required
@require_http_methods(["GET"])
def edge_addon_redirect_view(request, crxid):
    """Probe the Edge Add-ons API for `crxid` and redirect to its detail page.

    On Edge-API 404 (extension was sideloaded from Chrome Web Store) or any
    upstream failure, falls back to the Chrome Web Store detail page so the
    user lands on the most likely source rather than a generic landing page.
    """
    if not _EDGE_CRXID_RE.match(crxid):
        return HttpResponseBadRequest('invalid crxid')

    api_url = _EDGE_API_TEMPLATE.format(crxid=crxid)
    req = urllib.request.Request(api_url, headers={'User-Agent': 'FenrisHub'})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if 200 <= response.status < 300:
                return HttpResponseRedirect(_EDGE_DETAIL_TEMPLATE.format(crxid=crxid))
            logger.warning('Edge addon probe for %s: unexpected status %s', crxid, response.status)
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            logger.warning('Edge addon probe for %s: HTTPError %s', crxid, exc.code)
    except (urllib.error.URLError, TimeoutError) as exc:
        logger.warning('Edge addon probe for %s failed: %r', crxid, exc)

    return HttpResponseRedirect(_CHROME_STORE_DETAIL_TEMPLATE.format(crxid=crxid))
