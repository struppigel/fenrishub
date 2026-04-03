"""Views package for FenrisHub fixlist app."""

# Import commonly-mocked functions for backward compatibility with existing test patches
from django.shortcuts import render

# Re-export views from domain modules
from .auth import (
    login_view,
    change_password_view,
    dashboard_view,
    logout_view,
)

from .uploads import (
    upload_log_view,
    uploaded_logs_view,
    view_uploaded_log,
    diff_uploaded_logs_view,
    uploads_trash_view,
    uploaded_log_content_api,
)

from .fixlists import (
    create_fixlist_view,
    fixlists_trash_view,
    view_fixlist,
    shared_fixlist_view,
    download_fixlist,
    copy_to_clipboard_api,
)

from .analyzer import (
    log_analyzer_view,
    analyze_log_api,
    analyze_line_details_api,
    preview_pending_rule_changes_api,
    persist_pending_rule_changes_api,
    update_analyzed_line_status_api,
)

from .snippets import (
    snippets_view,
    snippets_api,
)

from .rules import (
    rules_view,
    add_rule_view,
    test_rule_api,
)

# Re-export utilities from utils module
from .utils import (
    custom_404_view,
    get_action_scoped_uploads,
    get_updatable_uploads,
    get_client_ip,
    _purge_old_trash,
    _uploads_redirect_with_state,
    _resolve_upload_recipient_username,
    _consume_anonymous_upload_slot,
    _anonymous_upload_limit,
)

__all__ = [
    'render',  # For backward compatibility with test patches
    'login_view',
    'change_password_view',
    'dashboard_view',
    'upload_log_view',
    'uploaded_logs_view',
    'view_uploaded_log',
    'diff_uploaded_logs_view',
    'uploads_trash_view',
    'fixlists_trash_view',
    'uploaded_log_content_api',
    'create_fixlist_view',
    'view_fixlist',
    'shared_fixlist_view',
    'download_fixlist',
    'copy_to_clipboard_api',
    'log_analyzer_view',
    'analyze_log_api',
    'analyze_line_details_api',
    'preview_pending_rule_changes_api',
    'persist_pending_rule_changes_api',
    'update_analyzed_line_status_api',
    'snippets_view',
    'snippets_api',
    'rules_view',
    'add_rule_view',
    'test_rule_api',
    'logout_view',
    'custom_404_view',
]
