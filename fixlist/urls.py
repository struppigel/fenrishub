from django.urls import path
from .views.analyzer import (
    analyze_line_details_api,
    analyze_log_api,
    log_analyzer_view,
    persist_pending_rule_changes_api,
    preview_pending_rule_changes_api,
    update_analyzed_line_status_api,
)
from .views.auth import change_password_view, dashboard_view, login_view, logout_view
from .views.fixlists import (
    copy_to_clipboard_api,
    create_fixlist_view,
    download_fixlist,
    fixlists_trash_view,
    shared_fixlist_view,
    view_fixlist,
)
from .views.infection_cases import (
    create_infection_case_view,
    infection_case_add_items_view,
    infection_case_confirm_username_change_view,
    infection_case_delete_view,
    infection_cases_view,
    view_infection_case,
)
from .views.rules import add_rule_view, rules_view, test_rule_api
from .views.snippets import snippets_api, snippets_view
from .views.uploads import (
    diff_uploaded_logs_view,
    upload_log_view,
    uploaded_log_content_api,
    uploaded_logs_view,
    uploads_trash_view,
    view_uploaded_log,
)

urlpatterns = [
    path('', login_view, name='login'),
    path('upload/<str:helper_username>/', upload_log_view, name='upload_log_for_helper'),
    path('upload/', upload_log_view, name='upload_log'),
    path('account/password/', change_password_view, name='change_password'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('uploads/', uploaded_logs_view, name='uploaded_logs'),
    path('uploads/trash/', uploads_trash_view, name='uploads_trash'),
    path('uploads/<str:upload_id>/', view_uploaded_log, name='view_uploaded_log'),
    path('uploads/diff/<str:id1>/<str:id2>/', diff_uploaded_logs_view, name='diff_uploaded_logs'),
    path('fixlists/trash/', fixlists_trash_view, name='fixlists_trash'),
    path('fixlists/create/', create_fixlist_view, name='create_fixlist'),
    path('cases/', infection_cases_view, name='infection_cases'),
    path('cases/create/', create_infection_case_view, name='create_infection_case'),
    path('cases/<str:case_id>/', view_infection_case, name='view_infection_case'),
    path('cases/<str:case_id>/add-items/', infection_case_add_items_view, name='infection_case_add_items'),
    path('cases/<str:case_id>/confirm-username-change/', infection_case_confirm_username_change_view, name='infection_case_confirm_username_change'),
    path('cases/<str:case_id>/delete/', infection_case_delete_view, name='infection_case_delete'),
    path('fixlists/analyze/', log_analyzer_view, name='log_analyzer'),
    path('api/uploaded-logs/<str:upload_id>/content/', uploaded_log_content_api, name='uploaded_log_content_api'),
    path('api/analyze-log/', analyze_log_api, name='analyze_log_api'),
    path('api/analyze-log/line-details/', analyze_line_details_api, name='analyze_line_details_api'),
    path('api/analyze-log/status/', update_analyzed_line_status_api, name='update_analyzed_line_status_api'),
    path('api/fixlist/rules-preview/', preview_pending_rule_changes_api, name='preview_pending_rule_changes_api'),
    path('api/fixlist/rules-persist/', persist_pending_rule_changes_api, name='persist_pending_rule_changes_api'),
    path('fixlists/snippets/', snippets_view, name='snippets'),
    path('rules/', rules_view, name='rules'),
    path('rules/add/', add_rule_view, name='add_rule'),
    path('api/rules/test/', test_rule_api, name='test_rule_api'),
    path('api/snippets/', snippets_api, name='snippets_api'),
    path('fixlist/<int:pk>/', view_fixlist, name='view_fixlist'),
    path('share/<str:token>/', shared_fixlist_view, name='shared_fixlist'),
    path('download/<str:token>/', download_fixlist, name='download_fixlist'),
    path('api/copy/<str:token>/', copy_to_clipboard_api, name='copy_api'),
    path('logout/', logout_view, name='logout'),
]
