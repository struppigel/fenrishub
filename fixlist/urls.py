from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('account/password/', views.change_password_view, name='change_password'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('fixlists/create/', views.create_fixlist_view, name='create_fixlist'),
    path('fixlists/analyze/', views.log_analyzer_view, name='log_analyzer'),
    path('api/analyze-log/', views.analyze_log_api, name='analyze_log_api'),
    path('api/analyze-log/line-details/', views.analyze_line_details_api, name='analyze_line_details_api'),
    path('api/analyze-log/status/', views.update_analyzed_line_status_api, name='update_analyzed_line_status_api'),
    path('api/fixlist/rules-preview/', views.preview_pending_rule_changes_api, name='preview_pending_rule_changes_api'),
    path('api/fixlist/rules-persist/', views.persist_pending_rule_changes_api, name='persist_pending_rule_changes_api'),
    path('fixlist/<int:pk>/', views.view_fixlist, name='view_fixlist'),
    path('share/<str:token>/', views.shared_fixlist_view, name='shared_fixlist'),
    path('download/<str:token>/', views.download_fixlist, name='download_fixlist'),
    path('api/copy/<str:token>/', views.copy_to_clipboard_api, name='copy_api'),
    path('logout/', views.logout_view, name='logout'),
]
