from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('fixlists/create/', views.create_fixlist_view, name='create_fixlist'),
    path('fixlists/analyze/', views.log_analyzer_view, name='log_analyzer'),
    path('fixlist/<int:pk>/', views.view_fixlist, name='view_fixlist'),
    path('share/<str:token>/', views.shared_fixlist_view, name='shared_fixlist'),
    path('download/<str:token>/', views.download_fixlist, name='download_fixlist'),
    path('api/copy/<str:token>/', views.copy_to_clipboard_api, name='copy_api'),
    path('logout/', views.logout_view, name='logout'),
]
