from django.contrib import admin
from .models import Fixlist, AccessLog


@admin.register(Fixlist)
class FixlistAdmin(admin.ModelAdmin):
    list_display = ('title', 'owner', 'download_count', 'created_at', 'share_token')
    list_filter = ('created_at', 'is_public')
    search_fields = ('title', 'owner__username')
    readonly_fields = ('download_count', 'share_token', 'created_at', 'updated_at')
    fields = ('owner', 'title', 'content', 'internal_note', 'download_count', 'share_token', 'created_at', 'updated_at', 'is_public')


@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = ('fixlist', 'accessed_at', 'ip_address')
    list_filter = ('accessed_at',)
    readonly_fields = ('accessed_at', 'ip_address')
