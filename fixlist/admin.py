from django import forms
from django.contrib import admin, messages
from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import path, reverse

from .analyzer import import_rules_from_lines
from .models import AccessLog, ClassificationRule, Fixlist


class RuleImportForm(forms.Form):
    status = forms.ChoiceField(
        choices=[
            choice
            for choice in ClassificationRule.STATUS_CHOICES
            if choice[0] != ClassificationRule.STATUS_UNKNOWN
        ],
        help_text='Select the target state for all imported lines.',
    )
    source_name = forms.CharField(
        required=False,
        max_length=128,
        help_text='Optional source label, for example badlist.txt',
    )
    rules_text = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'rows': 16, 'cols': 120}),
        help_text='Paste one rule per line in Fenris format.',
    )
    rules_file = forms.FileField(
        required=False,
        help_text='Or upload a text file in Fenris format.',
    )

    def clean(self):
        cleaned = super().clean()
        rules_text = cleaned.get('rules_text', '')
        rules_file = cleaned.get('rules_file')
        if not rules_text and not rules_file:
            raise forms.ValidationError('Provide pasted rule text or upload a file.')
        return cleaned


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


@admin.register(ClassificationRule)
class ClassificationRuleAdmin(admin.ModelAdmin):
    change_list_template = 'admin/fixlist/classificationrule/change_list.html'
    list_display = ('status', 'match_type', 'short_source', 'source_name', 'is_enabled', 'updated_at')
    list_filter = ('status', 'match_type', 'is_enabled', 'source_name')
    search_fields = ('source_text', 'description', 'name', 'filepath', 'clsid')
    readonly_fields = ('created_at', 'updated_at')

    fieldsets = (
        (
            None,
            {
                'fields': (
                    'status',
                    'match_type',
                    'source_text',
                    'description',
                    'source_name',
                    'is_enabled',
                )
            },
        ),
        (
            'Parsed Metadata',
            {
                'fields': (
                    'entry_type',
                    'clsid',
                    'name',
                    'filepath',
                    'normalized_filepath',
                    'filename',
                    'company',
                    'arguments',
                    'file_not_signed',
                ),
                'classes': ('collapse',),
            },
        ),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )

    def short_source(self, obj):
        if len(obj.source_text) <= 80:
            return obj.source_text
        return obj.source_text[:77] + '...'

    short_source.short_description = 'source_text'

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                'import-rules/',
                self.admin_site.admin_view(self.import_rules_view),
                name='fixlist_classificationrule_import_rules',
            )
        ]
        return custom_urls + urls

    def import_rules_view(self, request):
        if request.method == 'POST':
            form = RuleImportForm(request.POST, request.FILES)
            if form.is_valid():
                rules_text = form.cleaned_data.get('rules_text', '')
                rules_file = form.cleaned_data.get('rules_file')
                status = form.cleaned_data['status']
                source_name = form.cleaned_data.get('source_name', '').strip()

                lines = []
                if rules_text:
                    lines.extend(rules_text.splitlines())

                if rules_file:
                    file_content = rules_file.read().decode('utf-8', errors='ignore')
                    lines.extend(file_content.splitlines())
                    if not source_name:
                        source_name = rules_file.name

                result = import_rules_from_lines(lines, status=status, source_name=source_name)
                self.message_user(
                    request,
                    (
                        'Import complete: '
                        f"created={result['created']}, "
                        f"updated={result['updated']}, "
                        f"skipped={result['skipped']}, "
                        f"invalid={result['invalid']}"
                    ),
                    level=messages.SUCCESS,
                )

                if result['errors']:
                    self.message_user(
                        request,
                        'Some lines were invalid. First error: ' + result['errors'][0],
                        level=messages.WARNING,
                    )

                changelist_url = reverse('admin:fixlist_classificationrule_changelist')
                return HttpResponseRedirect(changelist_url)
        else:
            form = RuleImportForm()

        context = {
            **self.admin_site.each_context(request),
            'opts': self.model._meta,
            'title': 'Import classification rules',
            'form': form,
        }
        return TemplateResponse(request, 'admin/fixlist/classificationrule/import_rules.html', context)
