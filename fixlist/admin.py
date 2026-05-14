from django import forms
from django.contrib import admin, messages
from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import path, reverse

from .analyzer import import_rules_from_lines
from .models import (
    AccessLog,
    ClassificationRule,
    Fixlist,
    FixlistSnippet,
    InfectionCase,
    InfectionCaseFixlist,
    InfectionCaseLog,
    InfectionCaseNote,
    ParsedFilepathExclusion,
    SiteConfig,
    UploadedLog,
)


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


class ChangeRuleOwnerForm(forms.Form):
    new_owner = forms.ModelChoiceField(
        queryset=User.objects.order_by('username'),
        label='New owner',
    )
    limit_to_last_n = forms.IntegerField(
        required=False,
        min_value=1,
        label='Limit to last N (optional)',
        help_text='If set, restricts the reassignment to the most recently created N rules from the selection.',
    )


@admin.register(Fixlist)
class FixlistAdmin(admin.ModelAdmin):
    list_display = ('username', 'owner', 'download_count', 'created_at', 'share_token')
    list_filter = ('created_at', 'is_public')
    search_fields = ('username', 'owner__username')
    readonly_fields = ('download_count', 'share_token', 'created_at', 'updated_at')
    fields = ('owner', 'username', 'content', 'internal_note', 'download_count', 'share_token', 'created_at', 'updated_at', 'is_public')


@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = ('fixlist', 'accessed_at', 'ip_address')
    list_filter = ('accessed_at',)
    readonly_fields = ('accessed_at', 'ip_address')


@admin.register(ClassificationRule)
class ClassificationRuleAdmin(admin.ModelAdmin):
    change_list_template = 'admin/fixlist/classificationrule/change_list.html'
    list_display = ('status', 'owner', 'match_type', 'entry_type', 'short_source', 'company', 'source_name', 'is_enabled', 'updated_at')
    list_filter = ('status', 'owner', 'match_type', 'entry_type', 'is_enabled', 'source_name')
    search_fields = ('source_text', 'description', 'name', 'filepath', 'clsid', 'company', 'owner__username')
    readonly_fields = ('created_at', 'updated_at')
    actions = ['change_owner']

    fieldsets = (
        (
            None,
            {
                'fields': (
                    'status',
                    'owner',
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
            },
        ),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )

    def short_source(self, obj):
        if len(obj.source_text) <= 80:
            return obj.source_text
        return obj.source_text[:77] + '...'

    short_source.short_description = 'source_text'

    @admin.action(description='Change owner of selected rules…')
    def change_owner(self, request, queryset):
        if request.POST.get('apply'):
            form = ChangeRuleOwnerForm(request.POST)
            if form.is_valid():
                new_owner = form.cleaned_data['new_owner']
                limit_n = form.cleaned_data.get('limit_to_last_n')
                if limit_n:
                    target_pks = list(
                        queryset.order_by('-created_at').values_list('pk', flat=True)[:limit_n]
                    )
                else:
                    target_pks = list(queryset.values_list('pk', flat=True))

                target_qs = ClassificationRule.objects.filter(pk__in=target_pks)

                try:
                    with transaction.atomic():
                        updated = target_qs.exclude(owner=new_owner).update(owner=new_owner)
                    skipped_conflicts = []
                    already_owned = target_qs.filter(owner=new_owner).count()
                except IntegrityError:
                    updated = 0
                    already_owned = 0
                    skipped_conflicts = []
                    for rule in target_qs.iterator():
                        if rule.owner_id == new_owner.id:
                            already_owned += 1
                            continue
                        try:
                            with transaction.atomic():
                                ClassificationRule.objects.filter(pk=rule.pk).update(
                                    owner=new_owner,
                                )
                            updated += 1
                        except IntegrityError:
                            skipped_conflicts.append(rule)

                parts = [f'Reassigned {updated} rule(s) to {new_owner.username}.']
                if already_owned:
                    parts.append(
                        f'Skipped {already_owned} already owned by {new_owner.username}.'
                    )
                if skipped_conflicts:
                    examples = '; '.join(
                        f'#{r.pk} [{r.match_type}] {r.source_text[:60]}'
                        for r in skipped_conflicts[:5]
                    )
                    suffix = '' if len(skipped_conflicts) <= 5 else ' (…)'
                    parts.append(
                        f'Skipped {len(skipped_conflicts)} due to existing '
                        f'(status, match_type, source_text) collisions under '
                        f'{new_owner.username}: {examples}{suffix}'
                    )
                level = messages.WARNING if skipped_conflicts else messages.SUCCESS
                self.message_user(request, ' '.join(parts), level=level)
                return None
        else:
            form = ChangeRuleOwnerForm()

        context = {
            **self.admin_site.each_context(request),
            'opts': self.model._meta,
            'title': 'Change owner of selected rules',
            'form': form,
            'rule_count': queryset.count(),
            'selected_ids': list(queryset.values_list('pk', flat=True)),
            'action_name': 'change_owner',
        }
        return TemplateResponse(
            request,
            'admin/fixlist/classificationrule/change_owner.html',
            context,
        )

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

                result = import_rules_from_lines(
                    lines,
                    status=status,
                    source_name=source_name,
                    owner=request.user,
                )
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


@admin.register(FixlistSnippet)
class FixlistSnippetAdmin(admin.ModelAdmin):
    list_display = ('name', 'owner', 'updated_at')
    list_filter = ('owner',)
    search_fields = ('name', 'content')
    readonly_fields = ('created_at', 'updated_at')
    fields = ('owner', 'name', 'content', 'created_at', 'updated_at')


@admin.register(UploadedLog)
class UploadedLogAdmin(admin.ModelAdmin):
    list_display = ('upload_id', 'reddit_username', 'log_type', 'is_incomplete', 'created_by', 'recipient_user', 'created_at')
    list_filter = ('log_type', 'is_incomplete', 'created_at')
    search_fields = ('upload_id', 'reddit_username', 'original_filename')
    readonly_fields = ('upload_id', 'content_hash', 'detected_encoding', 'created_at', 'updated_at')
    fieldsets = (
        (None, {
            'fields': ('upload_id', 'reddit_username', 'original_filename', 'log_type', 'is_incomplete', 'created_by', 'recipient_user'),
        }),
        ('Content', {
            'fields': ('content', 'content_hash', 'detected_encoding'),
            'classes': ('collapse',),
        }),
        ('Analysis Stats', {
            'fields': (
                'total_line_count',
                'count_malware', 'count_pup', 'count_clean', 'count_alert', 'count_warning',
                'count_grayware', 'count_security', 'count_info', 'count_junk', 'count_unknown',
                'fixlog_total', 'fixlog_success', 'fixlog_not_found', 'fixlog_error',
            ),
            'classes': ('collapse',),
        }),
        ('Timestamps', {'fields': ('created_at', 'updated_at', 'deleted_at')}),
    )


class InfectionCaseLogInline(admin.TabularInline):
    model = InfectionCaseLog
    extra = 0
    raw_id_fields = ('uploaded_log', 'added_by')
    readonly_fields = ('added_at',)


class InfectionCaseFixlistInline(admin.TabularInline):
    model = InfectionCaseFixlist
    extra = 0
    raw_id_fields = ('fixlist', 'added_by')
    readonly_fields = ('added_at',)


class InfectionCaseNoteInline(admin.TabularInline):
    model = InfectionCaseNote
    extra = 0
    raw_id_fields = ('created_by', 'anchor_log', 'anchor_note')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(InfectionCase)
class InfectionCaseAdmin(admin.ModelAdmin):
    list_display = ('case_id', 'username', 'owner', 'status', 'auto_assign_new_items', 'created_at')
    list_filter = ('status', 'auto_assign_new_items', 'created_at')
    search_fields = ('case_id', 'username', 'symptom_description', 'owner__username')
    readonly_fields = ('case_id', 'created_at', 'updated_at')
    fields = ('case_id', 'owner', 'username', 'symptom_description', 'reference_url', 'status', 'auto_assign_new_items', 'created_at', 'updated_at', 'deleted_at')
    inlines = [InfectionCaseLogInline, InfectionCaseFixlistInline, InfectionCaseNoteInline]


@admin.register(InfectionCaseLog)
class InfectionCaseLogAdmin(admin.ModelAdmin):
    list_display = ('case', 'uploaded_log', 'added_by', 'added_at')
    list_filter = ('added_at',)
    search_fields = ('case__case_id', 'uploaded_log__upload_id')
    raw_id_fields = ('case', 'uploaded_log', 'added_by')
    readonly_fields = ('added_at',)


@admin.register(InfectionCaseFixlist)
class InfectionCaseFixlistAdmin(admin.ModelAdmin):
    list_display = ('case', 'fixlist', 'added_by', 'added_at')
    list_filter = ('added_at',)
    search_fields = ('case__case_id',)
    raw_id_fields = ('case', 'fixlist', 'added_by')
    readonly_fields = ('added_at',)


@admin.register(InfectionCaseNote)
class InfectionCaseNoteAdmin(admin.ModelAdmin):
    list_display = ('case', 'short_content', 'created_by', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('case__case_id', 'content')
    raw_id_fields = ('case', 'created_by', 'anchor_log', 'anchor_note')
    readonly_fields = ('created_at', 'updated_at')
    fields = ('case', 'anchor_log', 'anchor_note', 'content', 'created_by', 'created_at', 'updated_at', 'deleted_at')

    def short_content(self, obj):
        return obj.content[:80] + '...' if len(obj.content) > 80 else obj.content
    short_content.short_description = 'Content'


@admin.register(ParsedFilepathExclusion)
class ParsedFilepathExclusionAdmin(admin.ModelAdmin):
    list_display = ('normalized_filepath', 'is_enabled', 'updated_at')
    list_filter = ('is_enabled',)
    search_fields = ('normalized_filepath', 'note')
    readonly_fields = ('created_at', 'updated_at')
    fields = ('normalized_filepath', 'note', 'is_enabled', 'created_at', 'updated_at')


@admin.register(SiteConfig)
class SiteConfigAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'guest_token_preview', 'updated_at')
    readonly_fields = ('updated_at',)
    fields = ('guest_token', 'updated_at')
    change_list_template = 'admin/fixlist/siteconfig/change_list.html'

    def guest_token_preview(self, obj):
        token = obj.guest_token or ''
        if not token:
            return '(disabled)'
        if len(token) <= 8:
            return token
        return f'{token[:4]}…{token[-4:]}'

    guest_token_preview.short_description = 'guest token'

    def has_add_permission(self, request):
        return not SiteConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                'regenerate-guest-token/',
                self.admin_site.admin_view(self.regenerate_guest_token_view),
                name='fixlist_siteconfig_regenerate_guest_token',
            ),
            path(
                'clear-guest-token/',
                self.admin_site.admin_view(self.clear_guest_token_view),
                name='fixlist_siteconfig_clear_guest_token',
            ),
        ]
        return custom_urls + urls

    def regenerate_guest_token_view(self, request):
        if request.method != 'POST':
            return HttpResponseRedirect(reverse('admin:fixlist_siteconfig_changelist'))
        config = SiteConfig.get_solo()
        config.guest_token = SiteConfig.generate_guest_token()
        config.save()
        self.message_user(
            request,
            f'New guest token generated: {config.guest_token}',
            level=messages.SUCCESS,
        )
        return HttpResponseRedirect(reverse('admin:fixlist_siteconfig_changelist'))

    def clear_guest_token_view(self, request):
        if request.method != 'POST':
            return HttpResponseRedirect(reverse('admin:fixlist_siteconfig_changelist'))
        config = SiteConfig.get_solo()
        config.guest_token = ''
        config.save()
        self.message_user(request, 'Guest access disabled.', level=messages.SUCCESS)
        return HttpResponseRedirect(reverse('admin:fixlist_siteconfig_changelist'))
