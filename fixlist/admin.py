import csv
import io
import re

from django import forms
from django.contrib import admin, messages
from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import path, reverse

from .analyzer import (
    find_rule_duplicates,
    import_rules_from_lines,
    invalidate_rule_buckets_cache,
    reparse_rules,
)
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


class ChromeExtensionBulkUploadForm(forms.Form):
    csv_file = forms.FileField(
        help_text=(
            'CSV from mallorybowes/chrome-mal-ids '
            '(columns EXTID, EXTID-NAME, STILL-ACTIVE).'
        ),
    )


CHROME_EXT_ID_RE = re.compile(r'^[a-p]{32}$')
CHROME_EXT_SOURCE_NAME = 'chrome-mal-ids'
CHROME_EXT_SOURCE_URL = 'https://github.com/mallorybowes/chrome-mal-ids'
CHROME_EXT_NAME_SKIP = {'unknown', 'see source/notes fields'}
CHROME_EXT_CURLY_QUOTES = '“”‘’"\''


def _normalize_chrome_ext_name(raw):
    if not raw:
        return ''
    cleaned = raw.strip().strip(CHROME_EXT_CURLY_QUOTES).strip()
    if cleaned.lower() in CHROME_EXT_NAME_SKIP:
        return ''
    return cleaned


def _build_chrome_ext_description(name):
    if name:
        return f'{name} - {CHROME_EXT_SOURCE_URL}'
    return CHROME_EXT_SOURCE_URL


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
    actions = ['change_owner', 'strip_leading_case_insensitive_flag', 'reparse_from_source_text']

    fieldsets = (
        (
            None,
            {
                'fields': (
                    'status',
                    'owner',
                    'match_type',
                    'priority',
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
                    'attributes',
                    'is_hidden',
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

    @admin.action(description='Re-parse selected rules from source_text')
    def reparse_from_source_text(self, request, queryset):
        result = reparse_rules(queryset, apply=True)
        scanned = queryset.count()
        if result["changed"]:
            level = messages.SUCCESS
            preview = '; '.join(
                f"#{diff['rule'].id} ({', '.join(diff['fields'].keys())})"
                for diff in result["diffs"][:5]
            )
            suffix = '' if len(result["diffs"]) <= 5 else ' (…)'
            message = (
                f"Re-parsed {result['changed']} of {scanned} rule(s). "
                f"Unchanged: {result['unchanged']}. Unparseable: {result['unparseable']}. "
                f"Updated: {preview}{suffix}"
            )
        else:
            level = (
                messages.WARNING if result["unparseable"] else messages.INFO
            )
            message = (
                f"Scanned {scanned} rule(s). No parsed metadata differed from "
                f"the current parser. Unparseable: {result['unparseable']}."
            )
        self.message_user(request, message, level=level)

    @admin.action(description='Strip leading "(?i)" from selected regex rules')
    def strip_leading_case_insensitive_flag(self, request, queryset):
        prefix = '(?i)'
        regex_qs = queryset.filter(match_type=ClassificationRule.MATCH_REGEX)
        skipped_non_regex = queryset.count() - regex_qs.count()

        candidates = regex_qs.filter(source_text__startswith=prefix)
        skipped_no_prefix = regex_qs.count() - candidates.count()

        updated = 0
        skipped_conflicts = []
        skipped_empty = 0

        for rule in candidates.iterator():
            new_source = rule.source_text[len(prefix):]
            if not new_source:
                skipped_empty += 1
                continue
            try:
                with transaction.atomic():
                    rule.source_text = new_source
                    rule.save(update_fields=['source_text', 'updated_at'])
                updated += 1
            except IntegrityError:
                skipped_conflicts.append(rule)

        if updated:
            invalidate_rule_buckets_cache()

        parts = [f'Stripped "(?i)" prefix from {updated} regex rule(s).']
        if skipped_non_regex:
            parts.append(f'Skipped {skipped_non_regex} non-regex rule(s).')
        if skipped_no_prefix:
            parts.append(f'Skipped {skipped_no_prefix} regex rule(s) without "(?i)" prefix.')
        if skipped_empty:
            parts.append(f'Skipped {skipped_empty} where stripping would leave an empty pattern.')
        if skipped_conflicts:
            examples = '; '.join(
                f'#{r.pk} {r.source_text[:60]}'
                for r in skipped_conflicts[:5]
            )
            suffix = '' if len(skipped_conflicts) <= 5 else ' (…)'
            parts.append(
                f'Skipped {len(skipped_conflicts)} due to '
                f'(owner, status, match_type, source_text) collision: {examples}{suffix}'
            )
        level = (
            messages.WARNING
            if (skipped_conflicts or skipped_empty or skipped_non_regex)
            else messages.SUCCESS
        )
        self.message_user(request, ' '.join(parts), level=level)

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
            ),
            path(
                'import-chrome-extensions/',
                self.admin_site.admin_view(self.import_chrome_extensions_view),
                name='fixlist_classificationrule_import_chrome_extensions',
            ),
            path(
                'reparse-all/',
                self.admin_site.admin_view(self.reparse_all_view),
                name='fixlist_classificationrule_reparse_all',
            ),
            path(
                'duplicates/',
                self.admin_site.admin_view(self.duplicates_view),
                name='fixlist_classificationrule_duplicates',
            ),
        ]
        return custom_urls + urls

    def reparse_all_view(self, request):
        qs = ClassificationRule.objects.filter(
            match_type__in=(
                ClassificationRule.MATCH_PARSED_ENTRY,
                ClassificationRule.MATCH_FILEPATH,
            )
        )
        scanned = qs.count()

        if request.method == 'POST':
            result = reparse_rules(qs, apply=True)
            self.message_user(
                request,
                (
                    f"Re-parsed {result['changed']} of {scanned} rule(s). "
                    f"Unchanged: {result['unchanged']}. "
                    f"Skipped (match_type would change): {result['match_type_skip']}. "
                    f"Unparseable: {result['unparseable']}."
                ),
                level=messages.SUCCESS if result['changed'] else messages.INFO,
            )
            return HttpResponseRedirect(
                reverse('admin:fixlist_classificationrule_changelist')
            )

        from django.core.paginator import Paginator

        preview = reparse_rules(qs, apply=False)
        per_page = 50
        paginator = Paginator(preview['diffs'], per_page)
        page_number = request.GET.get('page') or 1
        page_obj = paginator.get_page(page_number)
        diff_preview = [
            {
                'rule': diff['rule'],
                'fields': [
                    {'name': name, 'old': old, 'new': new}
                    for name, (old, new) in diff['fields'].items()
                ],
            }
            for diff in page_obj.object_list
        ]
        context = {
            **self.admin_site.each_context(request),
            'opts': self.model._meta,
            'title': 'Re-parse all rules from source_text',
            'scanned': scanned,
            'changed': preview['changed'],
            'unchanged': preview['unchanged'],
            'unparseable': preview['unparseable'],
            'match_type_skip': preview['match_type_skip'],
            'diff_preview': diff_preview,
            'page_obj': page_obj,
            'paginator': paginator,
        }
        return TemplateResponse(
            request,
            'admin/fixlist/classificationrule/reparse_all.html',
            context,
        )

    def duplicates_view(self, request):
        qs = ClassificationRule.objects.filter(
            match_type__in=(
                ClassificationRule.MATCH_PARSED_ENTRY,
                ClassificationRule.MATCH_FILEPATH,
            )
        ).select_related('owner')

        if request.method == 'POST':
            raw_ids = request.POST.getlist('disable')
            ids = []
            for raw in raw_ids:
                try:
                    ids.append(int(raw))
                except (TypeError, ValueError):
                    continue
            action = 'delete' if 'action_delete' in request.POST else 'disable'
            count = 0
            if ids:
                if action == 'delete':
                    count, _ = ClassificationRule.objects.filter(pk__in=ids).delete()
                else:
                    count = ClassificationRule.objects.filter(
                        pk__in=ids, is_enabled=True
                    ).update(is_enabled=False)
                if count:
                    invalidate_rule_buckets_cache()
            verb = 'Deleted' if action == 'delete' else 'Disabled'
            self.message_user(
                request,
                f"{verb} {count} rule(s).",
                level=messages.SUCCESS if count else messages.INFO,
            )
            return HttpResponseRedirect(
                reverse('admin:fixlist_classificationrule_duplicates')
            )

        groups = find_rule_duplicates(qs)
        total_rules = sum(len(g) for g in groups)

        from django.core.paginator import Paginator
        paginator = Paginator(groups, 25)
        page_obj = paginator.get_page(request.GET.get('page') or 1)

        context = {
            **self.admin_site.each_context(request),
            'opts': self.model._meta,
            'title': 'Find duplicate rules',
            'scanned': qs.count(),
            'group_count': len(groups),
            'rule_count': total_rules,
            'group_page': page_obj.object_list,
            'page_obj': page_obj,
            'paginator': paginator,
        }
        return TemplateResponse(
            request,
            'admin/fixlist/classificationrule/duplicates.html',
            context,
        )

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

    def import_chrome_extensions_view(self, request):
        if request.method == 'POST':
            form = ChromeExtensionBulkUploadForm(request.POST, request.FILES)
            if form.is_valid():
                csv_file = form.cleaned_data['csv_file']
                raw = csv_file.read().decode('utf-8', errors='ignore')
                reader = csv.DictReader(io.StringIO(raw))

                rows_scanned = 0
                inactive_skipped = 0
                invalid_skipped = 0
                within_file_dupe_skipped = 0
                collected = {}  # extid -> description

                for row in reader:
                    rows_scanned += 1
                    extid = (row.get('EXTID') or '').strip()
                    if not extid:
                        continue
                    if not CHROME_EXT_ID_RE.match(extid):
                        invalid_skipped += 1
                        continue
                    still_active = (row.get('STILL-ACTIVE') or '').strip()
                    if still_active == '0':
                        inactive_skipped += 1
                        continue
                    if extid in collected:
                        within_file_dupe_skipped += 1
                        continue
                    name = _normalize_chrome_ext_name(row.get('EXTID-NAME'))
                    collected[extid] = _build_chrome_ext_description(name)

                existing = set(
                    ClassificationRule.objects.filter(
                        status=ClassificationRule.STATUS_MALWARE,
                        match_type=ClassificationRule.MATCH_SUBSTRING,
                        source_text__in=list(collected.keys()),
                    ).values_list('source_text', flat=True)
                )

                priority = ClassificationRule.default_priority_for(
                    ClassificationRule.MATCH_SUBSTRING
                )
                to_create = [
                    ClassificationRule(
                        owner=request.user,
                        status=ClassificationRule.STATUS_MALWARE,
                        match_type=ClassificationRule.MATCH_SUBSTRING,
                        source_text=extid,
                        description=description,
                        source_name=CHROME_EXT_SOURCE_NAME,
                        priority=priority,
                    )
                    for extid, description in collected.items()
                    if extid not in existing
                ]
                duplicate_skipped = len(collected) - len(to_create)

                if to_create:
                    ClassificationRule.objects.bulk_create(to_create)
                    invalidate_rule_buckets_cache()

                self.message_user(
                    request,
                    (
                        f'Chrome extension import complete: '
                        f'scanned={rows_scanned}, '
                        f'created={len(to_create)}, '
                        f'skipped_duplicate={duplicate_skipped}, '
                        f'skipped_within_file={within_file_dupe_skipped}, '
                        f'skipped_inactive={inactive_skipped}, '
                        f'skipped_invalid={invalid_skipped}'
                    ),
                    level=messages.SUCCESS if to_create else messages.INFO,
                )
                return HttpResponseRedirect(
                    reverse('admin:fixlist_classificationrule_changelist')
                )
        else:
            form = ChromeExtensionBulkUploadForm()

        context = {
            **self.admin_site.each_context(request),
            'opts': self.model._meta,
            'title': 'Import malicious Chrome extension IDs',
            'form': form,
        }
        return TemplateResponse(
            request,
            'admin/fixlist/classificationrule/import_chrome_extensions.html',
            context,
        )


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
