from pathlib import Path

from django.test import TestCase

class TemplateMarkupTests(TestCase):
    @staticmethod
    def _read_template(template_name):
        project_root = Path(__file__).resolve().parent.parent.parent
        template_path = project_root / "templates" / template_name
        return template_path.read_text(encoding="utf-8")

    @staticmethod
    def _read_static_asset(*relative_parts):
        project_root = Path(__file__).resolve().parent.parent.parent
        asset_path = project_root / "static"
        for part in relative_parts:
            asset_path = asset_path / part
        return asset_path.read_text(encoding="utf-8")

    def test_view_fixlist_template_has_preview_guest_button(self):
        content = self._read_template("view_fixlist.html")

        self.assertIn("preview guest view", content)
        self.assertIn("view source log", content)
        self.assertIn("copy fix message", content)
        self.assertIn("{USERNAME}", content)
        self.assertIn("{HELPERNAME}", content)
        self.assertIn("{FIXLISTLINK}", content)
        self.assertIn("{FRSTPATH}", content)
        self.assertIn('href="{{ guest_preview_url }}"', content)
        self.assertIn('value="disable_public"', content)
        self.assertIn('value="enable_public"', content)

    def test_shared_fixlist_template_contains_modal_warning_flow(self):
        content = self._read_template("shared_fixlist.html")

        self.assertIn("id=\"agreement-modal\"", content)
        self.assertIn("Executing a Fixlist on the wrong system may permanently damage it", content)
        self.assertIn("class=\"muted consent-note\"", content)
        self.assertIn("shared-content-locked", content)
        self.assertNotIn("before you continue", content)
        self.assertNotIn("leave page", content)

    def test_dashboard_template_actions_share_action_button_class(self):
        content = self._read_template("dashboard.html")

        self.assertIn('class="action-btn" onclick="copyShareLink', content)
        self.assertIn('class="action-btn">view</a>', content)
        self.assertIn('name="action" value="disable_public"', content)
        self.assertIn('name="action" value="enable_public"', content)

    def test_dashboard_template_delete_button_text(self):
        content = self._read_template("dashboard.html")

        self.assertIn('class="action-btn delete-btn"', content)
        self.assertIn('>delete</button>', content)
        self.assertNotIn('>trash</button>', content)

    def test_base_template_navigation_omits_upload_link(self):
        content = self._read_template("base.html")

        self.assertIn('{% url \'uploaded_logs\' %}', content)
        self.assertIn('{% url \'profile\' %}', content)
        self.assertNotIn('>upload</a>', content)

    def test_upload_templates_include_upload_toolbar_and_copy_id_ui(self):
        upload_page = self._read_template("upload_log.html")
        uploads_page = self._read_template("uploaded_logs.html")

        self.assertIn('id="uploadedLogId"', upload_page)
        self.assertIn('copyUploadId', upload_page)
        self.assertIn('target_helper', upload_page)
        self.assertIn('>upload<', uploads_page)
        self.assertIn('>merge<', uploads_page)
        self.assertIn('>rescan<', uploads_page)
        self.assertIn('helperUploadUrl', uploads_page)
        self.assertIn('copyHelperUploadUrl', uploads_page)
        self.assertIn("{% url 'upload_log_for_helper' request.user.username %}", uploads_page)
        self.assertIn('>analyze</a>', uploads_page)
        self.assertIn('?upload_id={{ uploaded_log.upload_id|urlencode }}', uploads_page)
        self.assertIn('class="merge-controls button-group"', uploads_page)
        self.assertIn('name="action" value="delete_selected"', uploads_page)
        self.assertIn('confirmDeleteSelected', uploads_page)
        self.assertIn('lines {{ uploaded_log.total_line_count }}', uploads_page)
        self.assertIn('? {{ uploaded_log.count_unknown }}', uploads_page)

    def test_log_analyzer_template_contains_status_picker_hooks(self):
        content = self._read_template("log_analyzer.html")
        script_content = "\n".join(
            [
                self._read_static_asset("js", "log_analyzer", "shared.js"),
                self._read_static_asset("js", "log_analyzer", "analysis.js"),
                self._read_static_asset("js", "log_analyzer", "conflict_wizard.js"),
                self._read_static_asset("js", "log_analyzer", "rule_preview.js"),
                self._read_static_asset("js", "log_analyzer", "bootstrap.js"),
            ]
        )

        self.assertIn('id="statusPicker"', content)
        self.assertIn('id="conflictWizardModal"', content)
        self.assertIn('id="ruleReviewDialog"', content)
        self.assertIn('id="conflictWizardDialog"', content)
        self.assertIn('id="plannedExistingRuleChangesList"', content)
        self.assertIn('id="saveRulesRescanButton"', content)
        self.assertIn('>save rules<', content)
        self.assertIn('id="questionCursorModeButton"', content)
        self.assertIn('id="lineInspectorModal"', content)
        self.assertIn('id="lineInspectorDialog"', content)
        self.assertIn('data-insert-status="!"', content)
        self.assertIn('id="saveFixlistButton"', content)
        self.assertIn('id="conflictWizardBackButton"', content)
        self.assertIn('id="bulkIgnoreFirewallRules"', content)
        self.assertIn('role="radiogroup"', content)
        self.assertNotIn("onclick=", content)
        self.assertIn("window.logAnalyzerConfig", content)
        self.assertIn("{% static 'css/log_analyzer.css' %}", content)
        self.assertIn("{% static 'js/log_analyzer/shared.js' %}", content)
        self.assertIn("{% static 'js/log_analyzer/analysis.js' %}", content)
        self.assertIn("{% static 'js/log_analyzer/conflict_wizard.js' %}", content)
        self.assertIn("{% static 'js/log_analyzer/rule_preview.js' %}", content)
        self.assertIn("{% static 'js/log_analyzer/bootstrap.js' %}", content)
        self.assertIn("persistRuleChangesUrl", content)

        self.assertIn("fenrishub_pending_status_changes", script_content)
        self.assertIn("manual override:", script_content)
        self.assertIn("renderContradictionListsForRule", script_content)
        self.assertIn("No dominant-status contradictions were detected.", script_content)
        self.assertIn("advanceConflictWizard", script_content)
        self.assertIn("pending_change_id", script_content)
        self.assertIn("existing status changes", script_content)
        self.assertIn("PERSIST_RULE_CHANGES_URL", script_content)
        self.assertIn("persistPendingRuleChanges", script_content)
        self.assertIn("RULE_SUBMIT_TARGET_RESCAN", script_content)
        self.assertIn("saveRulesAndRescan", script_content)
        self.assertIn("function clearPendingAnalyzerChanges()", script_content)
        self.assertIn("clearPendingAnalyzerChanges();", script_content)
        self.assertIn("toggleQuestionCursorMode", script_content)
        self.assertIn("openLineInspectorModal", script_content)
        self.assertIn("bindAnalyzerButton('saveRulesRescanButton'", script_content)
        self.assertIn("bulkIgnoreFirewallRules", script_content)
        self.assertIn("shouldSkipFirewallRulesLine", script_content)
        self.assertIn("firewallrules:", script_content.lower())
        self.assertIn("cancelRuleWorkflow", script_content)
        self.assertIn("ruleReviewBackdrop.addEventListener('click', () => cancelRuleWorkflow())", script_content)
        self.assertIn("has-pending-changes", script_content)
        self.assertIn("Object.assign(window", script_content)
        self.assertIn("handleAnalyzerModalOpen", script_content)
        self.assertIn("focusStatusPickerButton", script_content)
        self.assertIn("lineDetailsUrl", content)
        self.assertIn("initialUploadId", content)
        self.assertIn("isSuperuser", content)
        self.assertIn("loadInitialUploadForAnalyzer", script_content)
        self.assertIn("config.initialUploadId", script_content)
        self.assertNotIn("{% url 'analyze_log_api' %}", script_content)
        self.assertIn("addRemainingAsClean", script_content)
        self.assertIn("addRemainingCleanButton", script_content)
        self.assertIn("is_superuser", content)

    def test_log_analyzer_legend_has_toggle_data_attributes_for_all_statuses(self):
        content = self._read_template("log_analyzer.html")

        expected_statuses = [
            ("status-b", "B"),
            ("status-p", "P"),
            ("status-c", "C"),
            ("status-w", "!"),
            ("status-a", "A"),
            ("status-g", "G"),
            ("status-s", "S"),
            ("status-i", "I"),
            ("status-j", "J"),
            ("status-unknown", "?"),
        ]
        for status_class, label in expected_statuses:
            self.assertIn(
                f'data-status-class="{status_class}"',
                content,
                f"Legend item missing data-status-class for {label}",
            )

    def test_log_analyzer_css_has_legend_toggle_hide_rules(self):
        css_content = self._read_static_asset("css", "log_analyzer.css")

        hide_classes = [
            "hide-status-b",
            "hide-status-p",
            "hide-status-c",
            "hide-status-w",
            "hide-status-a",
            "hide-status-g",
            "hide-status-s",
            "hide-status-i",
            "hide-status-j",
            "hide-status-unknown",
        ]
        for hide_class in hide_classes:
            self.assertIn(hide_class, css_content)

        self.assertIn("legend-hidden", css_content)

    def test_log_analyzer_js_has_legend_toggle_functions(self):
        shared_js = self._read_static_asset("js", "log_analyzer", "shared.js")
        bootstrap_js = self._read_static_asset("js", "log_analyzer", "bootstrap.js")

        self.assertIn("HIDE_CLASS_PREFIX", shared_js)
        self.assertIn("hiddenStatuses", shared_js)
        self.assertIn("ALL_LEGEND_STATUS_CLASSES", shared_js)
        self.assertIn("toggleStatusVisibility", bootstrap_js)
        self.assertIn("toggleAllStatusVisibility", bootstrap_js)
        self.assertIn("bindLegendToggle", bootstrap_js)
        self.assertIn("legend-hidden", bootstrap_js)
        self.assertIn("legendToggleAllButton", bootstrap_js)

    def test_log_analyzer_legend_has_toggle_all_button(self):
        content = self._read_template("log_analyzer.html")
        css_content = self._read_static_asset("css", "log_analyzer.css")

        self.assertIn('id="legendToggleAllButton"', content)
        self.assertIn("legend-toggle-all", content)
        self.assertIn(".legend-toggle-all", css_content)

    def test_create_fixlist_template_only_uses_prefill_handoff(self):
        content = self._read_template("create_fixlist.html")

        self.assertIn("fenrishub_prefill_content", content)
        self.assertIn('name="source_upload_id"', content)
        self.assertNotIn('id="persistRulesInput"', content)
        self.assertNotIn('id="pendingRuleChangesInput"', content)
        self.assertNotIn('id="selectedRuleIdsInput"', content)
        self.assertNotIn('id="conflictResolutionsInput"', content)
        self.assertNotIn("fenrishub_persist_rules", content)
        self.assertNotIn("fenrishub_pending_rule_changes", content)
        self.assertNotIn("fenrishub_selected_rule_ids", content)
        self.assertNotIn("fenrishub_conflict_resolutions", content)

    def test_profile_template_mentions_frstpath_placeholder(self):
        content = self._read_template("profile.html")
        self.assertIn("{FRSTPATH}", content)


