import re
from pathlib import Path

from django.test import TestCase


# Kept in one place so the help text, the resolver and this guard cannot drift apart.
SPEECH_PLACEHOLDERS = (
    "{HELPERNAME}",
    "{USERNAME}",
    "{UPLOADLINK_HELPER}",
    "{UPLOADLINK_HELPER_PREFILLED}",
    "{UPLOADLINK_GENERAL}",
    "{UPLOADLINK_GENERAL_PREFILLED}",
    "{COUNTER}",
)


class TemplateMarkupTests(TestCase):
    """
    Only regression-guard checks remain: each asserts that something deliberately
    removed from a template stays removed, or that a documented placeholder is
    still referenced. Positive "this string exists" checks against raw template
    source have been dropped in favour of behavioural view tests.
    """

    @staticmethod
    def _read_template(template_name):
        project_root = Path(__file__).resolve().parent.parent.parent
        return (project_root / "templates" / template_name).read_text(encoding="utf-8")

    def test_base_template_navigation_omits_upload_link(self):
        content = self._read_template("base.html")

        self.assertIn('{% url \'uploaded_logs\' %}', content)
        self.assertIn('{% url \'profile\' %}', content)
        self.assertNotIn('>upload</a>', content)

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

    def test_help_page_uses_no_em_or_en_dashes(self):
        """The help text is written with plain hyphens; long dashes stay out."""
        content = self._read_template("help.html")

        for dash, name in (("—", "em dash"), ("–", "en dash")):
            with self.subTest(dash=name):
                self.assertNotIn(dash, content, f"help.html must not contain a {name}")

    def test_no_template_opens_a_multiline_hash_comment(self):
        """
        Django's {# #} comment is single-line only. An unclosed one renders its
        text straight onto the page, so every {# must be closed on its own line.
        Multi-line notes belong in {% comment %} blocks.
        """
        project_root = Path(__file__).resolve().parent.parent.parent
        for template_path in sorted((project_root / "templates").rglob("*.html")):
            for number, line in enumerate(template_path.read_text(encoding="utf-8").splitlines(), 1):
                if "{#" in line and "#}" not in line:
                    self.fail(
                        f"{template_path.name}:{number} opens a {{# comment that is never "
                        f"closed on the same line; use {{% comment %}} instead: {line.strip()}"
                    )

    def test_analyzer_template_no_longer_claims_the_response_is_browser_only(self):
        content = self._read_template("log_analyzer.html")

        self.assertIn("{{ initial_response_text }}", content)
        self.assertNotIn("kept in this browser's draft, not saved to the server", content)
        self.assertNotIn("save fix", content)
        self.assertNotIn("update fix", content)

    def test_help_template_no_longer_claims_the_response_stays_local(self):
        content = self._read_template("help.html")

        self.assertNotIn("it is never sent to the server", content)

    def test_view_fixlist_template_tabs_have_no_required_textarea(self):
        content = self._read_template("view_fixlist.html")

        self.assertIn('name="response"', content)
        self.assertIn('id="activeTabInput"', content)
        self.assertIn('onclick="copyResponse(this)"', content)
        # A hidden `required` control blocks form submission silently.
        self.assertNotIn('id="content" name="content" required', content)

    def test_infection_case_template_handles_response_before_fixlist_fallback(self):
        content = self._read_template("view_infection_case.html")

        response_branch = content.find("item.item_type == 'response'")
        self.assertNotEqual(response_branch, -1)
        # The fixlist branch is the {% else %} fallback, so the response branch
        # must come first or response entries render as fixlists.
        self.assertLess(response_branch, content.find("{% else %}\n        {% with fixlist=item.fixlist %}"))

    def test_profile_template_mentions_frstpath_placeholder(self):
        content = self._read_template("profile.html")
        self.assertIn("{FRSTPATH}", content)

    def test_speeches_template_documents_every_supported_placeholder(self):
        """
        The variable list lives in the content textarea's placeholder on both the
        create and the edit form, and must not drift from applySpeechPlaceholders()
        in shared.js.
        """
        content = self._read_template("speeches.html")
        tags = re.findall(r'<textarea id="(?:createContent|editContent)"[^>]*>', content)
        self.assertEqual(len(tags), 2)
        for tag in tags:
            for placeholder in SPEECH_PLACEHOLDERS:
                with self.subTest(tag=tag[:40], placeholder=placeholder):
                    self.assertIn(placeholder, tag)

    def test_help_page_documents_every_supported_placeholder(self):
        content = self._read_template("help.html")
        for placeholder in SPEECH_PLACEHOLDERS:
            with self.subTest(placeholder=placeholder):
                self.assertIn(placeholder, content)

    def test_shared_js_resolves_every_documented_placeholder(self):
        project_root = Path(__file__).resolve().parent.parent.parent
        content = (project_root / "static" / "js" / "log_analyzer" / "shared.js").read_text(encoding="utf-8")
        for placeholder in SPEECH_PLACEHOLDERS:
            with self.subTest(placeholder=placeholder):
                self.assertIn(f"'{placeholder}'", content)

    def test_legend_filter_hides_lines_by_verdict_not_by_paint_class(self):
        """
        The legend counts lines by verdict (dominant_status), so its filter has to
        hide them by verdict too. A filepath-fallback match is deliberately painted
        `status-unknown` while its verdict is e.g. B, so selecting on the .status-*
        paint class made those lines vanish under a "B only" filter -- the legend
        said B (5) and only the one directly-painted B line stayed visible.
        renderLogLines() stamps data-verdict-class; the CSS must match on that.
        """
        project_root = Path(__file__).resolve().parent.parent.parent
        css = (project_root / "static" / "css" / "log_analyzer.css").read_text(encoding="utf-8")
        analysis_js = (
            project_root / "static" / "js" / "log_analyzer" / "analysis.js"
        ).read_text(encoding="utf-8")
        template = self._read_template("log_analyzer.html")

        self.assertIn("lineDiv.dataset.verdictClass = badgeClass;", analysis_js)

        legend_classes = set(re.findall(r'class="legend-item" data-status-class="([\w-]+)"', template))
        self.assertIn("status-b", legend_classes)

        for status_class in sorted(legend_classes):
            with self.subTest(status_class=status_class):
                self.assertIn(
                    f'.log-lines-container.hide-{status_class} > '
                    f'.log-line[data-verdict-class="{status_class}"]',
                    css,
                )

        stale = re.findall(r"\.hide-status-[\w-]+ > \.log-line\.status-[\w-]+", css)
        self.assertEqual(stale, [], f"legend filter still selects on the paint class: {stale}")

    def test_speech_placeholder_tokens_cannot_collide_by_prefix(self):
        """
        {UPLOADLINK_HELPER} is a prefix of {UPLOADLINK_HELPER_PREFILLED} apart from
        the closing brace. Drop a brace from either name and the shorter token would
        eat the longer one during substitution, yielding ".../upload/x/_PREFILLED}".
        """
        for token in SPEECH_PLACEHOLDERS:
            with self.subTest(token=token):
                self.assertTrue(token.startswith("{") and token.endswith("}"))
                others = [o for o in SPEECH_PLACEHOLDERS if o != token]
                self.assertFalse(any(token in other for other in others))
