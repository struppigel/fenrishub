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
