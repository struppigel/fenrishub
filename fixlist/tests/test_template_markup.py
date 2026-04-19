from pathlib import Path

from django.test import TestCase


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
