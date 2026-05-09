"""Tests for the `highlight_parsed` template filter used in templates/rules.html.

These cover the user-reported regression: two FRST `____D` directory rules
were highlighted inconsistently because rule.filepath stores the
normalize_path-rewritten value (`C:\\Users\\username\\...`), so the literal
substring lookup missed the original path. Now both should highlight the full
path with the parsed-filepath span.
"""

from django.contrib.auth.models import User
from django.test import TestCase

from ..models import ClassificationRule
from ..templatetags.rule_tags import highlight_parsed


class HighlightParsedTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = User.objects.create_user(username="alice", password="password123")

    def _rule(self, **kwargs):
        defaults = dict(
            owner=self.owner,
            status=ClassificationRule.STATUS_UNKNOWN,
            match_type=ClassificationRule.MATCH_PARSED_ENTRY,
        )
        defaults.update(kwargs)
        return ClassificationRule(**defaults)

    def test_non_parsed_rule_returns_escaped_text_only(self):
        rule = self._rule(
            match_type=ClassificationRule.MATCH_SUBSTRING,
            source_text="<script>alert(1)</script>",
        )
        rendered = str(highlight_parsed(rule))
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("parsed-", rendered)

    def test_filepath_highlight_when_path_appears_literally(self):
        # User example #1 — never normalized, stored filepath equals source.
        source = (
            r"2026-04-15 22:55 - 2026-04-15 22:55 - 000000000 ____D "
            r"C:\ProgramData\Zam"
        )
        rule = self._rule(
            source_text=source,
            entry_type="onemonth",
            filepath=r"C:\ProgramData\Zam",
            filename="Zam",
        )
        rendered = str(highlight_parsed(rule))
        self.assertIn(
            r'<span class="parsed-filepath">C:\ProgramData\Zam</span>',
            rendered,
        )

    def test_filepath_highlight_when_normalize_path_rewrote_username(self):
        # User example #2 (the bug case): rule.filepath has "username", source has "Lucian".
        # Before the fix, only "Raxec" (filename) lit up. After: full path lights up.
        source = (
            r"2026-04-14 18:05 - 2026-04-14 18:05 - 000000000 ____D "
            r"C:\Users\Lucian\Raxec"
        )
        rule = self._rule(
            source_text=source,
            entry_type="onemonth",
            filepath=r"C:\Users\username\Raxec",
            filename="Raxec",
        )
        rendered = str(highlight_parsed(rule))
        self.assertIn(
            r'<span class="parsed-filepath">C:\Users\Lucian\Raxec</span>',
            rendered,
        )

    def test_filepath_highlight_handles_drive_letter_substitution(self):
        # normalize_path forces drive to C:; source had a different drive.
        source = "service entry pointing to D:\\Tools\\bad.exe in line"
        rule = self._rule(
            source_text=source,
            entry_type="service",
            filepath=r"C:\Tools\bad.exe",
            filename="bad.exe",
        )
        rendered = str(highlight_parsed(rule))
        self.assertIn(
            r'<span class="parsed-filepath">D:\Tools\bad.exe</span>',
            rendered,
        )

    def test_consistency_between_normalized_and_unnormalized_paths(self):
        # The user's complaint was about consistency between two similar rules.
        # Both should now produce a parsed-filepath span around the full path.
        source_a = (
            r"2026-04-15 22:55 - 2026-04-15 22:55 - 000000000 ____D "
            r"C:\ProgramData\Zam"
        )
        rule_a = self._rule(
            source_text=source_a,
            entry_type="onemonth",
            filepath=r"C:\ProgramData\Zam",
            filename="Zam",
        )
        source_b = (
            r"2026-04-14 18:05 - 2026-04-14 18:05 - 000000000 ____D "
            r"C:\Users\Lucian\Raxec"
        )
        rule_b = self._rule(
            source_text=source_b,
            entry_type="onemonth",
            filepath=r"C:\Users\username\Raxec",
            filename="Raxec",
        )

        rendered_a = str(highlight_parsed(rule_a))
        rendered_b = str(highlight_parsed(rule_b))
        self.assertIn('class="parsed-filepath"', rendered_a)
        self.assertIn('class="parsed-filepath"', rendered_b)
