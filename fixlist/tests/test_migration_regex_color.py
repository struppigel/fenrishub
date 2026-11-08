"""Migration 0090: regex rules start colouring only their match; existing
Informational regex rules keep colouring the whole line (as 0074 did for
substring rules)."""
import importlib

from django.apps import apps
from django.test import TestCase

from ..models import ClassificationRule
from .factories import make_rule, make_user

migration = importlib.import_module('fixlist.migrations.0090_regex_rules_color_matched_text')


class RegexColorMigrationTests(TestCase):
    def test_only_informational_regex_rules_keep_the_whole_line(self):
        owner = make_user()
        info_regex = make_rule('info', status='I', match_type=ClassificationRule.MATCH_REGEX, owner=owner)
        bad_regex = make_rule('bad', status='B', match_type=ClassificationRule.MATCH_REGEX, owner=owner)
        info_substring = make_rule('sub', status='I', match_type=ClassificationRule.MATCH_SUBSTRING, owner=owner)

        migration.keep_existing_informational_regex_rules_whole_line(apps, None)

        for rule in (info_regex, bad_regex, info_substring):
            rule.refresh_from_db()
        self.assertTrue(info_regex.color_whole_line)
        self.assertFalse(bad_regex.color_whole_line)
        self.assertFalse(info_substring.color_whole_line)
