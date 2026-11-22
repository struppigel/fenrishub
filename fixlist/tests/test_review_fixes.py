"""Fixes from the second code review of the facts work."""

from unittest.mock import patch

from django.contrib.messages import get_messages
from django.db.models.query import QuerySet
from django.test import RequestFactory
from django.urls import reverse

from .. import log_layout
from ..analyzer import _apply_block_verdicts, analyze_log_text, find_rule_duplicates
from ..fact_service import ConditionSpec, condition_key_for, set_rule_conditions
from ..models import ClassificationRule, Fact, FactRule
from ..rule_sets import resolve_user_rule_set_key
from ..upload_utils import store_cached_analysis
from ..views.facts import _resolve_fact, _save_fact
from ..views.llm_api import _served_analysis
from .factories import make_uploaded_log
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase

B = ClassificationRule.STATUS_MALWARE

SPOR = "\n".join([
    "==================== PERSISTENCE - autostarts ====================",
    "2026-11-20 08:14:02 [task] \\Microsoft\\Windows\\UpdateCheck",
    "    program: C:\\Users\\anna\\AppData\\Roaming\\svc\\run.exe [unsigned]",
])


class ReviewFixTests(LogAnalyzerApiBaseTestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)

    def test_a_filepath_fallback_does_not_spread_over_the_block(self):
        rule = ClassificationRule.objects.create(
            owner=self.user, status=B, match_type="parsed", source_text="x", apply_to_block=True,
        )
        walked = log_layout.analyzed_lines(SPOR)
        structure = log_layout.layout(SPOR, "Spor")
        lines = [{"rule_ids": []}, {"rule_ids": [rule.pk]}, {"rule_ids": []}]
        before = [dict(line) for line in lines]
        # The item line was decided through the rule's stored path alone.
        line_matches = {1: (None, [(rule, "found matching normalized path", "filepath")]), 2: (None, [])}
        _apply_block_verdicts(lines, walked, {}, line_matches, structure, [w.line_no for w in walked])
        self.assertEqual(lines, before)

    def test_duplicates_keep_rules_with_other_options_apart(self):
        path = r"C:\x\evil.exe"
        # Same normalized path (what duplicates are grouped by), own source text
        # each (the unique constraint), and different options.
        for number, overrides in enumerate(({}, {"only_entry_types": ["service"]}, {"apply_to_block": True})):
            ClassificationRule.objects.create(
                owner=self.user, status=B, match_type="filepath", source_text=f"{path} #{number}",
                normalized_filepath=path.lower(), **overrides,
            )
        self.assertEqual(find_rule_duplicates(ClassificationRule.objects.all()), [])

    def test_token_api_analysis_names_facts(self):
        fact = Fact.objects.create(name="nvidia installed")
        FactRule.objects.create(owner=self.user, fact=fact, match_type="substring", source_text="NVIDIA")
        log = make_uploaded_log("with-facts", content="NVIDIA driver line", log_type="FRST")
        key = resolve_user_rule_set_key(self.user)
        store_cached_analysis(log, key, analyze_log_text(log.content, key, log.log_type))
        request = RequestFactory().get("/")
        request.user = self.user
        analysis, _key, error = _served_analysis(request, log)
        self.assertIsNone(error)
        self.assertEqual([item["name"] for item in analysis["facts"]], ["nvidia installed"])

    def test_resolve_fact_uses_a_fact_created_meanwhile(self):
        existing = Fact.objects.create(name="Kaspersky installed")
        # The first lookup misses it (created by someone else just after).
        with patch.object(QuerySet, "first", side_effect=[None, existing]):
            fact, error = _resolve_fact(self.user, "new", "kaspersky INSTALLED")
        self.assertIsNone(error)
        self.assertEqual(fact, existing)
        self.assertEqual(Fact.objects.count(), 1)

    def test_save_fact_reports_a_name_taken_meanwhile(self):
        Fact.objects.create(name="Kaspersky installed")
        fact, error = _save_fact(None, self.user, "kaspersky installed", "", [])
        self.assertIsNone(fact)
        self.assertIn("already exists", error)

    def test_deleting_a_fact_that_got_a_condition_meanwhile(self):
        fact = Fact.objects.create(name="f")
        specs = [ConditionSpec(fact.pk, "require", "log")]
        rule = ClassificationRule.objects.create(
            owner=self.user, status=B, match_type="substring", source_text="x", condition_key=condition_key_for(specs),
        )
        set_rule_conditions(rule, specs)
        # The check passed before the condition existed.
        with patch("fixlist.views.facts.fact_delete_error", return_value=""):
            response = self.client.post(reverse("facts"), {"action": "delete", "pk": fact.pk})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Fact.objects.filter(pk=fact.pk).exists())
        self.assertIn("remove those conditions first", " ".join(str(m) for m in get_messages(response.wsgi_request)))

    def test_unticking_all_log_lines_without_types_saves_an_unrestricted_rule(self):
        self.client.post(reverse("add_rule"), {
            "status": B, "match_type": "substring", "source_text": "evil", "priority": "",
            "only_entry_types_present": "1",
        })
        self.assertEqual(ClassificationRule.objects.get(source_text="evil").only_entry_types, [])
