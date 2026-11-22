"""The rule editor's previews check a candidate rule's conditions: the pasted
text as one small log, stored logs from the facts of their cached analysis."""

import json

from django.urls import reverse

from ..analyzer import (
    _load_rule_buckets, analyze_log_text, condition_report, conditions_for_specs, find_facts,
    invalidate_rule_buckets_cache,
)
from ..fact_service import ConditionSpec
from ..models import ClassificationRule, Fact, FactRule, FactTagSource, RuleCondition, RuleTag
from ..rule_sets import resolve_user_rule_set_key
from ..upload_utils import store_cached_analysis
from .factories import make_uploaded_log
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase

B = ClassificationRule.STATUS_MALWARE
REQUIRE, FORBID = RuleCondition.POLARITY_REQUIRE, RuleCondition.POLARITY_FORBID

NVIDIA = r"R2 nvlddmkm; C:\Windows\System32\DriverStore\nvlddmkm.sys [1 2026-01-01] (NVIDIA Corporation)"
TARGET = r"HKLM\...\Run: [Updater] => C:\Users\a\AppData\Roaming\upd.exe [123 2026-01-01] () [File not signed]"
PASTED = "\n".join([NVIDIA, "", TARGET])

SPOR = "\n".join([
    "==================== PERSISTENCE - autostarts ====================",
    "2026-11-20 08:14:02 [task] \\Microsoft\\Windows\\UpdateCheck",
    "    program: C:\\Users\\anna\\AppData\\Roaming\\svc\\run.exe [unsigned]",
    "2026-11-20 08:15:02 [task] \\Microsoft\\Windows\\Defrag",
    "    program: C:\\Windows\\System32\\defrag.exe",
])


class PreviewConditionTests(LogAnalyzerApiBaseTestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)
        self.fact = Fact.objects.create(name="nvidia installed")
        self.fact_rule = FactRule.objects.create(
            owner=self.user, fact=self.fact, match_type="substring", source_text="NVIDIA Corporation",
        )

    def _conditions(self, polarity, scope=RuleCondition.SCOPE_LOG, fact=None):
        return [{"fact_id": (fact or self.fact).pk, "polarity": polarity, "scope": scope}]

    def _preview(self, text, conditions, source_text="upd.exe", **extra):
        lines = [line for line in text.split("\n") if line.strip()]
        response = self.client.post(reverse("test_rule_api"), data=json.dumps({
            "source_text": source_text, "status": B, "match_type": "substring",
            "lines": lines, "log_text": text, "conditions": conditions, **extra,
        }), content_type="application/json")
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()["results"]

    # -- the shared pieces --

    def test_find_facts_finds_what_the_analysis_finds(self):
        tag = RuleTag.objects.create(name="NVIDIA")
        ClassificationRule.objects.create(
            owner=self.user, status="S", match_type="substring", source_text="nvlddmkm",
        ).tags.add(tag)
        FactTagSource.objects.create(fact=Fact.objects.create(name="nvidia driver"), tag=tag)
        invalidate_rule_buckets_cache()
        facts, _walked = find_facts(PASTED, _load_rule_buckets("shared"))
        expected = analyze_log_text(PASTED)["facts"]
        self.assertEqual(
            sorted((fid, facts.lines_of(fid)) for fid in facts.fact_ids()),
            sorted((item["id"], item["line_indexes"]) for item in expected),
        )

    def test_condition_report_explains_hold_and_fail(self):
        facts, walked = find_facts(PASTED, _load_rule_buckets("shared"))
        line_nos = [item.line_no for item in walked]
        forbid = conditions_for_specs([ConditionSpec(self.fact.pk, FORBID, RuleCondition.SCOPE_LOG)])
        require = conditions_for_specs([ConditionSpec(self.fact.pk, REQUIRE, RuleCondition.SCOPE_LOG)])
        self.assertEqual(
            condition_report(forbid, facts, 1, None, line_nos),
            (False, 'forbids "nvidia installed" in the log (L1)'),
        )
        self.assertEqual(
            condition_report(require, facts, 1, None, line_nos),
            (True, 'requires "nvidia installed" in the log (L1)'),
        )

    # -- pasted lines --

    def test_forbid_fails_on_pasted_text_with_the_fact(self):
        nvidia, target = self._preview(PASTED, self._conditions(FORBID))
        self.assertFalse(target["matched"])
        self.assertEqual(target["condition_note"], 'not applied: forbids "nvidia installed" in the log (L1)')
        self.assertNotIn("condition_note", nvidia)

    def test_forbid_holds_without_the_fact(self):
        [target] = self._preview(TARGET, self._conditions(FORBID))
        self.assertTrue(target["matched"])
        self.assertTrue(target["condition_note"].startswith("conditions hold:"))

    def test_require_holds(self):
        _nvidia, target = self._preview(PASTED, self._conditions(REQUIRE))
        self.assertTrue(target["matched"])
        self.assertEqual(target["condition_note"], 'conditions hold: requires "nvidia installed" in the log (L1)')

    def test_block_scope_on_pasted_spor_text(self):
        roaming = Fact.objects.create(name="runs from Roaming")
        FactRule.objects.create(
            owner=self.user, fact=roaming, match_type="substring", source_text="\\AppData\\Roaming\\",
            all_log_types=True,
        )
        results = self._preview(
            SPOR, self._conditions(REQUIRE, RuleCondition.SCOPE_BLOCK, roaming), source_text="[task]",
            log_types=["Spor"],
        )
        matched = [result["line"] for result in results if result["matched"]]
        self.assertEqual(len(matched), 1)
        self.assertIn("UpdateCheck", matched[0])

    def test_lines_not_matching_the_text_are_not_checked(self):
        lines = [TARGET]
        response = self.client.post(reverse("test_rule_api"), data=json.dumps({
            "source_text": "upd.exe", "status": B, "match_type": "substring",
            "lines": lines, "log_text": PASTED, "conditions": self._conditions(FORBID),
        }), content_type="application/json")
        [target] = response.json()["results"]
        self.assertTrue(target["matched"])
        self.assertEqual(target["condition_note"], "conditions not checked")

    def test_unknown_fact_is_refused(self):
        response = self.client.post(reverse("test_rule_api"), data=json.dumps({
            "source_text": "upd.exe", "status": B, "match_type": "substring", "lines": [TARGET],
            "conditions": [{"fact_id": 99999, "polarity": "require", "scope": "log"}],
        }), content_type="application/json")
        self.assertEqual(response.status_code, 400)

    # -- stored logs --

    def _stored(self, upload_id, content, analyze=True):
        log = make_uploaded_log(upload_id, content=content, log_type="FRST&Addition")
        if analyze:
            key = resolve_user_rule_set_key(self.user)
            store_cached_analysis(log, key, analyze_log_text(content, key, log.log_type))
        return log

    def _scan(self, conditions):
        response = self.client.post(reverse("test_rule_logs_api"), data=json.dumps({
            "source_text": "upd.exe", "status": B, "match_type": "substring", "conditions": conditions,
        }), content_type="application/json")
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def test_stored_log_with_the_fact_is_left_out(self):
        self._stored("with-nvidia", PASTED)
        self._stored("without-nvidia", TARGET)
        data = self._scan(self._conditions(FORBID))
        [result] = data["results"]
        self.assertEqual([ref["upload_id"] for ref in result["logs"]], ["without-nvidia"])
        self.assertEqual(data["conditions_unchecked_logs"], 0)

    def test_logs_analyzed_before_the_fact_changed_are_unchecked(self):
        self._stored("with-nvidia", PASTED)
        self.fact_rule.description = "changed after the analysis"
        self.fact_rule.save()
        data = self._scan(self._conditions(FORBID))
        [result] = data["results"]
        self.assertEqual(result["logs"], [{"upload_id": "with-nvidia", "line_number": 3, "conditions": "unchecked"}])
        self.assertEqual(data["conditions_unchecked_logs"], 1)

    def test_logs_without_an_analysis_are_unchecked(self):
        self._stored("never-analyzed", PASTED, analyze=False)
        data = self._scan(self._conditions(FORBID))
        self.assertEqual(data["conditions_unchecked_logs"], 1)

    def test_without_conditions_the_scan_is_unchanged(self):
        self._stored("with-nvidia", PASTED, analyze=False)
        data = self._scan([])
        [result] = data["results"]
        self.assertEqual(result["logs"], [{"upload_id": "with-nvidia", "line_number": 3}])
