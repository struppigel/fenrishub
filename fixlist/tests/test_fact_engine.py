"""How the analyzer finds facts: fact rules (own patterns, also whole-log)
and tag sources (classification rules with a tag that matched). Facts never
change a line's verdict, colouring or rule ids."""

from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.urls import reverse

from ..analyzer import _current_rules_version, analyze_log_text, invalidate_rule_buckets_cache, parse_rule_line
from ..fact_service import attach_fact_info, invalidate_if_tags_referenced
from ..models import ClassificationRule, Fact, FactRule, FactTagSource, RuleTag, UserProfile
from ..tagging import apply_tag
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase

B = ClassificationRule.STATUS_MALWARE
C = ClassificationRule.STATUS_CLEAN
S = ClassificationRule.STATUS_SECURITY
A = ClassificationRule.STATUS_ALERT

SERVICE_PATH = r"C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe"
SERVICE_LINE = (
    r"R3 ProtoVPN Service; " + SERVICE_PATH + r" [477424 2026-03-06] (Proto AG -> ProtoVPN)"
)
# The same path on a line of another shape: a parsed rule for SERVICE_LINE
# matches it only through its file path (the filepath fallback).
PATH_LINE = r"2026-03-18 13:45 - 2026-03-18 13:45 - 000000000 ____D " + SERVICE_PATH

LOG = "\n".join([
    "first line",
    "",
    "AVP: Kaspersky Anti-Virus service",
    "evil.exe started",
    "last line",
])


class FactEngineTests(LogAnalyzerApiBaseTestCase):
    def setUp(self):
        super().setUp()
        self.fact = Fact.objects.create(name="Kaspersky installed")

    def _rule(self, source_text, status=B, match_type=ClassificationRule.MATCH_SUBSTRING, **overrides):
        return ClassificationRule.objects.create(
            owner=self.user, status=status, match_type=match_type, source_text=source_text, **overrides,
        )

    def _fact_rule(self, source_text, match_type=FactRule.MATCH_SUBSTRING, fact=None, **overrides):
        return FactRule.objects.create(
            owner=self.user, fact=fact or self.fact, match_type=match_type, source_text=source_text, **overrides,
        )

    def _tag_source(self, tag, **overrides):
        return FactTagSource.objects.create(fact=self.fact, tag=tag, **overrides)

    def _found(self, payload):
        return {item["id"]: item for item in payload.get("facts", [])}

    # -- nothing defined --

    def test_no_facts_key_without_fact_rules_or_sources(self):
        self._rule("evil.exe")
        payload = analyze_log_text(LOG)
        self.assertNotIn("facts", payload)

    # -- fact rules --

    def test_substring_fact_rule_records_line_indexes_and_numbers(self):
        self._fact_rule("Kaspersky")
        found = self._found(analyze_log_text(LOG))
        # Analyzed-line index 1 (blank lines are skipped), log page line 3.
        self.assertEqual(found[self.fact.pk]["line_indexes"], [1])
        self.assertEqual(found[self.fact.pk]["line_nos"], [3])
        self.assertFalse(found[self.fact.pk]["wholelog"])

    def test_fact_rule_never_changes_the_verdict_colouring_or_rule_ids(self):
        rule = self._rule("Kaspersky", status=C)
        without = analyze_log_text(LOG)["lines"]
        self._fact_rule("Kaspersky")
        self._fact_rule("first line", match_type=FactRule.MATCH_EXACT)
        invalidate_rule_buckets_cache()
        with_facts = analyze_log_text(LOG)["lines"]
        self.assertEqual(without, with_facts)
        self.assertEqual(with_facts[1]["rule_ids"], [rule.pk])
        self.assertEqual(with_facts[0]["dominant_status"], "?")

    def test_regex_and_exact_fact_rules(self):
        regex_fact = Fact.objects.create(name="started something")
        self._fact_rule(r"^\w+\.exe started$", match_type=FactRule.MATCH_REGEX, fact=regex_fact)
        self._fact_rule("last line", match_type=FactRule.MATCH_EXACT)
        found = self._found(analyze_log_text(LOG))
        self.assertEqual(found[regex_fact.pk]["line_indexes"], [2])
        self.assertEqual(found[self.fact.pk]["line_indexes"], [3])

    def test_whole_log_fact_rule_is_a_fact_about_the_log(self):
        self._fact_rule(r"Kaspersky.*\n.*evil", match_type=FactRule.MATCH_REGEX, whole_log=True)
        found = self._found(analyze_log_text(LOG))
        self.assertTrue(found[self.fact.pk]["wholelog"])
        self.assertEqual(found[self.fact.pk]["line_indexes"], [])

    def test_disabled_fact_rule_finds_nothing(self):
        self._fact_rule("Kaspersky", is_enabled=False)
        self.assertNotIn("facts", analyze_log_text(LOG))

    def test_substring_fact_rule_with_a_path_does_not_match_through_the_path(self):
        # A classification rule would also match PATH_LINE through the path it
        # contains (the weak fallback); a fact must not come from that.
        self._fact_rule(SERVICE_LINE)
        found = self._found(analyze_log_text("\n".join([SERVICE_LINE, PATH_LINE])))
        self.assertEqual(found[self.fact.pk]["line_indexes"], [0])

    def test_filepath_fact_rule_matches_by_path(self):
        self._fact_rule(
            SERVICE_PATH, match_type=FactRule.MATCH_FILEPATH,
            filepath=SERVICE_PATH, normalized_filepath=SERVICE_PATH.lower(),
        )
        found = self._found(analyze_log_text("\n".join([SERVICE_LINE, PATH_LINE])))
        self.assertEqual(found[self.fact.pk]["line_indexes"], [0, 1])

    def test_fact_rules_follow_rule_sets(self):
        private = User.objects.create_user(username="private_helper", password="pw")
        UserProfile.objects.create(user=private, rule_set_mode="private")
        FactRule.objects.create(
            owner=private, fact=self.fact, match_type=FactRule.MATCH_SUBSTRING, source_text="Kaspersky",
        )
        self.assertNotIn("facts", analyze_log_text(LOG, "shared"))
        found = self._found(analyze_log_text(LOG, f"private:{private.pk}"))
        self.assertEqual(found[self.fact.pk]["line_indexes"], [1])

    # -- tag sources --

    def test_tag_source_counts_a_tagged_rule_that_decided_the_line(self):
        tag = RuleTag.objects.create(name="Kaspersky")
        self._rule("Kaspersky", status=S).tags.add(tag)
        self._tag_source(tag, mode=FactTagSource.MODE_DECIDED)
        found = self._found(analyze_log_text(LOG))
        self.assertEqual(found[self.fact.pk]["line_indexes"], [1])

    def test_matched_mode_counts_a_shadowed_match_decided_mode_does_not(self):
        tag = RuleTag.objects.create(name="Kaspersky")
        self._rule("Kaspersky", status=S).tags.add(tag)                     # substring, priority 7
        self._rule(LOG.splitlines()[2], status=C, match_type=ClassificationRule.MATCH_EXACT)  # 19 wins
        source = self._tag_source(tag, mode=FactTagSource.MODE_MATCHED)
        self.assertIn(self.fact.pk, self._found(analyze_log_text(LOG)))

        source.mode = FactTagSource.MODE_DECIDED
        source.save()
        invalidate_rule_buckets_cache()
        self.assertNotIn("facts", analyze_log_text(LOG))

    def test_status_filter(self):
        tag = RuleTag.objects.create(name="Kaspersky")
        self._rule("Kaspersky", status=B).tags.add(tag)  # a fake: B
        self._tag_source(tag, statuses=[S, C])
        self.assertNotIn("facts", analyze_log_text(LOG))

    def test_untagged_rules_do_not_count(self):
        tag = RuleTag.objects.create(name="Kaspersky")
        self._rule("Kaspersky", status=S)
        self._tag_source(tag)
        self.assertNotIn("facts", analyze_log_text(LOG))

    def test_filepath_fallback_counts_only_when_allowed(self):
        tag = RuleTag.objects.create(name="Proton")
        parsed = parse_rule_line(SERVICE_LINE, status=S, source_name="test-suite")
        ClassificationRule.objects.create(owner=self.user, **parsed).tags.add(tag)
        source = self._tag_source(tag)
        found = self._found(analyze_log_text(PATH_LINE))
        self.assertNotIn(self.fact.pk, found)

        source.include_filepath_fallback = True
        source.save()
        invalidate_rule_buckets_cache()
        self.assertIn(self.fact.pk, self._found(analyze_log_text(PATH_LINE)))

    def test_fired_whole_log_alert_rule_with_the_tag_is_a_fact_about_the_log(self):
        tag = RuleTag.objects.create(name="Kaspersky")
        self._rule(r"Kaspersky", status=A, match_type=ClassificationRule.MATCH_REGEX, whole_log=True).tags.add(tag)
        self._tag_source(tag)
        found = self._found(analyze_log_text(LOG))
        self.assertTrue(found[self.fact.pk]["wholelog"])
        self.assertEqual(found[self.fact.pk]["line_indexes"], [])

    # -- serving, invalidation, tag deletion --

    def test_attach_fact_info_adds_names_and_drops_deleted_facts(self):
        gone = Fact.objects.create(name="gone")
        payload = {"lines": [], "facts": [
            {"id": self.fact.pk, "line_indexes": [1], "line_nos": [3], "wholelog": False},
            {"id": gone.pk, "line_indexes": [], "line_nos": [], "wholelog": True},
        ]}
        gone.delete()
        served = attach_fact_info(payload)
        self.assertEqual([item["name"] for item in served["facts"]], ["Kaspersky installed"])
        self.assertEqual(len(payload["facts"]), 2)  # the stored payload is untouched

    def test_applying_a_tag_a_fact_counts_drops_the_rule_buckets(self):
        tag = RuleTag.objects.create(name="Kaspersky")
        other = RuleTag.objects.create(name="unrelated")
        rule = self._rule("Kaspersky", status=S)
        self._tag_source(tag)
        version = _current_rules_version()
        apply_tag(other, [rule.pk], [])
        self.assertEqual(_current_rules_version(), version)
        apply_tag(tag, [rule.pk], [])
        self.assertGreater(_current_rules_version(), version)
        self.assertIn(self.fact.pk, self._found(analyze_log_text(LOG)))
        self.assertFalse(invalidate_if_tags_referenced([other.pk]))

    def test_tag_used_by_a_fact_cannot_be_deleted(self):
        tag = RuleTag.objects.create(name="Kaspersky")
        self._tag_source(tag)
        self.client.force_login(self.user)
        response = self.client.post(reverse("rule_tags"), {"action": "delete", "pk": tag.pk})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(RuleTag.objects.filter(pk=tag.pk).exists())
        self.assertIn("Kaspersky installed", " ".join(str(m) for m in get_messages(response.wsgi_request)))
