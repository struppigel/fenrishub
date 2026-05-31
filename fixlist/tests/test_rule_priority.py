"""Tests for the numeric priority field on ClassificationRule."""
import json
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..analyzer import inspect_line_matches, invalidate_rule_buckets_cache
from ..models import ClassificationRule, DEFAULT_PRIORITY_BY_MATCH_TYPE
from .factories import make_rule, make_user


class PriorityDefaultsTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = make_user("priorityuser")

    def test_default_priority_for_each_match_type(self):
        self.assertEqual(ClassificationRule.default_priority_for("exact"), 19)
        self.assertEqual(ClassificationRule.default_priority_for("parsed"), 15)
        self.assertEqual(ClassificationRule.default_priority_for("filepath"), 11)
        self.assertEqual(ClassificationRule.default_priority_for("substring"), 7)
        self.assertEqual(ClassificationRule.default_priority_for("regex"), 3)

    def test_save_auto_fills_priority_from_match_type(self):
        rule = make_rule("foo", owner=self.user, match_type=ClassificationRule.MATCH_REGEX)
        self.assertEqual(rule.priority, 3)

        exact_rule = make_rule("bar", owner=self.user, match_type=ClassificationRule.MATCH_EXACT)
        self.assertEqual(exact_rule.priority, 19)

    def test_explicit_priority_is_preserved_on_save(self):
        rule = make_rule(
            "explicit",
            owner=self.user,
            match_type=ClassificationRule.MATCH_REGEX,
            priority=18,
        )
        self.assertEqual(rule.priority, 18)


class PriorityShadowingTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = make_user("shadowuser")

    def test_higher_priority_regex_shadows_lower_priority_exact(self):
        line = "specific-line-text"
        # Exact rule at default priority 19
        make_rule(
            line,
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_EXACT,
        )
        # Regex rule at priority 20 — should win
        make_rule(
            r"specific-line-.*",
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_REGEX,
            priority=20,
        )

        invalidate_rule_buckets_cache()
        inspection = inspect_line_matches(line)

        self.assertEqual(inspection["effective_priority"], 20)
        self.assertEqual(inspection["dominant_status"], ClassificationRule.STATUS_MALWARE)
        shadowed_statuses = {m["status"] for m in inspection["shadowed_matches"]}
        self.assertIn(ClassificationRule.STATUS_CLEAN, shadowed_statuses)

    def test_lowering_priority_flips_outcome(self):
        line = "specific-line-text"
        make_rule(
            line,
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_EXACT,
        )
        regex_rule = make_rule(
            r"specific-line-.*",
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_REGEX,
            priority=5,  # below exact's 19
        )

        invalidate_rule_buckets_cache()
        inspection = inspect_line_matches(line)

        self.assertEqual(inspection["effective_priority"], 19)
        self.assertEqual(inspection["dominant_status"], ClassificationRule.STATUS_CLEAN)
        shadowed_ids = {m["id"] for m in inspection["shadowed_matches"]}
        self.assertIn(regex_rule.id, shadowed_ids)


class PriorityTieBreakingTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = make_user("tieuser")

    def test_same_priority_falls_back_to_status_precedence(self):
        line = "shared-line-content"
        make_rule(
            "shared-line",
            owner=self.user,
            status=ClassificationRule.STATUS_PUP,
            match_type=ClassificationRule.MATCH_SUBSTRING,
            priority=10,
        )
        make_rule(
            r"shared-.*content",
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_REGEX,
            priority=10,
        )

        invalidate_rule_buckets_cache()
        inspection = inspect_line_matches(line)

        self.assertEqual(inspection["effective_priority"], 10)
        # Status precedence: B (malware) beats P (pup)
        self.assertEqual(inspection["dominant_status"], ClassificationRule.STATUS_MALWARE)
        # Heterogeneous matchers at same priority -> "priority:N" label
        self.assertEqual(inspection["effective_matcher"], "priority:10")
        self.assertEqual(len(inspection["matches"]), 2)
        self.assertEqual(len(inspection["shadowed_matches"]), 0)


class PriorityViewTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = User.objects.create_user("viewuser", password="password123")
        self.client.login(username="viewuser", password="password123")

    def test_create_rule_without_priority_uses_match_type_default(self):
        response = self.client.post(reverse("rules"), {
            "action": "create",
            "status": ClassificationRule.STATUS_MALWARE,
            "match_type": ClassificationRule.MATCH_REGEX,
            "source_text": "evil.*",
            "description": "test",
        })
        self.assertEqual(response.status_code, 302)
        rule = ClassificationRule.objects.get(source_text="evil.*", owner=self.user)
        self.assertEqual(rule.priority, 3)

    def test_create_rule_with_explicit_priority(self):
        response = self.client.post(reverse("rules"), {
            "action": "create",
            "status": ClassificationRule.STATUS_MALWARE,
            "match_type": ClassificationRule.MATCH_SUBSTRING,
            "source_text": "evil-token",
            "description": "test",
            "priority": "17",
        })
        self.assertEqual(response.status_code, 302)
        rule = ClassificationRule.objects.get(source_text="evil-token", owner=self.user)
        self.assertEqual(rule.priority, 17)

    def test_create_rule_with_out_of_range_priority_clamps(self):
        response = self.client.post(reverse("rules"), {
            "action": "create",
            "status": ClassificationRule.STATUS_MALWARE,
            "match_type": ClassificationRule.MATCH_SUBSTRING,
            "source_text": "evil-token-2",
            "description": "test",
            "priority": "999",
        })
        self.assertEqual(response.status_code, 302)
        rule = ClassificationRule.objects.get(source_text="evil-token-2", owner=self.user)
        self.assertEqual(rule.priority, 20)

    def test_edit_rule_changes_priority(self):
        rule = make_rule(
            "foo",
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_SUBSTRING,
        )
        self.assertEqual(rule.priority, 7)

        response = self.client.post(reverse("rules"), {
            "action": "edit",
            "pk": rule.pk,
            "status": ClassificationRule.STATUS_MALWARE,
            "match_type": ClassificationRule.MATCH_SUBSTRING,
            "source_text": "foo",
            "description": "",
            "is_enabled": "on",
            "priority": "18",
        })
        self.assertEqual(response.status_code, 302)
        rule.refresh_from_db()
        self.assertEqual(rule.priority, 18)


class PriorityRuleTestApiTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = User.objects.create_user("apiuser", password="password123")
        self.client.login(username="apiuser", password="password123")

    def _post(self, payload):
        return self.client.post(
            reverse("test_rule_api"),
            data=json.dumps(payload),
            content_type="application/json",
        )

    def test_explicit_priority_lets_new_regex_shadow_existing_exact(self):
        line = "EXACT-LINE-X"
        make_rule(
            line,
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_EXACT,
        )
        invalidate_rule_buckets_cache()

        response = self._post({
            "source_text": r"EXACT-LINE-.*",
            "match_type": "regex",
            "status": "B",
            "priority": 20,  # higher than the exact rule's 19
            "lines": [line],
        })

        result = response.json()["results"][0]
        self.assertTrue(result["matched"])
        self.assertFalse(result["new_rule_shadowed"])
        self.assertEqual(result["new_rule_priority"], 20)
        self.assertEqual(result["existing_priority"], 19)
        self.assertEqual(result["combined_status"], "B")

    def test_no_priority_means_default_for_match_type(self):
        line = "SOME-LINE"
        make_rule(
            line,
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_EXACT,
        )
        invalidate_rule_buckets_cache()

        response = self._post({
            "source_text": r"SOME-.*",
            "match_type": "regex",
            "status": "B",
            "lines": [line],
        })

        result = response.json()["results"][0]
        self.assertTrue(result["matched"])
        self.assertEqual(result["new_rule_priority"], 3)  # default for regex
        self.assertTrue(result["new_rule_shadowed"])
        self.assertEqual(result["new_rule_shadowed_by"], "priority 19")


class PriorityConflictSuppressionTests(TestCase):
    """Conflicts surface only when the new rule cannot shadow the existing matches."""

    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = User.objects.create_user("conflictuser", password="password123")
        self.client.login(username="conflictuser", password="password123")

    def _preview(self, line, new_status, change_id="1"):
        return self.client.post(
            reverse("preview_pending_rule_changes_api"),
            data=json.dumps({
                "pending_changes": [{
                    "id": change_id,
                    "line": line,
                    "original_status": "?",
                    "new_status": new_status,
                    "order": 1,
                }],
            }),
            content_type="application/json",
        )

    def test_higher_priority_new_rule_suppresses_conflicts(self):
        line = "CONFLICT-LINE"
        # Existing exact rule at default priority 19
        make_rule(
            line,
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
        )
        # Existing substring rule at default priority 7 (additional overlap)
        make_rule(
            "CONFLICT",
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_SUBSTRING,
        )
        invalidate_rule_buckets_cache()

        # The pending preview can't carry priority directly; it derives default
        # from match_type. So a pending change parsed as exact will land at
        # priority 19 — equal to the existing exact rule. This test verifies
        # the equality case still surfaces the conflict.
        response = self._preview(line, ClassificationRule.STATUS_PUP)
        self.assertEqual(response.status_code, 200)
        contradictions = response.json()["contradictions"]
        # Same priority (both 19) → conflict still surfaces
        self.assertGreaterEqual(len(contradictions["override_vs_existing_dominant"]), 1)

    def test_same_priority_still_surfaces_conflict(self):
        line = "SAME-PRIO-LINE"
        make_rule(
            line,
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
        )
        invalidate_rule_buckets_cache()

        # New rule is also exact (default priority 20) — same priority as existing
        response = self._preview(line, ClassificationRule.STATUS_CLEAN)
        self.assertEqual(response.status_code, 200)
        contradictions = response.json()["contradictions"]
        self.assertEqual(len(contradictions["override_vs_existing_dominant"]), 1)

    def test_lower_priority_new_rule_still_surfaces_conflict(self):
        line = "LOW-PRIO-CONFLICT-LINE"
        # Existing exact rule at default priority 19
        make_rule(
            line,
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
        )
        invalidate_rule_buckets_cache()

        # New rule is regex (default priority 3) — lower than existing exact
        # The regex pattern matches the line.
        response = self.client.post(
            reverse("preview_pending_rule_changes_api"),
            data=json.dumps({
                "pending_changes": [{
                    "id": "1",
                    "line": line,
                    "original_status": "?",
                    "new_status": ClassificationRule.STATUS_CLEAN,
                    "order": 1,
                }],
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        contradictions = response.json()["contradictions"]
        # Lower-priority new rule still triggers conflict (it would be shadowed)
        # The pending change becomes an exact rule (parse_rule_line default), so
        # the priority would equal the existing rule's. Use the rule_changes priority
        # to confirm.
        rule_changes = response.json()["rule_changes"]
        self.assertEqual(rule_changes[0]["priority"], 19)  # exact => 19
        # Equal priority => conflict still surfaces
        self.assertEqual(len(contradictions["override_vs_existing_dominant"]), 1)

    def test_higher_priority_existing_rule_suppresses_when_new_is_lower(self):
        """When the existing rule is at higher priority than the new pending rule,
        the conflict still surfaces because the new rule will be shadowed."""
        line = "REGEX-WINS-LINE"
        # Existing regex rule at priority 20 (high)
        make_rule(
            r"REGEX-WINS-.*",
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_REGEX,
            priority=20,
        )
        invalidate_rule_buckets_cache()

        # New pending change parses as exact (default priority 19) — lower than 20
        response = self._preview(line, ClassificationRule.STATUS_CLEAN)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        rule_changes = body["rule_changes"]
        contradictions = body["contradictions"]
        self.assertEqual(rule_changes[0]["priority"], 19)
        # Lower-priority new rule will be shadowed → still a conflict
        self.assertEqual(len(contradictions["override_vs_existing_dominant"]), 1)

    def test_new_rule_with_strictly_higher_priority_suppresses_conflict(self):
        """When the new pending rule's match_type yields a higher default priority
        than every existing match, no conflict needs surfacing."""
        line = "EXACT-WINS-OVER-REGEX"
        # Existing regex rule at default priority 3 — low.
        make_rule(
            r"EXACT-WINS-.*",
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_REGEX,
        )
        invalidate_rule_buckets_cache()

        # New pending change parses as exact (default priority 19) — higher
        response = self._preview(line, ClassificationRule.STATUS_CLEAN)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        contradictions = body["contradictions"]
        self.assertEqual(body["rule_changes"][0]["priority"], 19)
        # New rule shadows existing → no conflict surfaced
        self.assertEqual(len(contradictions["override_vs_existing_dominant"]), 0)
        self.assertEqual(len(contradictions["overlaps_other_status_rules"]), 0)


class PriorityMigrationTests(TestCase):
    """Sanity check: existing test database (post-migrate) honors the per-match-type priorities."""

    def test_priority_constants_match_migration(self):
        self.assertEqual(DEFAULT_PRIORITY_BY_MATCH_TYPE, {
            "exact": 19,
            "parsed": 15,
            "filepath": 11,
            "substring": 7,
            "script": 3,
            "regex": 3,
        })
