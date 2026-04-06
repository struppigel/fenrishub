import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from unittest.mock import patch

from django.http import HttpResponse
from django.test import RequestFactory

from ..analyzer import inspect_line_matches, invalidate_rule_buckets_cache
from ..models import ClassificationRule, ParsedFilepathExclusion, UploadedLog
from ..views import log_analyzer_view


class RuleOwnershipTests(TestCase):
    """Tests for rule ownership enforcement in preview and persist APIs."""

    def setUp(self):
        invalidate_rule_buckets_cache()
        self.alice = User.objects.create_user(username="alice", password="password123")
        self.bob = User.objects.create_user(username="bob", password="password123")

    def _preview(self, pending_changes):
        return self.client.post(
            reverse("preview_pending_rule_changes_api"),
            data=json.dumps({"pending_changes": pending_changes}),
            content_type="application/json",
        )

    def _persist(self, pending_changes, selected_ids, conflict_resolutions):
        return self.client.post(
            reverse("persist_pending_rule_changes_api"),
            data=json.dumps({
                "pending_changes": pending_changes,
                "selected_rule_change_ids": selected_ids,
                "conflict_resolutions": conflict_resolutions,
            }),
            content_type="application/json",
        )

    # -- owner_username in preview API --

    def test_preview_conflict_matching_rules_include_owner_username(self):
        """Matching rules in contradictions include the owner_username field."""
        self.client.login(username="alice", password="password123")
        ClassificationRule.objects.create(
            owner=self.bob,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="OWNERSHIP-LINE",
        )

        response = self._preview([{
            "id": "1",
            "line": "OWNERSHIP-LINE",
            "original_status": "?",
            "new_status": ClassificationRule.STATUS_CLEAN,
            "order": 1,
        }])

        payload = response.json()
        self.assertEqual(response.status_code, 200)

        all_matching_rules = []
        for conflict in payload["contradictions"]["override_vs_existing_dominant"]:
            all_matching_rules.extend(conflict["matching_rules"])
        for conflict in payload["contradictions"]["overlaps_other_status_rules"]:
            all_matching_rules.extend(conflict["matching_rules"])

        self.assertTrue(all_matching_rules)
        for match in all_matching_rules:
            self.assertIn("owner_username", match)

    def test_preview_conflict_matching_rule_shows_correct_owner(self):
        """owner_username matches the actual rule owner, not the requesting user."""
        self.client.login(username="alice", password="password123")
        ClassificationRule.objects.create(
            owner=self.bob,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="BOB-RULE-LINE",
        )

        response = self._preview([{
            "id": "1",
            "line": "BOB-RULE-LINE",
            "original_status": "?",
            "new_status": ClassificationRule.STATUS_CLEAN,
            "order": 1,
        }])

        payload = response.json()
        override_conflicts = payload["contradictions"]["override_vs_existing_dominant"]
        self.assertTrue(override_conflicts)
        bob_rules = [
            match
            for conflict in override_conflicts
            for match in conflict["matching_rules"]
            if match["owner_username"] == "bob"
        ]
        self.assertTrue(bob_rules)

    def test_preview_own_rule_shows_own_username(self):
        """owner_username shows the requesting user's name for their own rules."""
        self.client.login(username="alice", password="password123")
        ClassificationRule.objects.create(
            owner=self.alice,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="ALICE-RULE-LINE",
        )

        response = self._preview([{
            "id": "1",
            "line": "ALICE-RULE-LINE",
            "original_status": "?",
            "new_status": ClassificationRule.STATUS_CLEAN,
            "order": 1,
        }])

        payload = response.json()
        override_conflicts = payload["contradictions"]["override_vs_existing_dominant"]
        self.assertTrue(override_conflicts)
        alice_rules = [
            match
            for conflict in override_conflicts
            for match in conflict["matching_rules"]
            if match["owner_username"] == "alice"
        ]
        self.assertTrue(alice_rules)

    # -- persist API cross-user enforcement --

    def test_persist_update_existing_status_ignores_other_users_rule(self):
        """update_existing_status resolution is silently ignored for another user's rule."""
        self.client.login(username="alice", password="password123")
        bobs_rule = ClassificationRule.objects.create(
            owner=self.bob,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="CROSS-USER-UPDATE",
        )

        response = self._persist(
            pending_changes=[{
                "id": "1",
                "line": "CROSS-USER-UPDATE",
                "original_status": "?",
                "new_status": ClassificationRule.STATUS_MALWARE,
                "order": 1,
            }],
            selected_ids=["1"],
            conflict_resolutions=[{
                "conflict_key": f"override:1:{bobs_rule.id}",
                "contradiction_type": "override_vs_existing_dominant",
                "change_id": "1",
                "existing_rule_id": bobs_rule.id,
                "action": "update_existing_status",
            }],
        )

        bobs_rule.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(bobs_rule.status, ClassificationRule.STATUS_CLEAN)

    def test_persist_disable_other_ignores_other_users_rule(self):
        """keep_new_disable_other resolution does not disable another user's rule."""
        self.client.login(username="alice", password="password123")
        bobs_rule = ClassificationRule.objects.create(
            owner=self.bob,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="CROSS-USER-DISABLE",
        )

        response = self._persist(
            pending_changes=[{
                "id": "1",
                "line": "CROSS-USER-DISABLE",
                "original_status": "?",
                "new_status": ClassificationRule.STATUS_CLEAN,
                "order": 1,
            }],
            selected_ids=["1"],
            conflict_resolutions=[{
                "conflict_key": f"override:1:{bobs_rule.id}",
                "contradiction_type": "override_vs_existing_dominant",
                "change_id": "1",
                "existing_rule_id": bobs_rule.id,
                "action": "keep_new_disable_other",
            }],
        )

        bobs_rule.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(bobs_rule.is_enabled)

    def test_persist_update_existing_status_works_for_own_rule(self):
        """update_existing_status correctly updates the requesting user's own rule."""
        self.client.login(username="alice", password="password123")
        alices_rule = ClassificationRule.objects.create(
            owner=self.alice,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="OWN-RULE-UPDATE",
        )

        response = self._persist(
            pending_changes=[{
                "id": "1",
                "line": "OWN-RULE-UPDATE",
                "original_status": "?",
                "new_status": ClassificationRule.STATUS_MALWARE,
                "order": 1,
            }],
            selected_ids=["1"],
            conflict_resolutions=[{
                "conflict_key": f"override:1:{alices_rule.id}",
                "contradiction_type": "override_vs_existing_dominant",
                "change_id": "1",
                "existing_rule_id": alices_rule.id,
                "action": "update_existing_status",
            }],
        )

        alices_rule.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(alices_rule.status, ClassificationRule.STATUS_MALWARE)

    def test_persist_disable_other_works_for_own_rule(self):
        """keep_new_disable_other correctly disables the requesting user's own rule."""
        self.client.login(username="alice", password="password123")
        alices_rule = ClassificationRule.objects.create(
            owner=self.alice,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="OWN-RULE-DISABLE",
        )

        response = self._persist(
            pending_changes=[{
                "id": "1",
                "line": "OWN-RULE-DISABLE",
                "original_status": "?",
                "new_status": ClassificationRule.STATUS_CLEAN,
                "order": 1,
            }],
            selected_ids=["1"],
            conflict_resolutions=[{
                "conflict_key": f"override:1:{alices_rule.id}",
                "contradiction_type": "override_vs_existing_dominant",
                "change_id": "1",
                "existing_rule_id": alices_rule.id,
                "action": "keep_new_disable_other",
            }],
        )

        alices_rule.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(alices_rule.is_enabled)

    # -- inspect_line_matches includes owner_username --

    def test_inspect_line_matches_includes_owner_username(self):
        """inspect_line_matches returns owner_username on each matching rule."""
        ClassificationRule.objects.create(
            owner=self.bob,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="OWNER-IN-INSPECTION",
        )

        inspection = inspect_line_matches("OWNER-IN-INSPECTION")

        self.assertTrue(inspection["matches"])
        self.assertEqual(inspection["matches"][0]["owner_username"], "bob")

