from io import StringIO
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from ..analyzer import find_rule_duplicates
from ..models import ClassificationRule


def _make_parsed_rule(owner, **overrides):
    base = {
        "owner": owner,
        "status": ClassificationRule.STATUS_PUP,
        "match_type": ClassificationRule.MATCH_PARSED_ENTRY,
        "source_text": "ignored-for-comparison",
        "entry_type": "service",
        "name": "MySvc",
        "filepath": r"C:\Program Files\Vendor\svc.exe",
        "normalized_filepath": r"c:\program files\vendor\svc.exe",
        "filename": "svc.exe",
        "company": "Vendor",
        "arguments": "",
        "file_not_signed": False,
        "attributes": "",
        "clsid": "",
        "is_enabled": True,
    }
    base.update(overrides)
    # source_text must be unique per (owner, status, match_type) due to
    # unique_together — generate one per rule unless an override was given.
    if base["source_text"] == "ignored-for-comparison":
        base["source_text"] = f"src-{base['filepath']}-{id(overrides)}"
    return ClassificationRule.objects.create(**base)


def _make_filepath_rule(owner, **overrides):
    base = {
        "owner": owner,
        "status": ClassificationRule.STATUS_PUP,
        "match_type": ClassificationRule.MATCH_FILEPATH,
        "filepath": r"C:\Foo\bar.exe",
        "normalized_filepath": r"c:\foo\bar.exe",
        "filename": "bar.exe",
        "is_enabled": True,
    }
    base.update(overrides)
    base.setdefault("source_text", base["filepath"])
    return ClassificationRule.objects.create(**base)


def _all_rules():
    return ClassificationRule.objects.all()


class FindRuleDuplicatesTests(TestCase):

    def setUp(self):
        self.alice = User.objects.create_user(username="alice", password="pw")
        self.bob = User.objects.create_user(username="bob", password="pw")

    def test_two_identical_parsed_entry_rules_form_one_group(self):
        r1 = _make_parsed_rule(self.alice)
        r2 = _make_parsed_rule(self.bob)  # different owner avoids unique_together
        groups = find_rule_duplicates(_all_rules())
        self.assertEqual(len(groups), 1)
        self.assertEqual({r.id for r in groups[0]}, {r1.id, r2.id})

    def test_same_fields_different_status_not_grouped(self):
        _make_parsed_rule(self.alice, status=ClassificationRule.STATUS_MALWARE)
        _make_parsed_rule(self.bob, status=ClassificationRule.STATUS_PUP)
        self.assertEqual(find_rule_duplicates(_all_rules()), [])

    def test_clsid_ignored_for_firewall_entries(self):
        r1 = _make_parsed_rule(
            self.alice,
            entry_type="firewall",
            clsid="AAAA0000-0000-0000-0000-000000000001",
            name="Allow",
        )
        r2 = _make_parsed_rule(
            self.bob,
            entry_type="firewall",
            clsid="BBBB0000-0000-0000-0000-000000000002",
            name="Allow",
        )
        groups = find_rule_duplicates(_all_rules())
        self.assertEqual(len(groups), 1)
        self.assertEqual({r.id for r in groups[0]}, {r1.id, r2.id})

    def test_clsid_part_of_key_for_bho_entries(self):
        _make_parsed_rule(
            self.alice,
            entry_type="bho",
            clsid="11111111-1111-1111-1111-111111111111",
        )
        _make_parsed_rule(
            self.bob,
            entry_type="bho",
            clsid="22222222-2222-2222-2222-222222222222",
        )
        self.assertEqual(find_rule_duplicates(_all_rules()), [])

    def test_singleton_rule_not_reported(self):
        _make_parsed_rule(self.alice)
        self.assertEqual(find_rule_duplicates(_all_rules()), [])

    def test_filepath_rules_grouped_by_normalized_filepath(self):
        r1 = _make_filepath_rule(self.alice)
        r2 = _make_filepath_rule(self.bob)
        groups = find_rule_duplicates(_all_rules())
        self.assertEqual(len(groups), 1)
        self.assertEqual({r.id for r in groups[0]}, {r1.id, r2.id})

    def test_parsed_entry_and_filepath_with_same_path_not_mixed(self):
        _make_parsed_rule(self.alice, filepath=r"C:\X\y.exe", normalized_filepath=r"c:\x\y.exe", filename="y.exe")
        _make_filepath_rule(self.bob, filepath=r"C:\X\y.exe", normalized_filepath=r"c:\x\y.exe", filename="y.exe")
        self.assertEqual(find_rule_duplicates(_all_rules()), [])

    def test_disabled_and_enabled_rules_still_group_together(self):
        r1 = _make_parsed_rule(self.alice, is_enabled=False)
        r2 = _make_parsed_rule(self.bob, is_enabled=True)
        groups = find_rule_duplicates(_all_rules())
        self.assertEqual(len(groups), 1)
        self.assertEqual({r.id for r in groups[0]}, {r1.id, r2.id})

    def test_case_insensitive_filepath_grouping(self):
        r1 = _make_filepath_rule(
            self.alice,
            filepath=r"C:\Foo\BAR.exe",
            normalized_filepath=r"C:\Foo\BAR.exe",
            filename="BAR.exe",
        )
        r2 = _make_filepath_rule(
            self.bob,
            filepath=r"c:\foo\bar.EXE",
            normalized_filepath=r"c:\foo\bar.EXE",
            filename="bar.EXE",
        )
        groups = find_rule_duplicates(_all_rules())
        self.assertEqual(len(groups), 1)
        self.assertEqual({r.id for r in groups[0]}, {r1.id, r2.id})

    def test_filepath_rule_without_normalized_path_skipped(self):
        _make_filepath_rule(self.alice, normalized_filepath="")
        _make_filepath_rule(self.bob, normalized_filepath="")
        self.assertEqual(find_rule_duplicates(_all_rules()), [])


class DuplicatesAdminViewTests(TestCase):

    def setUp(self):
        self.admin = User.objects.create_superuser(
            username="root", password="pw", email="root@example.com"
        )
        self.alice = User.objects.create_user(username="alice", password="pw")
        self.bob = User.objects.create_user(username="bob", password="pw")
        self.client.force_login(self.admin)
        self.url = reverse("admin:fixlist_classificationrule_duplicates")

        self.r1 = _make_parsed_rule(self.alice)
        self.r2 = _make_parsed_rule(self.bob)
        # A singleton that must NOT appear.
        self.singleton = _make_parsed_rule(
            self.admin,
            filepath=r"C:\Singleton\x.exe",
            normalized_filepath=r"c:\singleton\x.exe",
            filename="x.exe",
        )

    def test_preview_renders_groups(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Find duplicate rules")
        self.assertContains(response, f"#{self.r1.id}")
        self.assertContains(response, f"#{self.r2.id}")

    def test_preview_skips_non_duplicates(self):
        response = self.client.get(self.url)
        self.assertNotContains(response, f"#{self.singleton.id}")

    def test_post_disables_selected_rules(self):
        response = self.client.post(
            self.url,
            data={"disable": [str(self.r2.id)], "action_disable": "Disable selected rule(s)"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.r1.refresh_from_db()
        self.r2.refresh_from_db()
        self.assertTrue(self.r1.is_enabled)
        self.assertFalse(self.r2.is_enabled)

    def test_post_deletes_selected_rules(self):
        rule_id = self.r2.id
        response = self.client.post(
            self.url,
            data={"disable": [str(rule_id)], "action_delete": "Delete selected rule(s)"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.r1.refresh_from_db()  # keeper still exists
        self.assertTrue(self.r1.is_enabled)
        self.assertFalse(ClassificationRule.objects.filter(pk=rule_id).exists())

    def test_post_delete_with_no_selection_is_noop(self):
        response = self.client.post(
            self.url,
            data={"action_delete": "Delete selected rule(s)"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(ClassificationRule.objects.filter(pk=self.r1.id).exists())
        self.assertTrue(ClassificationRule.objects.filter(pk=self.r2.id).exists())

    def test_post_with_no_selection_does_not_change_rules(self):
        response = self.client.post(self.url, data={}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.r1.refresh_from_db()
        self.r2.refresh_from_db()
        self.assertTrue(self.r1.is_enabled)
        self.assertTrue(self.r2.is_enabled)

    @patch("fixlist.admin.invalidate_rule_buckets_cache")
    def test_post_invalidates_rule_buckets_cache_when_changes_applied(self, mock_invalidate):
        self.client.post(self.url, data={"disable": [str(self.r1.id)]}, follow=True)
        self.assertTrue(mock_invalidate.called)

    @patch("fixlist.admin.invalidate_rule_buckets_cache")
    def test_post_does_not_invalidate_cache_when_nothing_changes(self, mock_invalidate):
        self.client.post(self.url, data={}, follow=True)
        self.assertFalse(mock_invalidate.called)

    def test_post_ignores_non_integer_ids(self):
        response = self.client.post(self.url, data={"disable": ["abc", "xyz"]}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.r1.refresh_from_db()
        self.r2.refresh_from_db()
        self.assertTrue(self.r1.is_enabled)
        self.assertTrue(self.r2.is_enabled)


class FindDuplicatesCommandTests(TestCase):

    def setUp(self):
        self.alice = User.objects.create_user(username="alice", password="pw")
        self.bob = User.objects.create_user(username="bob", password="pw")

    def test_command_lists_duplicates(self):
        r1 = _make_parsed_rule(self.alice)
        r2 = _make_parsed_rule(self.bob)
        out = StringIO()
        call_command("find_duplicates", stdout=out)
        output = out.getvalue()
        self.assertIn(f"#{r1.id}", output)
        self.assertIn(f"#{r2.id}", output)
        self.assertIn("Found 1 duplicate group(s) covering 2 rule(s).", output)
