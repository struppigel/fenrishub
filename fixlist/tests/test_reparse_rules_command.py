"""Tests for the `reparse_rules` management command.

Covers the use case the command was written for: a rule was created from a
Task line via the buggy parser (stored filepath=`C:\\Program Files`), and we
need to rewrite the stored parsed metadata to match what the current parser
emits without changing the source_text or the rule's status.
"""

from io import StringIO

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from ..models import ClassificationRule


ASUS_LINE = (
    r"Task: {D7B60407-4E11-47AA-9C00-CC0F414753C6} - "
    r"System32\Tasks\ASUS Live Update1 => "
    r"C:\Program Files (x86)\ASUS\ASUS Live Update\UpdateChecker.exe "
    r"[17920 2016-08-01] () [File not signed]"
)
CORRECT_FILEPATH = r"C:\Program Files (x86)\ASUS\ASUS Live Update\UpdateChecker.exe"


class ReparseRulesCommandTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="reparser", password="pw")
        # Simulate a rule born from the buggy parser: source_text is correct,
        # but the stored parsed metadata is wrong (truncated filepath, etc.).
        self.rule = ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_PUP,
            match_type=ClassificationRule.MATCH_PARSED_ENTRY,
            source_text=ASUS_LINE,
            source_name="legacy-bug",
            entry_type="scheduled_task",
            clsid="D7B60407-4E11-47AA-9C00-CC0F414753C6",
            name="",
            filepath=r"C:\Program Files",
            normalized_filepath=r"c:\program files",
            filename="Program Files",
            company="x86)\\ASUS\\ASUS Live Update\\UpdateChecker.exe [17920 2016-08-01] (",
            arguments="",
            file_not_signed=True,
        )

    def test_dry_run_reports_diff_without_writing(self):
        out = StringIO()
        call_command("reparse_rules", stdout=out)
        output = out.getvalue()

        self.assertIn(f"#{self.rule.id}", output)
        self.assertIn("filepath", output)
        self.assertIn("would change", output)
        self.assertIn("Dry run", output)

        self.rule.refresh_from_db()
        # Unchanged on disk.
        self.assertEqual(self.rule.filepath, r"C:\Program Files")
        self.assertEqual(self.rule.filename, "Program Files")

    def test_apply_persists_corrected_fields(self):
        out = StringIO()
        call_command("reparse_rules", "--apply", stdout=out)
        output = out.getvalue()

        self.assertIn("applied", output)
        self.assertIn("cache invalidated", output)

        self.rule.refresh_from_db()
        self.assertEqual(self.rule.filepath, CORRECT_FILEPATH)
        self.assertEqual(self.rule.filename, "UpdateChecker.exe")
        self.assertEqual(self.rule.company, "")
        self.assertEqual(self.rule.normalized_filepath, CORRECT_FILEPATH.lower())
        # source_text is never rewritten — it's the canonical input.
        self.assertEqual(self.rule.source_text, ASUS_LINE)

    def test_status_filter_skips_other_rules(self):
        # A second buggy rule that should NOT be touched because we filter on a different status.
        other_line = (
            r"Task: {B615BA87-24F8-40AA-BD14-A2B69D2F3E06} - "
            r"System32\Tasks\water => E:\Emoji\blinkdagger.mp3 "
            r"[62592 2024-10-20] () [File not signed]"
        )
        other = ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_PUP,
            match_type=ClassificationRule.MATCH_PARSED_ENTRY,
            source_text=other_line,
            filepath=r"C:\Program Files",
            normalized_filepath=r"c:\program files",
            filename="Program Files",
            company="bogus",
        )

        out = StringIO()
        call_command("reparse_rules", "--apply", "--status", ClassificationRule.STATUS_MALWARE, stdout=out)

        other.refresh_from_db()
        self.assertEqual(other.filepath, r"C:\Program Files")
        self.assertEqual(other.company, "bogus")

    def test_already_correct_rule_is_unchanged(self):
        # Use a different source_text so it doesn't collide with the rule in setUp.
        other_line = (
            r"Task: {C44E3249-F34C-4259-A841-86818C1FE185} - "
            r"System32\Tasks\Google => "
            r"C:\Program Files\Google\Chrome\Application\helper.exe "
            r"[1234 2026-04-18] (Google LLC -> Google LLC)"
        )
        correct = ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_PUP,
            match_type=ClassificationRule.MATCH_PARSED_ENTRY,
            source_text=other_line,
            entry_type="scheduled_task",
            clsid="",
            name=r"System32\Tasks\Google",
            filepath=r"C:\Program Files\Google\Chrome\Application\helper.exe",
            normalized_filepath=r"c:\program files\google\chrome\application\helper.exe",
            filename="helper.exe",
            company="Google LLC -> Google LLC",
            file_not_signed=False,
        )
        original_updated_at = correct.updated_at

        out = StringIO()
        call_command("reparse_rules", "--apply", stdout=out)

        correct.refresh_from_db()
        self.assertEqual(correct.updated_at, original_updated_at)
        self.assertEqual(
            correct.filepath, r"C:\Program Files\Google\Chrome\Application\helper.exe"
        )


class ReparseRulesAdminActionTests(TestCase):
    """Same backing logic as the CLI command, but invoked via the Django admin
    changelist action so Railway-style deployments without shell access can run
    it from the browser."""

    def setUp(self):
        self.admin = User.objects.create_superuser(
            username="root", password="pw", email="root@example.com"
        )
        self.client.force_login(self.admin)

        self.broken_rule = ClassificationRule.objects.create(
            owner=self.admin,
            status=ClassificationRule.STATUS_PUP,
            match_type=ClassificationRule.MATCH_PARSED_ENTRY,
            source_text=ASUS_LINE,
            source_name="legacy-bug",
            entry_type="scheduled_task",
            clsid="D7B60407-4E11-47AA-9C00-CC0F414753C6",
            filepath=r"C:\Program Files",
            normalized_filepath=r"c:\program files",
            filename="Program Files",
            company="x86)\\junk",
            file_not_signed=True,
        )

    def _post_action(self, action_name, pks):
        url = reverse("admin:fixlist_classificationrule_changelist")
        return self.client.post(
            url,
            data={
                "action": action_name,
                "_selected_action": [str(pk) for pk in pks],
            },
            follow=True,
        )

    def test_admin_action_rewrites_stored_metadata(self):
        response = self._post_action("reparse_from_source_text", [self.broken_rule.pk])
        self.assertEqual(response.status_code, 200)

        self.broken_rule.refresh_from_db()
        self.assertEqual(self.broken_rule.filepath, CORRECT_FILEPATH)
        self.assertEqual(self.broken_rule.filename, "UpdateChecker.exe")
        self.assertEqual(self.broken_rule.company, "")
        self.assertEqual(self.broken_rule.normalized_filepath, CORRECT_FILEPATH.lower())

    def test_reparse_all_view_get_renders_preview(self):
        url = reverse("admin:fixlist_classificationrule_reparse_all")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Re-parse all rules from source_text")
        self.assertContains(response, "Apply re-parse to 1 rule")
        self.assertContains(response, "filepath")
        # Nothing has been written yet.
        self.broken_rule.refresh_from_db()
        self.assertEqual(self.broken_rule.filepath, r"C:\Program Files")

    def test_admin_action_does_not_change_match_type(self):
        # A rule whose source_text is plain text that re-parses to match_type=exact.
        # The stored match_type=parsed_entry must NOT be silently downgraded to exact,
        # since that flips the rule's matching semantics (parsed metadata -> literal line).
        rule = ClassificationRule.objects.create(
            owner=self.admin,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_PARSED_ENTRY,
            source_text="some arbitrary descriptive note that is not an FRST line",
            filepath=r"C:\garbage",
            normalized_filepath=r"c:\garbage",
            filename="garbage.exe",
            company="Arg0",
        )

        url = reverse("admin:fixlist_classificationrule_reparse_all")
        response = self.client.post(url, follow=True)
        self.assertEqual(response.status_code, 200)

        rule.refresh_from_db()
        # Rule is untouched: match_type and metadata both preserved.
        self.assertEqual(rule.match_type, ClassificationRule.MATCH_PARSED_ENTRY)
        self.assertEqual(rule.filepath, r"C:\garbage")
        self.assertEqual(rule.company, "Arg0")

    def test_reparse_all_view_post_applies_to_every_rule(self):
        # Create a second buggy rule so we can confirm the view processes
        # everything without per-page selection.
        second = ClassificationRule.objects.create(
            owner=self.admin,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_PARSED_ENTRY,
            source_text=(
                r"Task: {B615BA87-24F8-40AA-BD14-A2B69D2F3E06} - "
                r"System32\Tasks\water => E:\Emoji\blinkdagger.mp3 "
                r"[62592 2024-10-20] () [File not signed]"
            ),
            filepath=r"C:\Program Files",
            normalized_filepath=r"c:\program files",
            filename="Program Files",
            company="garbage",
        )

        url = reverse("admin:fixlist_classificationrule_reparse_all")
        response = self.client.post(url, follow=True)
        self.assertEqual(response.status_code, 200)

        self.broken_rule.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(self.broken_rule.filepath, CORRECT_FILEPATH)
        self.assertEqual(second.filepath, r"C:\Emoji\blinkdagger.mp3")
        self.assertEqual(second.company, "")


# An unsigned process from two different user folders: before the process
# parser understood `[File not signed]`, each became its own exact rule.
UNSIGNED_TOR_LINE = (
    r"(C:\Users\Dazai\AppData\Local\CloudHandler\runtime\node.exe ->) () [File not signed] "
    r"C:\Users\Dazai\AppData\Local\CloudHandler\runtime\tor\tor\tor.exe"
)


class ProcessAndJobRuleMigrationHelperTests(TestCase):
    """The helpers that migration 0075 runs over existing rules."""

    def setUp(self):
        self.user = User.objects.create_user(username="migrator", password="pw")

    def _exact(self, source_text, status=ClassificationRule.STATUS_MALWARE, **extra):
        return ClassificationRule.objects.create(
            owner=self.user, status=status, match_type=ClassificationRule.MATCH_EXACT,
            source_text=source_text, **extra,
        )

    def test_reparse_normalizes_a_stored_process_parent(self):
        from ..analyzer import reparse_rules

        line = r"(C:\WINDOWS\Explorer.EXE ->) (Foo Inc) C:\Program Files\Foo\foo.exe"
        rule = ClassificationRule.objects.create(
            owner=self.user, status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_PARSED_ENTRY, source_text=line,
            entry_type="process", name=r"C:\WINDOWS\Explorer.EXE",
            filepath=r"C:\Program Files\Foo\foo.exe",
            normalized_filepath=r"c:\program files\foo\foo.exe",
            filename="foo.exe", company="Foo Inc",
        )

        reparse_rules(ClassificationRule.objects.all(), apply=True)

        rule.refresh_from_db()
        self.assertEqual(rule.name, r"c:\windows\explorer.exe")

    def test_convert_turns_unsigned_process_exact_rule_into_parsed(self):
        from ..analyzer import convert_exact_rules_to_parsed

        rule = self._exact(UNSIGNED_TOR_LINE, priority=19)

        result = convert_exact_rules_to_parsed(ClassificationRule.objects.all(), entry_types=("process",))

        self.assertEqual(result, {"converted": 1, "deleted": 0})
        rule.refresh_from_db()
        self.assertEqual(rule.match_type, ClassificationRule.MATCH_PARSED_ENTRY)
        self.assertEqual(rule.entry_type, "process")
        self.assertEqual(rule.filename, "tor.exe")
        self.assertTrue(rule.file_not_signed)
        self.assertEqual(rule.priority, ClassificationRule.default_priority_for(ClassificationRule.MATCH_PARSED_ENTRY))
        self.assertEqual(rule.source_text, UNSIGNED_TOR_LINE)

    def test_convert_keeps_a_custom_priority(self):
        from ..analyzer import convert_exact_rules_to_parsed

        rule = self._exact(UNSIGNED_TOR_LINE, priority=20)
        convert_exact_rules_to_parsed(ClassificationRule.objects.all(), entry_types=("process",))

        rule.refresh_from_db()
        self.assertEqual(rule.priority, 20)

    def test_convert_deletes_exact_rule_when_parsed_twin_exists(self):
        from ..analyzer import convert_exact_rules_to_parsed, parse_rule_line

        exact = self._exact(UNSIGNED_TOR_LINE)
        twin = ClassificationRule.objects.create(
            owner=self.user, **parse_rule_line(UNSIGNED_TOR_LINE, ClassificationRule.STATUS_MALWARE),
        )

        result = convert_exact_rules_to_parsed(ClassificationRule.objects.all(), entry_types=("process",))

        self.assertEqual(result, {"converted": 0, "deleted": 1})
        self.assertFalse(ClassificationRule.objects.filter(pk=exact.pk).exists())
        self.assertTrue(ClassificationRule.objects.filter(pk=twin.pk).exists())

    def test_migration_only_converts_lines_the_old_parser_could_not_read(self):
        from importlib import import_module

        newly_parseable = import_module(
            "fixlist.migrations.0075_reparse_process_and_job_rules"
        )._newly_parseable

        self.assertTrue(newly_parseable(UNSIGNED_TOR_LINE))
        self.assertTrue(newly_parseable(
            r"Task: C:\WINDOWS\Tasks\EPSON L120 Series Update {E56FDE2B-2E47-4955-9D1B-6EBE295D17DA}.job"
            r" => C:\WINDOWS\system32\spool\DRIVERS\x64\3\E_YTSLUE.EXE"
        ))
        self.assertTrue(newly_parseable(r"StartupDir: C:\Users\bob\AppData\Local\Temp\6fb2af726d\ "))

        # Already parseable before: stored as exact on purpose or for another reason.
        self.assertFalse(newly_parseable(r"(explorer.exe ->) (Foo Inc) C:\Program Files\Foo\foo.exe"))
        self.assertFalse(newly_parseable(r"Task: C:\WINDOWS\Tasks\update-sys.job => C:\Program Files (x86)\Skillbrains\Updater\Updater.exe"))
        self.assertFalse(newly_parseable(ASUS_LINE))

    def test_convert_leaves_other_exact_rules_alone(self):
        from ..analyzer import convert_exact_rules_to_parsed

        # Parses as a service, which is not one of the requested entry types.
        service = self._exact(
            r"R2 FooSvc; C:\Program Files\Foo\foo.exe [123 2026-01-01] (Foo Inc -> Foo Inc)"
        )
        unparseable = self._exact("just some text")

        result = convert_exact_rules_to_parsed(ClassificationRule.objects.all(), entry_types=("process",))

        self.assertEqual(result, {"converted": 0, "deleted": 0})
        service.refresh_from_db()
        unparseable.refresh_from_db()
        self.assertEqual(service.match_type, ClassificationRule.MATCH_EXACT)
        self.assertEqual(unparseable.match_type, ClassificationRule.MATCH_EXACT)
