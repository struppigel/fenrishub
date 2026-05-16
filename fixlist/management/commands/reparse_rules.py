"""Re-parse stored ClassificationRule rows using the current parser.

When a parser bug is fixed (e.g. the scheduled-task `(x86)` / empty-company
case), rules that were created via the buggy parser keep their bad parsed
metadata in the DB — clsid, filepath, filename, company, etc. The matcher
compares those stored fields against freshly parsed log entries, so until they
are rewritten the affected rules either silently stop matching the lines they
were created from, or worse, match unrelated lines whose paths happen to
collide with the broken stored filepath.

Usage:

    python manage.py reparse_rules               # dry run: report diffs only
    python manage.py reparse_rules --apply       # write changes
    python manage.py reparse_rules --apply --status B  # only rules with status B

This command is also available as an admin action (Rules → "Re-parse selected
rules from source_text") for environments without shell access (e.g. Railway).
"""

from django.core.management.base import BaseCommand

from fixlist.analyzer import reparse_rules
from fixlist.models import ClassificationRule


class Command(BaseCommand):
    help = (
        "Re-parse each ClassificationRule's source_text with the current parser "
        "and report (or apply) differences in stored parsed metadata."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Persist changes. Without this flag the command only reports diffs.",
        )
        parser.add_argument(
            "--status",
            default=None,
            help="Restrict to rules with this status code (B, P, C, !, G, S, I, J, ?).",
        )
        parser.add_argument(
            "--match-type",
            default=None,
            help="Restrict to a specific match_type (default: parsed_entry and filepath).",
        )

    def handle(self, *args, **options):
        apply_changes = options["apply"]
        status_filter = options["status"]
        match_type_filter = options["match_type"]

        qs = ClassificationRule.objects.all()
        if status_filter:
            qs = qs.filter(status=status_filter)
        if match_type_filter:
            qs = qs.filter(match_type=match_type_filter)
        else:
            qs = qs.filter(
                match_type__in=(
                    ClassificationRule.MATCH_PARSED_ENTRY,
                    ClassificationRule.MATCH_FILEPATH,
                )
            )

        total = qs.count()
        result = reparse_rules(qs, apply=apply_changes)

        for diff in result["diffs"]:
            rule = diff["rule"]
            self.stdout.write(f"#{rule.id} (status={rule.status}): {len(diff['fields'])} field(s) changed")
            self.stdout.write(f"    source_text: {rule.source_text[:120]}")
            for field, (old_value, new_value) in diff["fields"].items():
                self.stdout.write(f"    {field}: {old_value!r}  ->  {new_value!r}")

        self.stdout.write("")
        action = "applied" if apply_changes else "would change"
        self.stdout.write(
            self.style.SUCCESS(
                f"Scanned {total} rule(s): {action} {result['changed']}, "
                f"unchanged {result['unchanged']}, "
                f"match_type would change {result['match_type_skip']} (skipped), "
                f"unparseable {result['unparseable']}."
            )
        )

        if apply_changes and result["changed"]:
            self.stdout.write("Rule bucket cache invalidated.")
        elif not apply_changes:
            self.stdout.write("Dry run — re-run with --apply to persist changes.")
