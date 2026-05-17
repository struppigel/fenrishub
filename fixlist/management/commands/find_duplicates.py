"""List rules whose matching identity is identical.

Two parsed-entry rules with the same FrstEntry comparison fields and the same
status are redundant — only one of them ever does any work. Similarly for
filepath rules sharing the same normalized_filepath and status. This command
prints those groups so an admin can decide which to disable.

Usage:

    python manage.py find_duplicates

This is read-only. The same logic is also available as an admin view at
/admin/fixlist/classificationrule/duplicates/ which offers a bulk-disable form.
"""

from django.core.management.base import BaseCommand

from fixlist.analyzer import find_rule_duplicates
from fixlist.models import ClassificationRule


class Command(BaseCommand):
    help = "List parsed-entry and filepath rules with identical matching identity."

    def handle(self, *args, **options):
        qs = ClassificationRule.objects.filter(
            match_type__in=(
                ClassificationRule.MATCH_PARSED_ENTRY,
                ClassificationRule.MATCH_FILEPATH,
            )
        ).select_related('owner')
        groups = find_rule_duplicates(qs)
        total = sum(len(g) for g in groups)

        for group in groups:
            first = group[0]
            self.stdout.write(
                f"-- {first.match_type} status={first.status} "
                f"entry_type={first.entry_type or '-'} "
                f"filepath={first.filepath[:80]!r}"
            )
            for rule in group:
                badge = "" if rule.is_enabled else " [disabled]"
                self.stdout.write(
                    f"   #{rule.id} owner={rule.owner.username}{badge} "
                    f"source_text={rule.source_text[:120]!r}"
                )

        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS(
                f"Found {len(groups)} duplicate group(s) covering {total} rule(s)."
            )
        )
