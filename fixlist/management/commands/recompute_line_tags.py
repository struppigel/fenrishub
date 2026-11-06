from django.core.management.base import BaseCommand

from fixlist.tagging import current_line_tags, refresh_line_tags


class Command(BaseCommand):
    help = (
        'Recomputes which log lines the tags that match log lines (RuleTag.match_log_lines) '
        'match, for every cached analysis, and the line tags of the stat snapshots of logs '
        'that still exist. The same as "recompute log tags" on the rule tags page.'
    )

    def handle(self, *args, **opts):
        tag_count = len(current_line_tags())
        updated = refresh_line_tags(None)
        self.stdout.write(self.style.SUCCESS(
            f'Recomputed {tag_count} line tag(s) for {updated} cached analyses.'
        ))
