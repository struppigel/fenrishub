"""List malware (B) rules that Spor's Autodetect database does not cover yet.

Spor (tools/Spor) ships a curated pattern database of known malware families,
resources/autodetect.txt, rewritten by hand from FenrisHub's B rules for what
Spor sees. Its last column lists the FenrisHub rule ids each row covers. This
command prints the enabled B rules of the shared rule set whose ids are not
listed there, grouped by tag, so a later sync only has to look at new rules.
Browser-extension ids are left out (Spor does not list extensions).

Usage:

    python manage.py spor_pattern_candidates
    python manage.py spor_pattern_candidates --db path/to/autodetect.txt --tag RenLoader

Read-only.
"""

import re
from collections import defaultdict
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db.models import Q

from fixlist.models import ClassificationRule
from fixlist.rule_sets import SHARED_RULE_SET_KEY

DEFAULT_DB = Path(settings.BASE_DIR) / 'tools' / 'Spor' / 'resources' / 'autodetect.txt'
# A Chromium extension id, or a Firefox add-on id like name@domain: Spor does not list extensions.
_EXTENSION_ID_RE = re.compile(r'^(?:[a-p]{32}|[\w.+-]+@[\w.-]+)$')


def covered_ids(text):
    """FenrisHub rule ids in the last column of autodetect.txt rows."""
    ids = set()
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        columns = line.split('\t')
        if len(columns) >= 6:
            ids.update(int(part) for part in columns[5].split(',') if part.strip().isdigit())
    return ids


class Command(BaseCommand):
    help = "List enabled shared B rules not yet covered by Spor's autodetect.txt, grouped by tag."

    def add_arguments(self, parser):
        parser.add_argument('--db', default=str(DEFAULT_DB), help='path of autodetect.txt')
        parser.add_argument('--tag', default='', help='only rules with this tag')

    def handle(self, *args, **options):
        path = Path(options['db'])
        if not path.is_file():
            raise CommandError(f'{path} not found')
        covered = covered_ids(path.read_text(encoding='utf-8'))
        rules = (ClassificationRule.objects
                 .filter(status=ClassificationRule.STATUS_MALWARE, is_enabled=True)
                 .filter(Q(owner__fenris_profile__rule_set_mode=SHARED_RULE_SET_KEY)
                         | Q(owner__fenris_profile__isnull=True))
                 .exclude(pk__in=covered)
                 .prefetch_related('tags')
                 .order_by('id'))
        if options['tag']:
            rules = rules.filter(tags__name=options['tag'])
        groups = defaultdict(list)
        skipped = 0
        for rule in rules:
            if _EXTENSION_ID_RE.match(rule.source_text.strip()) or rule.entry_type == 'browser_extension':
                skipped += 1
                continue
            for tag in [tag.name for tag in rule.tags.all()] or ['(no tag)']:
                groups[tag].append(rule)
        total = len({rule.id for group in groups.values() for rule in group})
        for tag in sorted(groups, key=lambda name: (-len(groups[name]), name.lower())):
            self.stdout.write(f'-- {tag} ({len(groups[tag])})')
            for rule in groups[tag]:
                note = (rule.description or '').replace('\n', ' ')[:60]
                self.stdout.write(f'   #{rule.id} {rule.match_type} {rule.entry_type or "-"} '
                                  f'{rule.source_text[:140]!r}' + (f'  ({note})' if note else ''))
        self.stdout.write(f'{total} rules not covered ({len(covered)} covered, {skipped} extension ids left out).')
