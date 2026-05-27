from collections import Counter

from django.core.management.base import BaseCommand

from fixlist.models import UploadedLog, detect_log_type, _bump_logtype_rules_version


ANALYZED = {'FRST', 'Addition', 'FRST&Addition'}


class Command(BaseCommand):
    help = (
        'Re-runs detect_log_type() against every UploadedLog and updates the log_type field. '
        'Useful after adding/editing detection rules.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--only-unknown', action='store_true',
                            help='Only reclassify logs currently marked Unknown.')
        parser.add_argument('--dry-run', action='store_true',
                            help='Report what would change without saving.')
        parser.add_argument('--rebuild-stats', action='store_true',
                            help='Also recompute analyzer stats for any log that transitions '
                                 'into an analyzer-eligible type. Slow.')
        parser.add_argument('--chunk-size', type=int, default=200)

    def handle(self, *args, **opts):
        _bump_logtype_rules_version()
        qs = UploadedLog.objects.only('id', 'content', 'log_type')
        if opts['only_unknown']:
            qs = qs.filter(log_type='Unknown')

        transitions = Counter()
        recalc_ids = []
        scanned = 0
        for log in qs.iterator(chunk_size=opts['chunk_size']):
            scanned += 1
            new_type = detect_log_type(log.content or '')
            if new_type == log.log_type:
                continue
            transitions[(log.log_type, new_type)] += 1
            if not opts['dry_run']:
                old_type = log.log_type
                log.log_type = new_type
                log.save(update_fields=['log_type', 'updated_at'])
                if opts['rebuild_stats'] and new_type in ANALYZED and old_type not in ANALYZED:
                    recalc_ids.append(log.id)

        self.stdout.write(f'Scanned {scanned} log(s).')
        if not transitions:
            self.stdout.write('No log_type changes.')
        else:
            self.stdout.write('Transitions:')
            for (old, new), count in sorted(transitions.items(), key=lambda kv: -kv[1]):
                self.stdout.write(f'  {count:5d}  {old} -> {new}')

        if opts['rebuild_stats'] and recalc_ids:
            self.stdout.write(f'Rebuilding analyzer stats for {len(recalc_ids)} log(s)...')
            for log in UploadedLog.objects.filter(id__in=recalc_ids).iterator(chunk_size=50):
                try:
                    log.recalculate_analysis_stats()
                except Exception as exc:
                    self.stderr.write(f'  failed for log id={log.id}: {exc}')
            self.stdout.write('Stats rebuild complete.')
        elif opts['dry_run']:
            self.stdout.write('(dry-run: no changes saved)')
