import logging
import os
import time

from django.core.management.base import BaseCommand

from fixlist.models import UploadedLog
from fixlist.rule_sets import SHARED_RULE_SET_KEY
from fixlist.tagging import REFRESH_BATCH_SIZE, found_tags_by_upload

logger = logging.getLogger(__name__)

PROGRESS_EVERY = 50


def lower_process_priority():
    """Give this process the lowest CPU priority the OS allows.

    POSIX only; on Windows the admin launcher starts the process in the
    below-normal priority class instead (see start_reanalysis_process).
    """
    if not hasattr(os, 'nice'):
        return
    try:
        os.nice(19)
    except OSError:
        pass


def untagged_pks(pks):
    """The pks among `pks` whose log has no tag at all under the shared rule set.

    A log without a fresh cached analysis has no tags (see found_tags_by_upload).
    """
    result = []
    for start in range(0, len(pks), REFRESH_BATCH_SIZE):
        batch = pks[start:start + REFRESH_BATCH_SIZE]
        found = found_tags_by_upload(batch, SHARED_RULE_SET_KEY)
        result.extend(pk for pk in batch if not found.get(pk))
    return result


class Command(BaseCommand):
    help = (
        'Reanalyzes every (non-deleted) uploaded log of one log type: recomputes its '
        'analysis stats, cached analyses, line tags and stat snapshot. Runs at low priority.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--log-type', required=True,
                            help='Exact log type to reanalyze, e.g. FRST.')
        parser.add_argument('--only-untagged', action='store_true',
                            help='Only reanalyze logs that currently have no tags at all.')
        parser.add_argument('--dry-run', action='store_true',
                            help='Report how many logs would be reanalyzed without changing anything.')
        parser.add_argument('--chunk-size', type=int, default=200)

    def _progress(self, message):
        # Started from the admin, the process shares the server's stdout, so this lands in the deploy log.
        self.stdout.write(message)
        self.stdout.flush()

    def handle(self, *args, **opts):
        lower_process_priority()
        log_type = opts['log_type']
        only_untagged = opts['only_untagged']
        chunk_size = max(1, opts['chunk_size'])

        pks = list(
            UploadedLog.objects.filter(log_type=log_type, deleted_at__isnull=True)
            .order_by('pk').values_list('pk', flat=True)
        )
        if only_untagged:
            pks = untagged_pks(pks)

        qualifier = ' without tags' if only_untagged else ''
        self._progress(f'Found {len(pks)} log(s) of type {log_type}{qualifier}.')
        if opts['dry_run']:
            self.stdout.write('(dry-run: nothing reanalyzed)')
            return

        started = time.monotonic()
        done = 0
        failed = 0
        for start in range(0, len(pks), chunk_size):
            chunk = pks[start:start + chunk_size]
            for log in UploadedLog.objects.filter(pk__in=chunk, deleted_at__isnull=True).order_by('pk').iterator():
                try:
                    log.recalculate_analysis_stats()
                    done += 1
                except Exception as exc:
                    failed += 1
                    self.stderr.write(f'  failed for log id={log.id}: {exc}')
                    logger.exception('reanalyze_logs failed for log id=%s', log.id)
                processed = done + failed
                if processed % PROGRESS_EVERY == 0:
                    self._progress(f'{processed}/{len(pks)} processed ({failed} failed)')

        self._progress(
            f'Reanalyzed {done} log(s) of type {log_type}{qualifier}, '
            f'{failed} failed, in {time.monotonic() - started:.1f}s.'
        )
