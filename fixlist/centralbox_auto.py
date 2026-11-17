"""Automatic fresh centralbox lookups for likely malicious hashes.

A fresh lookup (centralbox.start_fresh_lookup) makes centralbox analyse a
hash anew with VirusTotal, Triage and others. Helpers start them by hand; this
module starts them by itself for hashes that are likely malicious:

- a scanner detected the file as malware (Malwarebytes, HitmanPro, Trojan
  Killer, HitmanPro output in a Fixlog; PUP and grayware detections do not count),
- MAU removed it and it is executable (EXECUTABLE_EXTENSIONS: the FILES
  section lists config, source and text files too; the cached MSI counts),
- an FRST / Addition line of a related log names the file and has status B, ! or P.

Only hashes centralbox does not know get one, and never a hash that already
had a fresh lookup (by anyone, ever): helpers can still re-run those by hand.

The budget is shared with the helpers, who must keep most of it:
- candidates go to a database queue (CentralboxAutoQueue) instead of being
  looked up at once; one drainer thread, holding a lease in SiteConfig that all
  workers see, works through it slowly;
- per minute, automatic lookups stop once CENTRALBOX_AUTO_FRESH_LOOKUPS_PER_MINUTE
  fresh lookups (by anyone) were started, and automatic reads (the cached check
  before a lookup, polling) once CENTRALBOX_AUTO_READS_PER_MINUTE reads were made;
- at most CENTRALBOX_AUTO_FRESH_MAX_RUNNING automatic lookups run at once, and
  at most CENTRALBOX_AUTO_FRESH_PER_DAY start per 24 hours;
- a log with more than CENTRALBOX_AUTO_FRESH_MAX_CANDIDATES_PER_LOG candidates
  is not normal: none of its hashes are queued;
- items waiting longer than CENTRALBOX_AUTO_QUEUE_MAX_AGE_DAYS are dropped.

The drainer lives in a worker process and dies with it; the queue does not.
Every trigger (an upload, the analyzer's suggestions, a log page) calls
ensure_auto_drainer(), so the next one after a restart resumes the queue.

Like centralbox.py, public functions never raise, and nothing runs in a
thread under the test runner (tests call drain_round() directly).
"""

import logging
import ntpath
import threading
import time
from datetime import timedelta

from django.conf import settings
from django.db import connections
from django.db.models import Q
from django.utils import timezone

from . import centralbox
from .file_hashes import is_md5, is_sha256, line_path_key
from .models import (
    CentralboxAutoQueue, CentralboxFreshLookup, HashVerdict, SiteConfig, UploadedLog, UploadedLogFileHash,
)

logger = logging.getLogger('fixlist.centralbox')

LEASE = timedelta(minutes=5)
ROUND_SECONDS = 20
# Related logs of the same forum user (no case) older than this are left out.
RELATED_LOG_DAYS = 30
# FRST / Addition logs read per trigger for their B / ! / P lines.
MAX_FRST_LOGS = 10

SCANNER_SOURCES = {
    'malwarebytes': 'Malwarebytes',
    'hitmanpro': 'HitmanPro',
    'trojan_killer': 'Trojan Killer',
    'fixlog_hitmanpro': 'HitmanPro (Fixlog)',
}
# MAU files worth a fresh lookup: programs, libraries, drivers, installers,
# scripts and shortcuts-to-code. Anything else in MAU's FILES section
# (.gitignore, .config, .cs, .md, .tmp, ...) is not.
EXECUTABLE_EXTENSIONS = frozenset({
    '.exe', '.dll', '.sys', '.drv', '.ocx', '.cpl', '.scr', '.com', '.pif', '.efi', '.msc',
    '.msi', '.msp', '.mst', '.appx', '.msix',
    '.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta',
    '.jar', '.py', '.pyw', '.lua', '.au3', '.a3x', '.ahk',
    # Electron app archives (app.asar): the code of the app.
    '.asar',
    # Shortcuts: malicious ones run scripts or downloaders through their arguments.
    '.lnk',
})


def is_executable_path(path):
    """True when the file name ends in one of EXECUTABLE_EXTENSIONS."""
    return ntpath.splitext((path or '').strip().strip('"').lower())[1] in EXECUTABLE_EXTENSIONS


FRST_PRIORITIES = {
    'B': CentralboxAutoQueue.PRIORITY_FRST_B,
    '!': CentralboxAutoQueue.PRIORITY_FRST_FLAGGED,
    'P': CentralboxAutoQueue.PRIORITY_FRST_FLAGGED,
}


def _setting(name, default):
    return int(getattr(settings, name, default))


def max_candidates_per_log():
    return max(0, _setting('CENTRALBOX_AUTO_FRESH_MAX_CANDIDATES_PER_LOG', 100))


def max_running():
    return max(1, _setting('CENTRALBOX_AUTO_FRESH_MAX_RUNNING', 5))


def per_day():
    return max(0, _setting('CENTRALBOX_AUTO_FRESH_PER_DAY', 100))


def reads_limit():
    return max(1, _setting('CENTRALBOX_AUTO_READS_PER_MINUTE', 40))


def queue_max_age():
    return timedelta(days=max(1, _setting('CENTRALBOX_AUTO_QUEUE_MAX_AGE_DAYS', 7)))


def auto_enabled():
    """A server key is set and the admin switch is on (centralbox may still be paused)."""
    try:
        return bool(centralbox.api_key()) and SiteConfig.get_solo().centralbox_auto_fresh_enabled
    except Exception:
        logger.exception('Reading the automatic fresh lookup switch failed')
        return False


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------

def flagged_frst_paths(uploads, user=None):
    """{normalized path: status letter} of the B / ! / P lines in the cached
    analyses of these logs' FRST / Addition logs (the viewer's rule set, or each
    log's recipient's when there is no viewer). Database only."""
    from .rule_sets import resolve_effective_rule_set_key, resolve_user_rule_set_key
    from .upload_utils import get_fresh_cached_analysis

    result = {}
    logs = [log for log in uploads if log.log_type in UploadedLog.ANALYZED_LOG_TYPES]
    logs.sort(key=lambda log: log.created_at, reverse=True)
    for log in logs[:MAX_FRST_LOGS]:
        try:
            key = resolve_user_rule_set_key(user) if user is not None else resolve_effective_rule_set_key(log)
            payload = get_fresh_cached_analysis(log, key)
        except Exception:
            logger.exception('Reading the cached analysis of %s failed', log.upload_id)
            continue
        for entry in (payload or {}).get('lines') or []:
            if not isinstance(entry, dict):
                continue
            status = entry.get('dominant_status')
            if status not in FRST_PRIORITIES:
                continue
            path = line_path_key(entry.get('line') or '')
            if not path:
                continue
            known = result.get(path)
            if known is None or FRST_PRIORITIES[status] < FRST_PRIORITIES[known]:
                result[path] = status
    return result


def _row_candidate(source, detection, path, normalized_path, flagged_paths):
    """(priority, reason) of one hash row, or None when it is not a candidate."""
    from .log_highlighting import threat_severity

    best = None
    detection = (detection or '').strip()
    if source in SCANNER_SOURCES and detection and threat_severity(detection) == 'b':
        best = (CentralboxAutoQueue.PRIORITY_SCANNER, f'{SCANNER_SOURCES[source]}: {detection}')
    if source == 'mau' and is_executable_path(path):
        option = (CentralboxAutoQueue.PRIORITY_MAU, 'removed by MAU')
        best = option if best is None or option[0] < best[0] else best
    status = flagged_paths.get(normalized_path) if normalized_path else None
    if status:
        option = (FRST_PRIORITIES[status], f'FRST line at {status}')
        best = option if best is None or option[0] < best[0] else best
    return best


def auto_fresh_candidates(upload_ids, flagged_paths=None):
    """{hash: (priority, reason)} of the likely malicious hashes in these logs
    (SHA256s, or MD5s for MD5-only rows), best priority first per hash.

    A log with more than max_candidates_per_log() candidates is skipped as a
    whole (abnormal or mis-parsed); a hash it shares with another log still
    counts through that one."""
    flagged_paths = flagged_paths or {}
    query = Q(source__in=list(SCANNER_SOURCES)) | Q(source='mau')
    if flagged_paths:
        query |= Q(normalized_path__in=list(flagged_paths))
    per_upload = {}
    rows = (
        UploadedLogFileHash.objects.filter(upload_id__in=list(upload_ids or []))
        .filter(query)
        .values_list('upload_id', 'sha256', 'md5', 'source', 'detection', 'path', 'normalized_path')
    )
    for upload_id, sha, md5, source, detection, path, normalized_path in rows.iterator():
        value = sha or md5
        if not value:
            continue
        candidate = _row_candidate(source, detection, path, normalized_path, flagged_paths)
        if candidate is None:
            continue
        found = per_upload.setdefault(upload_id, {})
        if value not in found or candidate[0] < found[value][0]:
            found[value] = candidate

    limit = max_candidates_per_log()
    result = {}
    for upload_id, found in per_upload.items():
        if len(found) > limit:
            logger.warning(
                'Automatic fresh lookups: upload pk=%s has %s candidates (more than %s); none are queued',
                upload_id, len(found), limit,
            )
            continue
        for value, candidate in found.items():
            if value not in result or candidate[0] < result[value][0]:
                result[value] = candidate
    return result


def _needs_lookup(candidates):
    """The candidates that may need a fresh lookup: MD5s are replaced by the
    SHA256 they stand for when it is known; hashes centralbox knows and hashes
    that already had a fresh lookup are left out."""
    md5_map = centralbox.resolve_md5s([h for h in candidates if is_md5(h)])
    resolved = {}
    for value, candidate in candidates.items():
        key = md5_map.get(value, value)
        if key not in resolved or candidate[0] < resolved[key][0]:
            resolved[key] = candidate
    if not resolved:
        return {}
    keys = list(resolved)
    known = set(
        HashVerdict.objects.filter(sha256__in=keys, state=HashVerdict.STATE_KNOWN).values_list('sha256', flat=True)
    )
    looked_up = set(CentralboxFreshLookup.objects.filter(sha256__in=keys).values_list('sha256', flat=True))
    return {
        key: candidate for key, candidate in resolved.items()
        if key not in known and key not in looked_up and (is_sha256(key) or is_md5(key))
    }


# ---------------------------------------------------------------------------
# Queue
# ---------------------------------------------------------------------------

def enqueue_auto_fresh(upload_ids, flagged_paths=None, start=True):
    """Queue the likely malicious hashes of these logs that need a fresh
    lookup; a hash already queued keeps the better priority. Then makes sure
    a drainer runs (unless `start` is False). Returns how many were added.
    Database only (the drainer does the lookups); never raises."""
    try:
        if not auto_enabled():
            return 0
        wanted = _needs_lookup(auto_fresh_candidates(upload_ids, flagged_paths))
        added = 0
        if wanted:
            now = timezone.now()
            existing = dict(
                CentralboxAutoQueue.objects.filter(hash__in=list(wanted)).values_list('hash', 'priority')
            )
            new_rows = [
                CentralboxAutoQueue(hash=value, priority=priority, reason=reason[:200], enqueued_at=now)
                for value, (priority, reason) in wanted.items() if value not in existing
            ]
            if new_rows:
                CentralboxAutoQueue.objects.bulk_create(new_rows, ignore_conflicts=True)
                added = len(new_rows)
            for value, (priority, reason) in wanted.items():
                if value in existing and priority < existing[value]:
                    CentralboxAutoQueue.objects.filter(hash=value).update(priority=priority, reason=reason[:200])
        if start:
            ensure_auto_drainer()
        return added
    except Exception:
        logger.exception('Queueing automatic fresh lookups failed')
        return 0


def related_group(upload):
    """The upload and the logs it is correlated with when nobody is viewing it:
    the same forum user's logs of the last RELATED_LOG_DAYS days."""
    from .case_correlations import SCOPE_USER, related_upload_ids

    ids, scope, _name = related_upload_ids(upload, None)
    if ids and scope == SCOPE_USER:
        since = timezone.now() - timedelta(days=RELATED_LOG_DAYS)
        ids = list(UploadedLog.objects.filter(pk__in=ids, created_at__gte=since).values_list('pk', flat=True))
    return [upload.pk] + list(ids)


def enqueue_for_upload(upload):
    """After an upload (in the background thread): queue the likely malicious
    hashes of the upload and its forum user's recent logs. Never raises."""
    try:
        if not auto_enabled():
            return 0
        ids = related_group(upload)
        logs = list(UploadedLog.objects.filter(
            pk__in=ids, deleted_at__isnull=True, log_type__in=UploadedLog.ANALYZED_LOG_TYPES,
        ))
        return enqueue_auto_fresh(ids, flagged_frst_paths(logs))
    except Exception:
        logger.exception('Queueing automatic fresh lookups failed for upload pk=%s', getattr(upload, 'pk', '?'))
        return 0


def queue_state(hashes):
    """(queued, running) counts among these hashes. Database only."""
    hashes = [h for h in set(hashes or []) if h]
    if not hashes:
        return 0, 0
    since = timezone.now() - centralbox.FRESH_LOOKUP_TIMEOUT
    queued = CentralboxAutoQueue.objects.filter(hash__in=hashes).count()
    running = CentralboxFreshLookup.objects.filter(
        sha256__in=hashes, state=CentralboxFreshLookup.STATE_RUNNING, requested_at__gt=since,
    ).count()
    return queued, running


def queued_hashes(hashes):
    """The hashes among these that wait in the queue. Database only, never raises."""
    try:
        hashes = [h for h in set(hashes or []) if h]
        if not hashes:
            return []
        return sorted(CentralboxAutoQueue.objects.filter(hash__in=hashes).values_list('hash', flat=True))
    except Exception:
        logger.exception('Reading the automatic lookup queue failed')
        return []


# ---------------------------------------------------------------------------
# Drainer
# ---------------------------------------------------------------------------

def _running_auto():
    return CentralboxFreshLookup.objects.filter(auto=True, state=CentralboxFreshLookup.STATE_RUNNING)


def _started_last_day(now):
    return CentralboxFreshLookup.objects.filter(auto=True, requested_at__gt=now - timedelta(days=1)).count()


def _has_work(now=None):
    now = now or timezone.now()
    if _running_auto().exists():
        return True
    return CentralboxAutoQueue.objects.exists() and _started_last_day(now) < per_day()


def _take_lease(now=None):
    """The new lease end when this caller may run the drainer, else None."""
    now = now or timezone.now()
    until = now + LEASE
    SiteConfig.get_solo()
    taken = SiteConfig.objects.filter(pk=1).filter(
        Q(centralbox_auto_drainer_until__isnull=True) | Q(centralbox_auto_drainer_until__lte=now)
    ).update(centralbox_auto_drainer_until=until)
    return until if taken else None


def _renew_lease(until):
    """Extend a held lease; None when someone else holds it now."""
    new_until = timezone.now() + LEASE
    renewed = SiteConfig.objects.filter(pk=1, centralbox_auto_drainer_until=until).update(
        centralbox_auto_drainer_until=new_until,
    )
    return new_until if renewed else None


def _release_lease(until):
    SiteConfig.objects.filter(pk=1, centralbox_auto_drainer_until=until).update(centralbox_auto_drainer_until=None)


def ensure_auto_drainer():
    """Start the drainer thread unless one runs (in any worker) or there is
    nothing to do. Cheap enough for every page view. Never raises."""
    try:
        if getattr(settings, 'TESTING', False):
            return False
        if not auto_enabled() or not centralbox.is_available() or not _has_work():
            return False
        until = _take_lease()
        if until is None:
            return False
        threading.Thread(
            target=_drain_in_thread, args=(until,), name='centralbox-auto-fresh', daemon=True,
        ).start()
        return True
    except Exception:
        logger.exception('Starting the automatic fresh lookup drainer failed')
        return False


def _drain_in_thread(until):
    try:
        while until is not None:
            if not drain_round():
                break
            time.sleep(ROUND_SECONDS)
            until = _renew_lease(until)
    except Exception:
        logger.exception('The automatic fresh lookup drainer failed')
    finally:
        try:
            if until is not None:
                _release_lease(until)
        finally:
            connections.close_all()


def _known_to_centralbox(value):
    """A cached read before a fresh lookup: True when centralbox knows the
    hash, False when it does not, None without an answer (budget, failure,
    centralbox still busy with it)."""
    if is_md5(value):
        result = centralbox.check_md5(value)
        verdict = result.get('verdict')
        if verdict:
            return verdict.get('state') == HashVerdict.STATE_KNOWN
        return False if result.get('unknown') else None
    result = centralbox.check_hashes([value], max_calls=2, deadline_seconds=8.0)
    verdict = result.get('verdicts', {}).get(value)
    if verdict is None:
        return None
    return verdict.get('state') == HashVerdict.STATE_KNOWN


def drain_round():
    """One pass of the drainer: poll the running automatic lookups, then start
    queued ones within every limit. True while there is more to do. Never raises."""
    try:
        if not auto_enabled() or not centralbox.is_available():
            return False
        now = timezone.now()
        CentralboxAutoQueue.objects.filter(enqueued_at__lt=now - queue_max_age()).delete()

        limit = reads_limit()
        for value in list(_running_auto().values_list('sha256', flat=True)):
            if centralbox.budget_used(centralbox.BUDGET_READS) >= limit:
                break
            centralbox.poll_fresh_lookup(value, reads_limit=limit)

        running = _running_auto().count()
        started = _started_last_day(now)
        daily = per_day()
        skipped = []
        started_now = 0
        waiting_for_budget = False
        while running < max_running() and started < daily:
            if not centralbox.is_available():
                break
            item = CentralboxAutoQueue.objects.exclude(pk__in=skipped).order_by('priority', 'enqueued_at', 'pk').first()
            if item is None:
                break
            if CentralboxFreshLookup.objects.filter(sha256=item.hash).exists():
                item.delete()
                continue
            if (centralbox.budget_used(centralbox.BUDGET_FRESH) >= centralbox.auto_fresh_lookups_per_minute()
                    or centralbox.budget_used(centralbox.BUDGET_READS) >= limit):
                waiting_for_budget = True
                break
            known = _known_to_centralbox(item.hash)
            if known is None:
                skipped.append(item.pk)
                continue
            if known:
                item.delete()
                continue
            result = centralbox.start_fresh_lookup(item.hash, None, auto=True)
            if not result.get('ok'):
                # Budget used up by others meanwhile, or centralbox failing (then paused).
                waiting_for_budget = True
                break
            CentralboxAutoQueue.objects.filter(pk=item.pk).delete()
            started += 1
            started_now += 1
            logger.info('Automatic fresh centralbox lookup of %s (%s)', item.hash, item.reason)
            if result.get('state') == CentralboxFreshLookup.STATE_RUNNING:
                running += 1

        if not centralbox.is_available():
            return False
        if _running_auto().exists():
            return True
        # Go on while the queue moves or only waits for the next minute's
        # budget; items without an answer wait for the next trigger instead
        # of being read again every round.
        return (started_now > 0 or waiting_for_budget) and started < daily and CentralboxAutoQueue.objects.exists()
    except Exception:
        logger.exception('An automatic fresh lookup round failed')
        return False
