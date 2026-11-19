"""The centralbox tab of the statistics page: verdicts, fresh lookups, API
usage and how much of the hashes in logs centralbox has answered for.

Database only: nothing here talks to centralbox. The stored data limits what
can be shown, and the page says so:

- HashVerdict and CentralboxFreshLookup keep one row per hash, so a hash
  counts once, at its latest check or lookup.
- CentralboxUsageMinute is purged after 7 days, so usage always covers the
  last 7 days whatever range is picked.
- UploadedLogFileHash rows go with their logs.
- The auto queue and the pause state are what they are right now.
"""

from collections import Counter
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from django.db.models import Count, Max, Min
from django.utils import timezone

from .. import centralbox, centralbox_auto
from ..models import (
    CentralboxAutoQueue, CentralboxFreshLookup, CentralboxUsageMinute, HashAlias, HashVerdict, SiteConfig,
    UploadedLogFileHash,
)
from .statistics import TRUNC_BY_GRANULARITY, UNASSIGNED_LABEL, _as_local_date, _bucket_label, _percent

TOP_N = 20
USAGE_DAYS = 7
# Rows per IN (...) list: stays below SQLite's variable limit.
CHUNK = 500

OUTCOME_MALICIOUS = 'malicious'
OUTCOME_SUSPICIOUS = 'suspicious'
OUTCOME_CLEAN = 'clean'
OUTCOME_UNKNOWN = 'not in centralbox'
OUTCOME_OTHER = 'known, no verdict'
OUTCOMES = (OUTCOME_MALICIOUS, OUTCOME_SUSPICIOUS, OUTCOME_CLEAN, OUTCOME_UNKNOWN, OUTCOME_OTHER)
FLAGGED = (HashVerdict.VERDICT_MALICIOUS, HashVerdict.VERDICT_SUSPICIOUS)

AUTO_LABEL = 'auto (Fenris)'
TIMED_OUT = 'timed out'
FRESH_STATES = (
    CentralboxFreshLookup.STATE_DONE, CentralboxFreshLookup.STATE_NOT_FOUND,
    CentralboxFreshLookup.STATE_ERROR, CentralboxFreshLookup.STATE_RUNNING, TIMED_OUT,
)
FRESH_STATE_LABELS = {
    CentralboxFreshLookup.STATE_DONE: 'done',
    CentralboxFreshLookup.STATE_NOT_FOUND: 'not found anywhere',
    CentralboxFreshLookup.STATE_ERROR: 'error',
    CentralboxFreshLookup.STATE_RUNNING: 'running',
    TIMED_OUT: 'timed out (never finished)',
}

QUEUE_PRIORITY_LABELS = {
    CentralboxAutoQueue.PRIORITY_SCANNER: 'scanner detection',
    CentralboxAutoQueue.PRIORITY_FRST_B: 'FRST B line',
    CentralboxAutoQueue.PRIORITY_MAU: 'removed by MAU',
    CentralboxAutoQueue.PRIORITY_FRST_FLAGGED: 'FRST ! / P line',
}
SOURCE_LABELS = dict(
    centralbox_auto.SCANNER_SOURCES, mau='MAU', other='other (any other hash in a log)',
    fixlog_file='Fixlog File: block', fixlog_folder='Fixlog folder listing', fixlog_other='Fixlog (other)',
)


def _chunks(values):
    values = list(values)
    for start in range(0, len(values), CHUNK):
        yield values[start:start + CHUNK]


def _outcome(state, verdict):
    if state == HashVerdict.STATE_UNKNOWN:
        return OUTCOME_UNKNOWN
    if verdict in (OUTCOME_MALICIOUS, OUTCOME_SUSPICIOUS, OUTCOME_CLEAN):
        return verdict
    return OUTCOME_OTHER


def _series(counts, axis, granularity, labels):
    """`{days, series: [{label, data}]}` over the axis for `labels` in order."""
    return {
        'days': [_bucket_label(bucket, granularity) for bucket in axis],
        'series': [
            {'label': label, 'data': [counts.get(label, {}).get(bucket, 0) for bucket in axis]}
            for label in labels
        ],
    }


def _top(queryset, field):
    rows = (
        queryset.exclude(**{field: ''}).values(field)
        .annotate(n=Count('id')).order_by('-n', field)[:TOP_N]
    )
    return [{'name': row[field], 'count': row['n']} for row in rows]


def _verdict_stats(start_dt, end_dt, axis, granularity, tz):
    qs = HashVerdict.objects.filter(checked_at__range=(start_dt, end_dt))
    trunc = TRUNC_BY_GRANULARITY[granularity]
    counts = {}
    totals = Counter()
    rows = (
        qs.annotate(bucket=trunc('checked_at', tzinfo=tz))
        .values('bucket', 'state', 'verdict').annotate(n=Count('id'))
    )
    for row in rows:
        outcome = _outcome(row['state'], row['verdict'])
        totals[outcome] += row['n']
        if row['bucket'] is None:
            continue
        by_bucket = counts.setdefault(outcome, {})
        bucket = _as_local_date(row['bucket'], tz)
        by_bucket[bucket] = by_bucket.get(bucket, 0) + row['n']
    # "known, no verdict" only gets a line when there is any.
    charted = [outcome for outcome in OUTCOMES if outcome != OUTCOME_OTHER or totals[outcome]]
    flagged_qs = qs.filter(state=HashVerdict.STATE_KNOWN, verdict__in=FLAGGED)
    return {
        'total': sum(totals.values()),
        'malicious': totals[OUTCOME_MALICIOUS],
        'suspicious': totals[OUTCOME_SUSPICIOUS],
        'clean': totals[OUTCOME_CLEAN],
        'unknown': totals[OUTCOME_UNKNOWN],
        'other': totals[OUTCOME_OTHER],
        'series': _series(counts, axis, granularity, charted),
        'families': _top(flagged_qs, 'family'),
        'malware_types': _top(flagged_qs, 'malware_type'),
    }


def _fresh_stats(start_dt, end_dt, axis, granularity, tz):
    qs = CentralboxFreshLookup.objects.filter(requested_at__range=(start_dt, end_dt))
    stale_before = timezone.now() - centralbox.FRESH_LOOKUP_TIMEOUT
    trunc = TRUNC_BY_GRANULARITY[granularity]
    rows = (
        qs.annotate(bucket=trunc('requested_at', tzinfo=tz))
        .values('bucket', 'auto', 'state', 'requested_by__username', 'requested_at')
    )
    by_kind = {}
    states = Counter()
    requesters = Counter()
    manual = auto = 0
    for row in rows.iterator(chunk_size=500):
        kind = 'auto' if row['auto'] else 'manual'
        if row['auto']:
            auto += 1
            requesters[AUTO_LABEL] += 1
        else:
            manual += 1
            requesters[(row['requested_by__username'] or '').strip() or UNASSIGNED_LABEL] += 1
        state = row['state']
        if state == CentralboxFreshLookup.STATE_RUNNING and row['requested_at'] <= stale_before:
            state = TIMED_OUT
        states[state] += 1
        if row['bucket'] is not None:
            by_bucket = by_kind.setdefault(kind, {})
            bucket = _as_local_date(row['bucket'], tz)
            by_bucket[bucket] = by_bucket.get(bucket, 0) + 1
    return {
        'total': manual + auto,
        'manual': manual,
        'auto': auto,
        'states': [
            {'state': state, 'label': FRESH_STATE_LABELS[state], 'count': states[state]}
            for state in FRESH_STATES if states[state] or state != TIMED_OUT
        ],
        'requesters': sorted(
            ({'username': name, 'count': n} for name, n in requesters.items()),
            key=lambda r: (-r['count'], r['username'].lower()),
        ),
        'series': _series(by_kind, axis, granularity, ['manual', 'auto']),
    }


def _usage_stats(tz):
    """Calls and failures per day over the last USAGE_DAYS days (all that is kept)."""
    today = timezone.localdate()
    days = [today - timedelta(days=offset) for offset in range(USAGE_DAYS - 1, -1, -1)]
    first = timezone.make_aware(datetime.combine(days[0], datetime.min.time()), tz)
    first_minute = int(first.timestamp()) // 60
    reads, fresh, failures = {}, {}, {}
    totals = Counter()
    peak = 0
    rows = CentralboxUsageMinute.objects.filter(minute__gte=first_minute).values_list('minute', 'key_id', 'calls', 'failures')
    for minute, key_id, calls, failed in rows.iterator(chunk_size=2000):
        day = datetime.fromtimestamp(minute * 60, tz=dt_timezone.utc).astimezone(tz).date()
        target = fresh if key_id == centralbox.BUDGET_FRESH else reads
        target[day] = target.get(day, 0) + calls
        failures[day] = failures.get(day, 0) + failed
        totals['fresh' if key_id == centralbox.BUDGET_FRESH else 'reads'] += calls
        totals['failures'] += failed
        if key_id == centralbox.BUDGET_READS:
            peak = max(peak, calls)
    labels = [day.isoformat() for day in days]
    return {
        'days': USAGE_DAYS,
        'reads': totals['reads'],
        'fresh': totals['fresh'],
        'failures': totals['failures'],
        'peak_reads_per_minute': peak,
        'series': {
            'days': labels,
            'series': [
                {'label': 'reads', 'data': [reads.get(day, 0) for day in days]},
                {'label': 'fresh lookups', 'data': [fresh.get(day, 0) for day in days]},
                {'label': 'failures', 'data': [failures.get(day, 0) for day in days]},
            ],
        },
    }


def _health():
    config = SiteConfig.get_solo()
    now = timezone.now()
    paused_until = config.centralbox_paused_until
    paused = bool(paused_until and paused_until > now)
    return {
        'key_set': bool(centralbox.api_key()),
        'enabled': bool(config.centralbox_enabled),
        'auto_enabled': bool(config.centralbox_auto_fresh_enabled),
        'paused': paused,
        'paused_until': paused_until if paused else None,
        'pause_reason': config.centralbox_pause_reason if paused else '',
    }


def _verdict_outcomes(sha_qs):
    """{sha256: outcome} for the SHA256s of `sha_qs` that centralbox answered for (one semi-join)."""
    rows = HashVerdict.objects.filter(sha256__in=sha_qs).values_list('sha256', 'state', 'verdict')
    return {sha: _outcome(state, verdict) for sha, state, verdict in rows}


def _md5_outcomes(md5_qs):
    """{md5: outcome} for the MD5s of `md5_qs` that have an answer: their
    SHA256's verdict (pairs seen in logs first, then centralbox's MD5 answers,
    as centralbox.resolve_md5s), or "not in centralbox" when centralbox did not
    know the MD5 itself. Semi-joins: Fixlog folder listings bring tens of
    thousands of MD5s."""
    sha_by_md5 = dict(
        UploadedLogFileHash.objects.filter(md5__in=md5_qs).exclude(sha256='')
        .order_by().values_list('md5', 'sha256').distinct()
    )
    unknown = set()
    for md5, sha in HashAlias.objects.filter(md5__in=md5_qs).values_list('md5', 'sha256'):
        if sha:
            sha_by_md5.setdefault(md5, sha)
        else:
            unknown.add(md5)
    outcomes = {}
    for chunk in _chunks(set(sha_by_md5.values())):
        outcomes.update(_verdict_outcomes(chunk))
    result = {md5: OUTCOME_UNKNOWN for md5 in unknown if md5 not in sha_by_md5}
    result.update({md5: outcomes[sha] for md5, sha in sha_by_md5.items() if sha in outcomes})
    return result


def _coverage_stats(start_dt, end_dt):
    """Per hash source: the distinct hashes in the range's logs and how many centralbox answered for.

    A hash is a SHA256, or an MD5 when the log gives no SHA256 (Trojan Killer,
    Fixlog folder listings). The rows are fetched without the model's default
    ordering, which would otherwise join the DISTINCT and multiply them.
    """
    file_hash_qs = UploadedLogFileHash.objects.filter(upload__created_at__range=(start_dt, end_dt)).order_by()
    sha_qs = file_hash_qs.exclude(sha256='')
    md5_qs = file_hash_qs.filter(sha256='').exclude(md5='')

    keys_by_source = {}
    for source, key in sha_qs.values_list('source', 'sha256').distinct().iterator(chunk_size=5000):
        keys_by_source.setdefault(source or 'other', set()).add(key)
    for source, key in md5_qs.values_list('source', 'md5').distinct().iterator(chunk_size=5000):
        keys_by_source.setdefault(source or 'other', set()).add(key)

    outcomes = _verdict_outcomes(sha_qs.values('sha256'))
    outcomes.update(_md5_outcomes(md5_qs.values('md5')))

    def summary(keys):
        found = [outcomes.get(key) for key in keys]
        answered = sum(1 for outcome in found if outcome is not None)
        return {
            'hashes': len(keys),
            'answered': answered,
            'flagged': sum(1 for outcome in found if outcome in FLAGGED),
            'percent': _percent(answered, len(keys)),
        }

    sources = sorted(
        (
            dict(summary(keys), source=source, label=SOURCE_LABELS.get(source, source))
            for source, keys in keys_by_source.items()
        ),
        key=lambda r: (-r['hashes'], r['label'].lower()),
    )
    all_keys = set().union(*keys_by_source.values()) if keys_by_source else set()
    return {'sources': sources, 'total': summary(all_keys)}


def _queue_stats():
    now = timezone.now()
    by_priority = dict(
        CentralboxAutoQueue.objects.values('priority').annotate(n=Count('id')).values_list('priority', 'n')
    )
    oldest = CentralboxAutoQueue.objects.aggregate(oldest=Min('enqueued_at'))['oldest']
    return {
        'total': sum(by_priority.values()),
        'priorities': [
            {'priority': priority, 'label': label, 'count': by_priority.get(priority, 0)}
            for priority, label in sorted(QUEUE_PRIORITY_LABELS.items())
        ],
        'oldest': oldest,
        'moving': centralbox_auto.queue_moving(now),
        'started_last_day': CentralboxFreshLookup.objects.filter(
            auto=True, requested_at__gt=now - timedelta(days=1),
        ).count(),
        'per_day': centralbox_auto.per_day(),
        'last_auto_at': CentralboxFreshLookup.objects.filter(auto=True).aggregate(last=Max('requested_at'))['last'],
    }


def centralbox_stats(start_dt, end_dt, axis, granularity, tz):
    """Everything the centralbox tab shows, as one dict."""
    return {
        'verdicts': _verdict_stats(start_dt, end_dt, axis, granularity, tz),
        'fresh': _fresh_stats(start_dt, end_dt, axis, granularity, tz),
        'usage': _usage_stats(tz),
        'health': _health(),
        'coverage': _coverage_stats(start_dt, end_dt),
        'queue': _queue_stats(),
    }
