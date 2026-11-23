"""The performance tab of the statistics page: how long the analyzer took per
log over time (AnalysisTiming), so a slowdown shows before it times out requests.

A scan's speed is its milliseconds per 1,000 lines: logs differ in size by
orders of magnitude, so raw durations would mostly show which logs were big.
Medians and 90th percentiles, not means, so one odd log (a cold process, a
busy server) does not move a whole day. Timings exist from the day they were
first recorded on; there is nothing to show before that.
"""

from django.urls import reverse

from ..models import AnalysisTiming, UploadedLog
from .statistics import _as_local_date, _bucket_label, _bucket_start

SLOWEST_N = 10
# Log types with their own line in the per-type chart; the rest are "other".
TYPE_CHART_TOP_N = 5
OTHER_TYPES_LABEL = 'other'


def _percentile(values, fraction):
    """The `fraction` percentile of `values` (nearest rank on the sorted list); None for none."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, round(fraction * len(ordered) + 0.5 - 1e-9))
    return ordered[min(rank, len(ordered)) - 1]


def _median(values):
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def _rounded(value, digits=1):
    return None if value is None else round(value, digits)


def _speed(row):
    """Milliseconds per 1,000 lines of a timing row (created_at, log_type, lines, ms, ...)."""
    return row['duration_ms'] * 1000 / row['line_count']


def performance_stats(start_dt, end_dt, axis, granularity, tz):
    """The performance tab's context: headline numbers, the speed per bucket
    (overall and per log type), the rule count, a table per log type and the
    slowest scans in the range."""
    rows = [
        row for row in AnalysisTiming.objects.filter(created_at__range=(start_dt, end_dt)).values(
            'created_at', 'upload_id', 'log_type', 'line_count', 'char_count', 'rule_count',
            'duration_ms', 'rules_load_ms',
        )
        if row['line_count'] > 0
    ]
    for row in rows:
        row['speed'] = _speed(row)
        row['bucket'] = _bucket_start(_as_local_date(row['created_at'], tz), granularity)

    speeds = [row['speed'] for row in rows]
    loads = [row['rules_load_ms'] for row in rows if row['rules_load_ms']]
    headline = {
        'scans': len(rows),
        'median_speed': _rounded(_median(speeds)),
        'p90_speed': _rounded(_percentile(speeds, 0.9)),
        'median_seconds': _rounded(_median([row['duration_ms'] / 1000 for row in rows]), 2),
        'max_seconds': _rounded(max((row['duration_ms'] for row in rows), default=0) / 1000, 2),
        'rule_loads': len(loads),
        'median_rule_load_seconds': _rounded(_median(loads) / 1000 if loads else None, 2),
    }

    by_bucket = {}
    for row in rows:
        by_bucket.setdefault(row['bucket'], []).append(row)
    days = [_bucket_label(bucket, granularity) for bucket in axis]

    def per_bucket(compute):
        return [_rounded(compute(by_bucket[bucket])) if bucket in by_bucket else None for bucket in axis]

    speed_series = {
        'days': days,
        'series': [
            {'label': 'median', 'data': per_bucket(lambda found: _median([r['speed'] for r in found]))},
            {'label': '90th percentile', 'data': per_bucket(lambda found: _percentile([r['speed'] for r in found], 0.9))},
        ],
    }
    rule_series = {
        'days': days,
        'series': [{'label': 'enabled rules', 'data': per_bucket(lambda found: max(r['rule_count'] for r in found))}],
    }

    by_type = {}
    for row in rows:
        by_type.setdefault(row['log_type'], []).append(row)
    type_rows = sorted(
        (
            {
                'log_type': log_type,
                'scans': len(found),
                'median_lines': _rounded(_median([r['line_count'] for r in found]), 0),
                'median_seconds': _rounded(_median([r['duration_ms'] / 1000 for r in found]), 2),
                'median_speed': _rounded(_median([r['speed'] for r in found])),
                'p90_speed': _rounded(_percentile([r['speed'] for r in found], 0.9)),
            }
            for log_type, found in by_type.items()
        ),
        key=lambda item: (-item['scans'], item['log_type'].lower()),
    )
    charted = [item['log_type'] for item in type_rows[:TYPE_CHART_TOP_N]]
    groups = {log_type: [] for log_type in charted}
    for row in rows:
        groups.setdefault(row['log_type'] if row['log_type'] in charted else OTHER_TYPES_LABEL, []).append(row)
    type_series = {'days': days, 'series': []}
    for label, found in groups.items():
        grouped = {}
        for row in found:
            grouped.setdefault(row['bucket'], []).append(row['speed'])
        type_series['series'].append({
            'label': label,
            'data': [_rounded(_median(grouped[bucket])) if bucket in grouped else None for bucket in axis],
        })

    slowest = sorted(rows, key=lambda row: -row['duration_ms'])[:SLOWEST_N]
    existing = set(UploadedLog.objects.live().filter(
        upload_id__in=[row['upload_id'] for row in slowest if row['upload_id']],
    ).values_list('upload_id', flat=True))
    slowest_rows = [
        {
            'created_at': row['created_at'],
            'upload_id': row['upload_id'],
            'url': reverse('view_uploaded_log', args=[row['upload_id']]) if row['upload_id'] in existing else '',
            'log_type': row['log_type'],
            'line_count': row['line_count'],
            'seconds': round(row['duration_ms'] / 1000, 2),
            'speed': round(row['speed'], 1),
            'rule_count': row['rule_count'],
        }
        for row in slowest
    ]

    return {
        'headline': headline,
        'speed_series': speed_series,
        'rule_series': rule_series,
        'type_series': type_series,
        'types': type_rows,
        'slowest': slowest_rows,
        'slowest_n': SLOWEST_N,
    }
