"""Aggregate statistics across snapshotted upload and fixlist data."""

from datetime import date, datetime, time, timedelta

from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count, ExpressionWrapper, F, FloatField, Min, Sum
from django.db.models.functions import TruncDate, TruncMonth, TruncWeek
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from ..models import FixlistStat, UploadedLogStat


ANALYZED_LOG_TYPES = ['FRST', 'Addition', 'FRST&Addition']
UNASSIGNED_LABEL = 'Unassigned'
DEFAULT_RANGE_DAYS = 30
TOP_N = 20
# Charts group by day up to this many days, by week up to WEEKLY_MAX_DAYS,
# by month beyond, so a long range stays readable and the page small.
DAILY_MAX_DAYS = 90
WEEKLY_MAX_DAYS = 731
TRUNC_BY_GRANULARITY = {'day': TruncDate, 'week': TruncWeek, 'month': TruncMonth}


def _parse_date(raw):
    if not raw:
        return None
    try:
        return datetime.strptime(raw.strip(), '%Y-%m-%d').date()
    except (ValueError, AttributeError):
        return None


def _oldest_data_date():
    """Local date of the oldest upload or fixlist snapshot, or None when there is none."""
    oldest = [
        value for value in (
            UploadedLogStat.objects.aggregate(first=Min('created_at'))['first'],
            FixlistStat.objects.aggregate(first=Min('created_at'))['first'],
        ) if value is not None
    ]
    return timezone.localdate(min(oldest)) if oldest else None


def _resolve_range(request):
    """The (start, end) dates and datetimes to show, kept to days that can hold data.

    Dates come from the URL, and every day of the range costs memory in the
    charts, so the range never reaches past today or before the oldest data -
    except that the default 30-day window always stays whole. `all=1` asks for
    everything from the oldest data on.
    """
    today = timezone.localdate()
    default_start = today - timedelta(days=DEFAULT_RANGE_DAYS - 1)

    start_date = _parse_date(request.GET.get('start')) or default_start
    end_date = _parse_date(request.GET.get('end')) or today
    start_date = min(start_date, today)
    end_date = min(end_date, today)
    if start_date > end_date:
        start_date, end_date = end_date, start_date

    window_start = end_date - timedelta(days=DEFAULT_RANGE_DAYS - 1)
    oldest = _oldest_data_date()
    floor = min(oldest, window_start) if oldest is not None else window_start
    if request.GET.get('all') == '1':
        start_date, end_date = floor, today
    else:
        start_date = max(start_date, floor)

    tz = timezone.get_current_timezone()
    start_dt = timezone.make_aware(datetime.combine(start_date, time.min), tz)
    end_dt = timezone.make_aware(datetime.combine(end_date, time.max), tz)
    return start_date, end_date, start_dt, end_dt


def _granularity(start_date, end_date):
    days = (end_date - start_date).days + 1
    if days <= DAILY_MAX_DAYS:
        return 'day'
    if days <= WEEKLY_MAX_DAYS:
        return 'week'
    return 'month'


def _bucket_start(day, granularity):
    if granularity == 'week':
        return day - timedelta(days=day.weekday())
    if granularity == 'month':
        return day.replace(day=1)
    return day


def _bucket_axis(start_date, end_date, granularity):
    """The start date of every bucket from start_date's to end_date's."""
    axis = []
    cursor = _bucket_start(start_date, granularity)
    while cursor <= end_date:
        axis.append(cursor)
        if granularity == 'week':
            cursor += timedelta(days=7)
        elif granularity == 'month':
            cursor = date(cursor.year + cursor.month // 12, cursor.month % 12 + 1, 1)
        else:
            cursor += timedelta(days=1)
    return axis


def _bucket_label(bucket, granularity):
    return bucket.strftime('%Y-%m') if granularity == 'month' else bucket.isoformat()


def _as_local_date(value, tz):
    """A truncated `created_at` as a date: TruncDate gives dates, TruncWeek/Month datetimes."""
    if isinstance(value, datetime):
        if timezone.is_aware(value):
            value = value.astimezone(tz)
        return value.date()
    return value


def _counts_by_bucket_and_label(queryset, label_field, granularity, tz):
    """``{label: {bucket_date: count}}`` for one person field, counted in the database."""
    trunc = TRUNC_BY_GRANULARITY[granularity]
    rows = (
        queryset.annotate(bucket=trunc('created_at', tzinfo=tz))
        .values('bucket', label_field)
        .annotate(n=Count('id'))
    )
    counts = {}
    for row in rows:
        if row['bucket'] is None:
            continue
        label = (row[label_field] or '').strip() or UNASSIGNED_LABEL
        by_bucket = counts.setdefault(label, {})
        bucket = _as_local_date(row['bucket'], tz)
        by_bucket[bucket] = by_bucket.get(bucket, 0) + row['n']
    return counts


def _helper_series(counts, axis, granularity):
    """Chart data: one line per helper over the bucket axis, busiest helper first."""
    totals = sorted(
        ((label, sum(by_bucket.values())) for label, by_bucket in counts.items()),
        key=lambda r: (-r[1], r[0].lower()),
    )
    return {
        'days': [_bucket_label(bucket, granularity) for bucket in axis],
        'series': [
            {'username': label, 'data': [counts[label].get(bucket, 0) for bucket in axis]}
            for label, _ in totals
        ],
    }


def _bucket_recipient(row):
    username = (row.get('recipient_username') or '').strip()
    return username or UNASSIGNED_LABEL


def _bucket_owner(row):
    return (row.get('owner_username') or '').strip() or UNASSIGNED_LABEL


@login_required
@require_http_methods(['GET'])
def statistics_view(request):
    start_date, end_date, start_dt, end_dt = _resolve_range(request)

    log_qs = UploadedLogStat.objects.filter(created_at__range=(start_dt, end_dt))
    fixlist_qs = FixlistStat.objects.filter(created_at__range=(start_dt, end_dt))

    line_totals = log_qs.aggregate(
        b=Sum('count_malware'),
        p=Sum('count_pup'),
        warn=Sum('count_warning'),
    )
    headline = {
        'total_logs': log_qs.count(),
        'malware_lines': line_totals['b'] or 0,
        'pup_lines': line_totals['p'] or 0,
        'warning_lines': line_totals['warn'] or 0,
    }

    fixlog_qs = log_qs.filter(log_type='Fixlog')
    fixlog_totals = fixlog_qs.aggregate(
        success=Sum('fixlog_success'),
        not_found=Sum('fixlog_not_found'),
        error=Sum('fixlog_error'),
        total=Sum('fixlog_total'),
    )
    fixlog_summary = {
        'count': fixlog_qs.count(),
        'success': fixlog_totals['success'] or 0,
        'not_found': fixlog_totals['not_found'] or 0,
        'error': fixlog_totals['error'] or 0,
        'total': fixlog_totals['total'] or 0,
    }

    totals_by_type = {
        row['log_type']: row['n']
        for row in log_qs.filter(log_type__in=ANALYZED_LOG_TYPES).values('log_type').annotate(n=Count('id'))
    }
    infected_by_type = {
        row['log_type']: row['n']
        for row in log_qs.filter(log_type__in=ANALYZED_LOG_TYPES, count_malware__gt=0)
        .values('log_type').annotate(n=Count('id'))
    }
    malware_by_log_type = []
    for lt in ANALYZED_LOG_TYPES:
        total = totals_by_type.get(lt, 0)
        infected = infected_by_type.get(lt, 0)
        percent = round(infected / total * 100, 1) if total else 0.0
        malware_by_log_type.append({
            'log_type': lt,
            'infected': infected,
            'total': total,
            'percent': percent,
        })

    logs_per_helper_raw = (
        log_qs.values('recipient_username')
        .annotate(n=Count('id'))
        .order_by('-n', 'recipient_username')
    )
    logs_per_helper_buckets = {}
    for row in logs_per_helper_raw:
        label = _bucket_recipient(row)
        logs_per_helper_buckets[label] = logs_per_helper_buckets.get(label, 0) + row['n']
    logs_per_helper = sorted(
        ({'username': k, 'count': v} for k, v in logs_per_helper_buckets.items()),
        key=lambda r: (-r['count'], r['username'].lower()),
    )

    analyzed_qs = log_qs.filter(log_type__in=ANALYZED_LOG_TYPES, total_line_count__gt=0)
    known_pct_expr = ExpressionWrapper(
        (F('total_line_count') - F('count_unknown')) * 100.0 / F('total_line_count'),
        output_field=FloatField(),
    )
    analyzed_agg = analyzed_qs.annotate(known_pct=known_pct_expr).aggregate(
        mean_known=Avg('known_pct'),
        n=Count('id'),
    )
    mean_known = round(analyzed_agg['mean_known'], 1) if analyzed_agg['mean_known'] is not None else 0.0
    mean_unknown = round(100.0 - mean_known, 1) if analyzed_agg['mean_known'] is not None else 0.0
    known_unknown = {
        'mean_known_pct': mean_known,
        'mean_unknown_pct': mean_unknown,
        'analyzed_log_count': analyzed_agg['n'] or 0,
    }

    tz = timezone.get_current_timezone()
    granularity = _granularity(start_date, end_date)
    axis = _bucket_axis(start_date, end_date, granularity)

    # Uploads per bucket are the per-helper counts summed: one query for both charts.
    log_counts = _counts_by_bucket_and_label(log_qs, 'recipient_username', granularity, tz)
    uploads_by_bucket = {}
    for by_bucket in log_counts.values():
        for bucket, n in by_bucket.items():
            uploads_by_bucket[bucket] = uploads_by_bucket.get(bucket, 0) + n
    uploads_per_day = [
        {'day': _bucket_label(bucket, granularity), 'count': uploads_by_bucket.get(bucket, 0)}
        for bucket in axis
    ]
    logs_per_helper_series = _helper_series(log_counts, axis, granularity)

    fixlists_per_helper_raw = (
        fixlist_qs.values('owner_username')
        .annotate(n=Count('id'))
        .order_by('-n', 'owner_username')
    )
    fixlists_per_helper_buckets = {}
    for row in fixlists_per_helper_raw:
        label = _bucket_owner(row)
        fixlists_per_helper_buckets[label] = fixlists_per_helper_buckets.get(label, 0) + row['n']
    fixlists_per_helper = sorted(
        ({'username': k, 'count': v} for k, v in fixlists_per_helper_buckets.items()),
        key=lambda r: (-r['count'], r['username'].lower()),
    )

    fixlists_per_helper_series = _helper_series(
        _counts_by_bucket_and_label(fixlist_qs, 'owner_username', granularity, tz), axis, granularity,
    )

    context = {
        'start_date': start_date.isoformat(),
        'end_date': end_date.isoformat(),
        'granularity': granularity,
        'headline': headline,
        'malware_by_log_type': malware_by_log_type,
        'fixlog_summary': fixlog_summary,
        'logs_per_helper': logs_per_helper,
        'logs_per_helper_top': logs_per_helper[:TOP_N],
        'logs_per_helper_series': logs_per_helper_series,
        'uploads_per_day': uploads_per_day,
        'known_unknown': known_unknown,
        'fixlists_per_helper': fixlists_per_helper,
        'fixlists_per_helper_top': fixlists_per_helper[:TOP_N],
        'fixlists_per_helper_series': fixlists_per_helper_series,
    }
    return render(request, 'statistics.html', context)
