"""Aggregate statistics across snapshotted upload and fixlist data."""

from datetime import datetime, time, timedelta

from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count, ExpressionWrapper, F, FloatField, Sum
from django.db.models.functions import TruncDate
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from ..models import FixlistStat, UploadedLogStat


ANALYZED_LOG_TYPES = ['FRST', 'Addition', 'FRST&Addition']
UNASSIGNED_LABEL = 'Unassigned'
DEFAULT_RANGE_DAYS = 30
TOP_N = 20


def _parse_date(raw):
    if not raw:
        return None
    try:
        return datetime.strptime(raw.strip(), '%Y-%m-%d').date()
    except (ValueError, AttributeError):
        return None


def _resolve_range(request):
    today = timezone.localdate()
    default_start = today - timedelta(days=DEFAULT_RANGE_DAYS - 1)

    start_date = _parse_date(request.GET.get('start')) or default_start
    end_date = _parse_date(request.GET.get('end')) or today

    if start_date > end_date:
        start_date, end_date = end_date, start_date

    tz = timezone.get_current_timezone()
    start_dt = timezone.make_aware(datetime.combine(start_date, time.min), tz)
    end_dt = timezone.make_aware(datetime.combine(end_date, time.max), tz)
    return start_date, end_date, start_dt, end_dt


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
    per_day_raw = (
        log_qs.annotate(day=TruncDate('created_at', tzinfo=tz))
        .values('day')
        .annotate(n=Count('id'))
    )
    per_day_map = {row['day']: row['n'] for row in per_day_raw if row['day'] is not None}

    day_axis = []
    cursor = start_date
    while cursor <= end_date:
        day_axis.append(cursor)
        cursor += timedelta(days=1)
    day_axis_iso = [d.isoformat() for d in day_axis]

    uploads_per_day = [
        {'day': d.isoformat(), 'count': per_day_map.get(d, 0)} for d in day_axis
    ]

    helper_day_raw = (
        log_qs.annotate(day=TruncDate('created_at', tzinfo=tz))
        .values('day', 'recipient_username')
        .annotate(n=Count('id'))
    )
    helper_day_map = {}
    for row in helper_day_raw:
        if row['day'] is None:
            continue
        label = (row['recipient_username'] or '').strip() or UNASSIGNED_LABEL
        helper_day_map.setdefault(label, {})[row['day']] = row['n']

    helper_totals = sorted(
        ((label, sum(by_day.values())) for label, by_day in helper_day_map.items()),
        key=lambda r: (-r[1], r[0].lower()),
    )
    logs_per_helper_series = {
        'days': day_axis_iso,
        'series': [
            {'username': label, 'data': [helper_day_map[label].get(d, 0) for d in day_axis]}
            for label, _ in helper_totals
        ],
    }

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

    context = {
        'start_date': start_date.isoformat(),
        'end_date': end_date.isoformat(),
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
    }
    return render(request, 'statistics.html', context)
