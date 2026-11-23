"""Aggregate statistics across snapshotted upload and fixlist data."""

from datetime import date, datetime, time, timedelta
from urllib.parse import urlencode

from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count, ExpressionWrapper, F, FloatField, Min, Sum
from django.db.models.functions import TruncDate, TruncMonth, TruncWeek
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from ..log_types import ANALYZED_LOG_TYPES
from ..models import FixlistStat, RuleTag, TagCategory, UploadedLogStat
from ..tagging import centralbox_tags_by_sha, parse_tag_ids, selected_tags_for_picker, tag_ids_by_key


UNASSIGNED_LABEL = 'Unassigned'
DEFAULT_RANGE_DAYS = 30
TOP_N = 20
# Tags the tag timeline draws when none are picked: the most found ones.
TAG_CHART_TOP_N = 10
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


def _percent(part, whole):
    """`part` as a percentage of `whole`, one decimal; 0.0 for an empty whole."""
    return round(part / whole * 100, 1) if whole else 0.0


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


DEFAULT_TAG_CHART_CATEGORY = 'family'


def _parse_category_id(raw, categories):
    """The id of the category `raw` names among `categories`, or None for all / an invalid one.

    Without the parameter at all (a fresh visit) the chart starts on the
    "family" category when one exists; an empty value means all categories."""
    if raw is None:
        return next(
            (c['id'] for c in categories if c['name'].strip().lower() == DEFAULT_TAG_CHART_CATEGORY),
            None,
        )
    try:
        category_id = int(raw)
    except (TypeError, ValueError):
        return None
    return category_id if any(category['id'] == category_id for category in categories) else None


# Hashes per IN (...) list: stays below SQLite's variable limit.
SHA_LOOKUP_CHUNK = 500


def _centralbox_tags_by_sha(shas):
    """``{sha256: {tag_id}}`` for `shas` (see tagging.centralbox_tags_by_sha), in chunks."""
    if not shas:
        return {}
    tags = list(
        RuleTag.objects.filter(match_centralbox=True).exclude(match_pattern='')
        .only('pk', 'match_pattern', 'exclude_pattern')
    )
    if not tags:
        return {}
    shas = sorted(shas)
    result = {}
    for start in range(0, len(shas), SHA_LOOKUP_CHUNK):
        result.update(centralbox_tags_by_sha(shas[start:start + SHA_LOOKUP_CHUNK], tags=tags))
    return result


def _tag_stats(analyzed_qs, axis, granularity, tz, category_id, picked_ids, unit_field=None):
    """Logs per rule tag in the range: the table rows, the timeline and how many logs were counted.

    With `unit_field` (e.g. 'forum_username') it counts distinct values of
    that field instead of logs: once per bucket in the chart, once in the
    range in the table, and the % base is the distinct values with tag data.

    Tags come from the rules and warning codes each snapshot recorded, resolved
    now (see tagging.tag_ids_by_key), so a rule tagged later counts for past
    logs too, plus the line tags it recorded (refreshed while the log exists)
    and the centralbox tags of the hashes correlated with its lines (recorded
    when the correlations are computed, tags resolved now). Without a category the table leaves out priority-0 categories -
    tags in nearly every log - as the uploads list does; a picked category shows
    all of its tags. Picked tags replace the most found ones in the chart.
    """
    trunc = TRUNC_BY_GRANULARITY[granularity]
    fields = ['bucket', 'rule_ids', 'warning_codes', 'line_tag_ids', 'correlated_sha256s']
    rows = analyzed_qs.annotate(bucket=trunc('created_at', tzinfo=tz)).values_list(
        *fields, *([unit_field] if unit_field else []),
    )
    bucket_by_row = {}
    unit_by_row = {}
    rule_ids_by_row = {}
    codes_by_row = {}
    line_tag_ids_by_row = {}
    shas_by_row = {}
    unrecorded = 0
    for index, (bucket, rule_ids, codes, line_tag_ids, shas, *unit) in enumerate(rows.iterator(chunk_size=500)):
        if rule_ids is None:
            unrecorded += 1
            continue
        if bucket is None:
            continue
        bucket_by_row[index] = _as_local_date(bucket, tz)
        if unit_field:
            unit_by_row[index] = unit[0]
        rule_ids_by_row[index] = rule_ids
        codes_by_row[index] = codes or []
        line_tag_ids_by_row[index] = line_tag_ids or []
        if shas:
            shas_by_row[index] = shas

    tag_ids_by_row = tag_ids_by_key(rule_ids_by_row, codes_by_row, line_tag_ids_by_row)
    # Centralbox tags of the hashes correlated with the log's lines, as found now.
    tags_by_sha = _centralbox_tags_by_sha(set().union(*shas_by_row.values()) if shas_by_row else set())
    for index, shas in shas_by_row.items():
        for sha in shas:
            tag_ids_by_row[index].update(tags_by_sha.get(sha, ()))

    # counts: {tag: {bucket: n}}, totals: {tag: n}. Logs are counted; units are
    # gathered in sets so each counts once per bucket and once in the range.
    counts = {}
    totals = {}
    if unit_field:
        units_by_bucket = {}
        units_in_range = {}
        for index, tag_ids in tag_ids_by_row.items():
            bucket, unit = bucket_by_row[index], unit_by_row[index]
            for tag_id in tag_ids:
                units_by_bucket.setdefault(tag_id, {}).setdefault(bucket, set()).add(unit)
                units_in_range.setdefault(tag_id, set()).add(unit)
        counts = {
            tag_id: {bucket: len(units) for bucket, units in by_bucket.items()}
            for tag_id, by_bucket in units_by_bucket.items()
        }
        totals = {tag_id: len(units) for tag_id, units in units_in_range.items()}
        counted = len(set(unit_by_row.values()))
    else:
        for index, tag_ids in tag_ids_by_row.items():
            bucket = bucket_by_row[index]
            for tag_id in tag_ids:
                by_bucket = counts.setdefault(tag_id, {})
                by_bucket[bucket] = by_bucket.get(bucket, 0) + 1
                totals[tag_id] = totals.get(tag_id, 0) + 1
        counted = len(rule_ids_by_row)
    tags = RuleTag.objects.select_related('category').in_bulk(set(counts) | set(picked_ids))
    # A deleted line tag can linger in the snapshots of logs that are gone.
    counts = {tag_id: by_bucket for tag_id, by_bucket in counts.items() if tag_id in tags}

    def shown(tag):
        if category_id is not None:
            return tag.category_id == category_id
        return tag.category.priority > 0

    table = sorted(
        (
            {
                'id': tag_id,
                'name': tags[tag_id].name,
                'category_id': tags[tag_id].category_id,
                'count': totals[tag_id],
                'percent': _percent(totals[tag_id], counted),
            }
            for tag_id, by_bucket in counts.items()
            if tag_id in tags and shown(tags[tag_id])
        ),
        key=lambda row: (-row['count'], row['name'].lower()),
    )

    picked = [tag_id for tag_id in picked_ids if tag_id in tags]
    charted = picked or [row['id'] for row in table[:TAG_CHART_TOP_N]]
    series = {
        'days': [_bucket_label(bucket, granularity) for bucket in axis],
        'series': [
            {
                'label': tags[tag_id].name,
                'data': [counts.get(tag_id, {}).get(bucket, 0) for bucket in axis],
            }
            for tag_id in charted
        ],
    }
    return {
        'rows': table,
        'series': series,
        'counted': counted,
        'unrecorded': unrecorded,
    }


def _bucket_recipient(row):
    username = (row.get('recipient_username') or '').strip()
    return username or UNASSIGNED_LABEL


def _bucket_owner(row):
    return (row.get('owner_username') or '').strip() or UNASSIGNED_LABEL


TAB_LOGS = 'logs'
TAB_USERS = 'users'
TAB_CENTRALBOX = 'centralbox'
TAB_PERFORMANCE = 'performance'
TABS = (TAB_LOGS, TAB_USERS, TAB_CENTRALBOX, TAB_PERFORMANCE)
# Tabs without the tag chart: they carry its choices along unchanged.
TABS_WITHOUT_TAGS = (TAB_CENTRALBOX, TAB_PERFORMANCE)


def _stat_querysets(log_range):
    """The log and fixlist snapshots created in the range."""
    start_dt, end_dt = log_range
    return (
        UploadedLogStat.objects.filter(created_at__range=(start_dt, end_dt)),
        FixlistStat.objects.filter(created_at__range=(start_dt, end_dt)),
    )


def _analyzed(log_qs):
    """The snapshots of analyzed logs, the base of the tag and known/unknown stats."""
    return log_qs.filter(log_type__in=ANALYZED_LOG_TYPES, total_line_count__gt=0)


def _tag_params(request):
    """The tag chart's choices from the URL: (categories, selected category id or None, picked tag ids)."""
    tag_categories = list(TagCategory.objects.order_by('name').values('id', 'name'))
    selected = _parse_category_id(request.GET.get('tag_category'), tag_categories)
    return tag_categories, selected, parse_tag_ids(request.GET.getlist('tags'))


def _tag_context(tag_stats, tag_categories, selected_tag_category, picked_tag_ids):
    """The template context of the tag chart, table and controls."""
    return {
        'tag_stats': tag_stats['rows'],
        'tag_series': tag_stats['series'],
        'tag_counted_count': tag_stats['counted'],
        'tag_unrecorded_count': tag_stats['unrecorded'],
        'tag_categories': tag_categories,
        'tag_chart_top_n': TAG_CHART_TOP_N,
        'selected_tag_category': selected_tag_category,
        'selected_tags': selected_tags_for_picker(picked_tag_ids),
    }


@login_required
@require_http_methods(['GET'])
def statistics_view(request):
    start_date, end_date, start_dt, end_dt = _resolve_range(request)
    tab = request.GET.get('tab') if request.GET.get('tab') in TABS else TAB_LOGS
    tz = timezone.get_current_timezone()
    granularity = _granularity(start_date, end_date)
    axis = _bucket_axis(start_date, end_date, granularity)

    context = {
        'tab': tab,
        'start_date': start_date.isoformat(),
        'end_date': end_date.isoformat(),
        'granularity': granularity,
    }
    if tab in TABS_WITHOUT_TAGS:
        if tab == TAB_CENTRALBOX:
            from .statistics_centralbox import centralbox_stats

            context['cb'] = centralbox_stats(start_dt, end_dt, axis, granularity, tz)
        else:
            from .statistics_performance import performance_stats

            context['perf'] = performance_stats(start_dt, end_dt, axis, granularity, tz)
        # The logs tab's tag choices ride along, so switching back keeps them.
        raw_category = request.GET.get('tag_category')
        carry = [] if raw_category is None else [('tag_category', raw_category)]
        carry += [('tags', tag_id) for tag_id in parse_tag_ids(request.GET.getlist('tags'))]
    else:
        if tab == TAB_USERS:
            from .statistics_users import users_stats_context

            context.update(users_stats_context(request, log_range=(start_dt, end_dt), axis=axis,
                                               granularity=granularity, tz=tz))
        else:
            context.update(_log_stats_context(request, log_range=(start_dt, end_dt), axis=axis,
                                              granularity=granularity, tz=tz))
        carry = [('tag_category', '' if context['selected_tag_category'] is None else context['selected_tag_category'])]
        carry += [('tags', tag['id']) for tag in context['selected_tags']]
    context['carry_params'] = carry
    context['carry_query'] = urlencode(carry)
    return render(request, 'statistics.html', context)


def _log_stats_context(request, log_range, axis, granularity, tz):
    """The logs tab: uploads, fixlists, tags and helpers in the range."""
    log_qs, fixlist_qs = _stat_querysets(log_range)

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

    analyzed_qs = _analyzed(log_qs)
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

    tag_categories, selected_tag_category, picked_tag_ids = _tag_params(request)
    tag_stats = _tag_stats(analyzed_qs, axis, granularity, tz, selected_tag_category, picked_tag_ids)

    return {
        **_tag_context(tag_stats, tag_categories, selected_tag_category, picked_tag_ids),
        'headline': headline,
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
