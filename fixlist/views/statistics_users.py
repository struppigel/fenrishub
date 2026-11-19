"""The users tab of the statistics page: the logs tab's stats per forum user.

A forum user is the person who posted the log (UploadedLogStat.forum_username,
keyed by models.stat_username). Snapshots of logs that were gone before the
field existed have no user ('') and are left out; the page says how many.
Every count is of distinct users: once per bucket in a chart, once in the
range in a table or card.
"""

from datetime import timedelta
from statistics import median

from django.db.models import Count, Max, Min, Q, Sum
from django.utils import timezone

from ..models import FixlistStat, UploadedLogStat
from .statistics import (
    TOP_N, TRUNC_BY_GRANULARITY, _analyzed, _as_local_date, _bucket_label, _bucket_recipient, _bucket_start,
    _helper_series, _percent, _stat_querysets, _tag_context, _tag_params, _tag_stats,
)

# Logs per user, as bar chart groups: (label, smallest, largest or None).
LOGS_PER_USER_GROUPS = (('1', 1, 1), ('2', 2, 2), ('3-5', 3, 5), ('6-10', 6, 10), ('11+', 11, None))
# A helper's case with a user stays open between two of the user's logs at most this many days apart.
CASE_GAP_DAYS = 14


def _users_by_bucket(users_qs, granularity, tz):
    """``{bucket_date: set(users)}`` of the users who uploaded a log in each bucket.

    Gathered as sets, not summed counts: buckets that land on the same local
    date must not count a user twice."""
    trunc = TRUNC_BY_GRANULARITY[granularity]
    rows = users_qs.annotate(bucket=trunc('created_at', tzinfo=tz)).values_list('bucket', 'forum_username').distinct()
    result = {}
    for bucket, user in rows:
        if bucket is not None:
            result.setdefault(_as_local_date(bucket, tz), set()).add(user)
    return result


def _open_cases(start_dt, end_dt, granularity, tz):
    """``{helper label: {bucket_date: set(users)}}``: the users each helper has an open case with.

    A case runs from one of the user's logs assigned to the helper to the next,
    as long as no more than CASE_GAP_DAYS pass between them; a longer gap ends
    it, so a user back months later doesn't count as open in between. Logs up
    to CASE_GAP_DAYS around the range are read too: they keep a case open into
    its first days or across its last ones. Sets, so a user counts once per
    bucket, also when blank helper names all become "Unassigned".
    """
    start_date = timezone.localtime(start_dt, tz).date()
    end_date = timezone.localtime(end_dt, tz).date()
    gap = timedelta(days=CASE_GAP_DAYS)
    rows = (
        UploadedLogStat.objects.exclude(forum_username='')
        .filter(created_at__range=(start_dt - gap, end_dt + gap))
        .values_list('created_at', 'forum_username', 'recipient_username')
    )
    days_by_case = {}
    for created_at, user, recipient in rows.iterator(chunk_size=2000):
        label = _bucket_recipient({'recipient_username': recipient})
        days_by_case.setdefault((label, user), set()).add(timezone.localtime(created_at, tz).date())

    result = {}
    for (label, user), days in days_by_case.items():
        days = sorted(days)
        stretches = [[days[0], days[0]]]
        for day in days[1:]:
            if day - stretches[-1][1] <= gap:
                stretches[-1][1] = day
            else:
                stretches.append([day, day])
        by_bucket = None
        for first, last in stretches:
            day, last = max(first, start_date), min(last, end_date)
            while day <= last:
                if by_bucket is None:
                    by_bucket = result.setdefault(label, {})
                by_bucket.setdefault(_bucket_start(day, granularity), set()).add(user)
                day += timedelta(days=1)
    return result


def _per_user(users_qs):
    """``{user: {logs, malware, pup, warning, fixlogs, first, last}}`` for the users in `users_qs`."""
    rows = users_qs.values('forum_username').annotate(
        logs=Count('id'),
        malware=Sum('count_malware'),
        pup=Sum('count_pup'),
        warning=Sum('count_warning'),
        fixlogs=Count('id', filter=Q(log_type='Fixlog')),
        first=Min('created_at'),
        last=Max('created_at'),
    )
    return {row.pop('forum_username'): row for row in rows}


def _new_users(start_dt, end_dt):
    """``{user: first log time}`` for the users whose first recorded log falls in the range."""
    rows = (
        UploadedLogStat.objects.exclude(forum_username='')
        .values('forum_username')
        .annotate(first=Min('created_at'))
        .filter(first__range=(start_dt, end_dt))
    )
    return {row['forum_username']: row['first'] for row in rows}


def _users_series(users_qs, new_users, axis, granularity, tz):
    """Chart data: users who uploaded, and new users, per bucket."""
    active = {bucket: len(users) for bucket, users in _users_by_bucket(users_qs, granularity, tz).items()}
    new = {}
    for first in new_users.values():
        bucket = _bucket_start(timezone.localtime(first, tz).date(), granularity)
        new[bucket] = new.get(bucket, 0) + 1
    return {
        'days': [_bucket_label(bucket, granularity) for bucket in axis],
        'series': [
            {'label': 'users', 'data': [active.get(bucket, 0) for bucket in axis]},
            {'label': 'new users', 'data': [new.get(bucket, 0) for bucket in axis]},
        ],
    }


def _logs_per_user(per_user):
    """Logs per user: the group sizes for the bar chart, the mean and median, and the
    median days from a user's first to last log in the range (users with 2+ logs)."""
    counts = [row['logs'] for row in per_user.values()]
    groups = [
        {'label': label, 'count': sum(1 for n in counts if n >= low and (high is None or n <= high))}
        for label, low, high in LOGS_PER_USER_GROUPS
    ]
    spans = [(row['last'] - row['first']).days for row in per_user.values() if row['logs'] > 1]
    return {
        'groups': groups,
        'mean': round(sum(counts) / len(counts), 1) if counts else 0.0,
        'median': median(counts) if counts else 0,
        'returning': len(spans),
        'median_span_days': median(spans) if spans else 0,
    }


def _users_per_helper(start_dt, end_dt, axis, granularity, tz):
    """Open cases per helper (see _open_cases): the table (users with a case open
    on any day of the range) and the chart."""
    by_label = _open_cases(start_dt, end_dt, granularity, tz)
    rows = sorted(
        (
            {'username': label, 'count': len(set().union(*by_bucket.values()))}
            for label, by_bucket in by_label.items()
        ),
        key=lambda r: (-r['count'], r['username'].lower()),
    )
    counts = {
        label: {bucket: len(users) for bucket, users in by_bucket.items()}
        for label, by_bucket in by_label.items()
    }
    return rows, _helper_series(counts, axis, granularity)


def users_stats_context(request, log_range, axis, granularity, tz):
    """The users tab: forum users, their tags, how many logs they post, and who helps them."""
    start_dt, end_dt = log_range
    log_qs, fixlist_qs = _stat_querysets(log_range)
    users_qs = log_qs.exclude(forum_username='')
    unknown_logs = log_qs.filter(forum_username='').count()

    per_user = _per_user(users_qs)
    user_count = len(per_user)
    new_users = _new_users(start_dt, end_dt)
    fixlists_by_user = dict(
        fixlist_qs.exclude(username='').values('username').annotate(n=Count('id')).values_list('username', 'n')
    )

    with_fixlog = sum(1 for row in per_user.values() if row['fixlogs'])
    # A fixlist written after the range's end still answers a log in it.
    # Intersected here: an IN (subquery) over the snapshots is slow on Postgres.
    fixlist_users = set(
        FixlistStat.objects.filter(created_at__gte=start_dt).exclude(username='')
        .values_list('username', flat=True).distinct()
    )
    with_fixlist = len(fixlist_users & set(per_user))
    headline = {
        'users': user_count,
        'malware_users': sum(1 for row in per_user.values() if row['malware']),
        'pup_users': sum(1 for row in per_user.values() if row['pup']),
        'warning_users': sum(1 for row in per_user.values() if row['warning']),
        'new_users': len(new_users),
    }
    cleanup = {
        'with_fixlist': with_fixlist,
        'with_fixlist_pct': _percent(with_fixlist, user_count),
        'with_fixlog': with_fixlog,
        'with_fixlog_pct': _percent(with_fixlog, user_count),
    }

    top_users = [
        {
            'username': user,
            'logs': row['logs'],
            'fixlists': fixlists_by_user.get(user, 0),
            'first': timezone.localtime(row['first'], tz).date().isoformat(),
            'last': timezone.localtime(row['last'], tz).date().isoformat(),
        }
        for user, row in sorted(per_user.items(), key=lambda item: (-item[1]['logs'], item[0]))[:TOP_N]
    ]

    users_per_helper, users_per_helper_series = _users_per_helper(start_dt, end_dt, axis, granularity, tz)

    tag_categories, selected_tag_category, picked_tag_ids = _tag_params(request)
    tag_stats = _tag_stats(_analyzed(users_qs), axis, granularity, tz, selected_tag_category, picked_tag_ids,
                           unit_field='forum_username')

    return {
        **_tag_context(tag_stats, tag_categories, selected_tag_category, picked_tag_ids),
        'users_headline': headline,
        'unknown_user_logs': unknown_logs,
        'users_series': _users_series(users_qs, new_users, axis, granularity, tz),
        'logs_per_user': _logs_per_user(per_user),
        'users_cleanup': cleanup,
        'top_users': top_users,
        'users_per_helper': users_per_helper,
        'users_per_helper_series': users_per_helper_series,
        'case_gap_days': CASE_GAP_DAYS,
    }
