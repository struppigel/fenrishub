"""
Parameter parsing for the token API (/api/v1/).

Read endpoints take their parameters from the query string, and those whose
input does not fit a URL (log lines, long regexes) also from a POST's JSON
object. Both arrive here as a mapping with `.get`: a QueryDict holds strings,
a JSON object may hold numbers, booleans and lists, and every helper accepts
either spelling. A malformed value raises ParamError, which views turn into a
400 naming the parameter.
"""

import re
from datetime import datetime, time, timedelta

from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime


class ParamError(ValueError):
    """A request parameter has the wrong type or format; the message names it."""


def text_param(params, name, *, max_chars=None):
    """The parameter as a stripped string ('' when absent)."""
    value = params.get(name)
    if value is None:
        return ''
    if isinstance(value, bool):
        raise ParamError(f'{name} must be a string.')
    if isinstance(value, (int, float)):
        value = str(value)
    if not isinstance(value, str):
        raise ParamError(f'{name} must be a string.')
    value = value.strip()
    if max_chars is not None and len(value) > max_chars:
        raise ParamError(f'{name} must be at most {max_chars} characters.')
    return value


def int_param(params, name, default, minimum, maximum):
    """The parameter as an int clamped to [minimum, maximum]; `default` when absent."""
    value = params.get(name)
    if value is None or value == '':
        return default
    if isinstance(value, bool):
        raise ParamError(f'{name} must be an integer.')
    if not isinstance(value, int):
        try:
            value = int(str(value).strip())
        except ValueError:
            raise ParamError(f'{name} must be an integer.') from None
    return max(minimum, min(maximum, value))


def optional_int_param(params, name):
    """The parameter as an int, or None when absent."""
    value = params.get(name)
    if value is None or value == '':
        return None
    return int_param(params, name, None, -(2 ** 31), 2 ** 31 - 1)


_TRUE = {'1', 'true', 'yes', 'on'}
_FALSE = {'0', 'false', 'no', 'off', ''}


def flag_param(params, name, default=False):
    """The parameter as a boolean: true/false, 1/0, yes/no or on/off."""
    value = params.get(name)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False if text else default
    raise ParamError(f'{name} must be true or false.')


def list_param(params, name, *, max_items=None):
    """The parameter as a list of stripped strings.

    A JSON list is taken item by item; a string is split at commas (none of
    the values listed this way - log types, status letters, field names, tag
    names - can hold one).
    """
    value = params.get(name)
    if value is None:
        return []
    if isinstance(value, list):
        items = []
        for item in value:
            if isinstance(item, bool) or not isinstance(item, (str, int)):
                raise ParamError(f'{name} must be a list of strings.')
            items.append(str(item))
    elif isinstance(value, (str, int)) and not isinstance(value, bool):
        items = str(value).split(',')
    else:
        raise ParamError(f'{name} must be a comma-separated string or a list.')
    items = [item.strip() for item in items if item.strip()]
    if max_items is not None and len(items) > max_items:
        raise ParamError(f'{name} takes at most {max_items} items.')
    return items


_DATE_ONLY_RE = re.compile(r'\d{4}-\d{2}-\d{2}')


def datetime_param(params, name):
    """``(moment, date_only)`` for an ISO date or date-time parameter, or ``(None, False)``.

    A value without a time zone is taken in the project's time zone, like the
    timestamps shown on the site.
    """
    raw = text_param(params, name, max_chars=40)
    if not raw:
        return None, False
    # A plain date first: parse_datetime also takes one (via fromisoformat) and
    # would make it midnight, losing that the caller meant the whole day.
    date_only = bool(_DATE_ONLY_RE.fullmatch(raw))
    try:
        if date_only:
            day = parse_date(raw)
            moment = datetime.combine(day, time.min) if day is not None else None
        else:
            moment = parse_datetime(raw)
    except ValueError:
        moment = None
    if moment is None:
        raise ParamError(f'{name} must be an ISO date (2026-11-05) or date-time (2026-11-05T14:30).')
    if timezone.is_naive(moment):
        moment = timezone.make_aware(moment, timezone.get_current_timezone())
    return moment, date_only


SCOPE_PARAM_NOTE = (
    'type and exclude_type take comma-separated log types; created_after and created_before '
    'take an ISO date or date-time and are both inclusive (a date covers that whole day).'
)


def apply_upload_scope(uploads, params, *, default_types=(), default_exclude=()):
    """Narrow an UploadedLog queryset by the scope parameters every search shares.

    `type` and `exclude_type` are comma-separated log types (exact names);
    `created_after` / `created_before` are inclusive, a date-only value
    covering that whole day. Defaults apply when a parameter is absent, not
    when it is given empty, so a caller can switch a default exclusion off.
    """
    log_types = list_param(params, 'type', max_items=20)
    if not log_types and params.get('type') is None:
        log_types = list(default_types)
    if log_types:
        uploads = uploads.filter(log_type__in=log_types)
    excluded = list_param(params, 'exclude_type', max_items=20)
    if not excluded and params.get('exclude_type') is None:
        excluded = list(default_exclude)
    if excluded:
        uploads = uploads.exclude(log_type__in=excluded)

    after, _after_date_only = datetime_param(params, 'created_after')
    if after is not None:
        uploads = uploads.filter(created_at__gte=after)
    before, before_date_only = datetime_param(params, 'created_before')
    if before is not None:
        if before_date_only:
            uploads = uploads.filter(created_at__lt=before + timedelta(days=1))
        else:
            uploads = uploads.filter(created_at__lte=before)
    return uploads


def scope_cache_part(params, *, default_types=(), default_exclude=()):
    """A stable string of the scope parameters, for cache keys of searches over that scope."""
    parts = []
    for name, default in (('type', default_types), ('exclude_type', default_exclude)):
        items = list_param(params, name, max_items=20)
        if not items and params.get(name) is None:
            items = list(default)
        parts.append(','.join(sorted(items)))
    for name in ('created_after', 'created_before'):
        moment, date_only = datetime_param(params, name)
        parts.append(f'{moment.isoformat() if moment else ""}{"d" if date_only else ""}')
    return '|'.join(parts)
