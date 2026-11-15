"""centralbox.dev hash lookups: the only code in FenrisHub that talks to centralbox.

Everything here is built so FenrisHub works exactly as before when centralbox
is slow, broken, rate limited, returns garbage or no longer exists:

- Off unless CENTRALBOX_API_KEY is set and SiteConfig.centralbox_enabled is on.
- No page render calls this module's network code: pages read stored
  HashVerdict rows only. Lookups run in background threads or in small async
  endpoints with a hard deadline.
- Every request has a timeout and a response size cap; answers are validated
  field by field and nothing half-valid is stored.
- Failures pause all lookups (SiteConfig.centralbox_paused_until, shared by
  every worker): 3 failures in a row pause 10 minutes, a rejected key 6 hours,
  a 429 for its Retry-After. Calls per minute are capped across workers by
  CentralboxUsageMinute.
- Under the test runner no request is ever sent (Railway runs the suite
  before every deploy); tests mock `_http_get` or opt in with mocked urlopen.
- Public functions never raise: they log and return what they have.

Only the SHA256 itself is sent - no path, user name or upload id.
"""

import hashlib
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, connections, transaction
from django.db.models import F
from django.utils import timezone

from .file_hashes import is_md5, is_sha256
from .models import (
    CentralboxFreshLookup, CentralboxUsageMinute, HashAlias, HashVerdict, SiteConfig, UploadedLog,
    UploadedLogFileHash,
)

logger = logging.getLogger('fixlist.centralbox')

BASE_URL = 'https://centralbox.dev/api/v1'
MAX_RESPONSE_BYTES = 256 * 1024
FAILURES_BEFORE_PAUSE = 3
PAUSE_ON_FAILURE = timedelta(minutes=10)
PAUSE_ON_AUTH_ERROR = timedelta(hours=6)
RATE_PAUSE_MIN_SECONDS = 60
RATE_PAUSE_MAX_SECONDS = 3600
MAX_LINKS = 6

_LABEL_RE = re.compile(r'^[\w .+&-]{1,64}$')
_SOURCE_RE = re.compile(r'^[\w .()&+-]{1,40}$')
_PROVIDER_STATUSES = ('malicious', 'suspicious', 'clean', 'not_found', 'error', 'info', 'unsupported')
_FLAGGED = (HashVerdict.VERDICT_MALICIOUS, HashVerdict.VERDICT_SUSPICIOUS)

# Failures in a row in this process; any success resets it.
_failure_lock = threading.Lock()
_consecutive_failures = 0


class _Failure(Exception):
    """A failed or unusable centralbox answer. `kind`: network, server, auth, rate, bad."""

    def __init__(self, kind, detail='', retry_after=None):
        super().__init__(f'{kind}: {detail}')
        self.kind = kind
        self.detail = detail
        self.retry_after = retry_after


def _setting(name, default):
    return getattr(settings, name, default)


def api_key():
    return (getattr(settings, 'CENTRALBOX_API_KEY', '') or '').strip()


def is_available():
    """True when a lookup may be sent right now. Never raises."""
    try:
        if not api_key():
            return False
        config = SiteConfig.get_solo()
        if not config.centralbox_enabled:
            return False
        paused_until = config.centralbox_paused_until
        return not (paused_until and paused_until > timezone.now())
    except Exception:
        logger.exception('centralbox availability check failed')
        return False


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _request(method, path, key, body=None):
    """Send one request to BASE_URL + path with `key` and return the decoded JSON object.

    Returns None for 404 (not in the corpus); raises _Failure for anything else
    that is not a well-formed JSON object."""
    if getattr(settings, 'TESTING', False) and not getattr(settings, 'CENTRALBOX_ALLOW_HTTP_IN_TESTS', False):
        raise _Failure('network', 'requests are disabled under the test runner')
    headers = {
        'Authorization': f'Bearer {key}',
        'Accept': 'application/json',
        'User-Agent': 'FenrisHub',
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
    timeout = float(_setting('CENTRALBOX_TIMEOUT', 4))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code in (401, 403):
            raise _Failure('auth', f'HTTP {exc.code}')
        if exc.code == 429:
            retry_after = exc.headers.get('Retry-After') if exc.headers is not None else None
            raise _Failure('rate', 'HTTP 429', retry_after=retry_after)
        raise _Failure('server', f'HTTP {exc.code}')
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise _Failure('network', repr(exc)[:160])
    if len(raw) > MAX_RESPONSE_BYTES:
        raise _Failure('bad', 'response too large')
    try:
        decoded = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise _Failure('bad', 'response is not JSON')
    if not isinstance(decoded, dict):
        raise _Failure('bad', 'response is not a JSON object')
    return decoded


def _http_get(path):
    """GET with the server key (CENTRALBOX_API_KEY): cached reads only."""
    return _request('GET', path, api_key())


# ---------------------------------------------------------------------------
# Budget and pause, shared across worker processes
# ---------------------------------------------------------------------------

# Budget buckets in CentralboxUsageMinute.key_id: the server key's reads, and
# its fresh lookups (centralbox limits those separately).
BUDGET_READS = ''
BUDGET_FRESH = 'fresh'


def take_budget(key_id=BUDGET_READS, limit=None):
    """Count one call against this minute's limit of a bucket; False when it is used up."""
    if limit is None:
        limit = int(_setting('CENTRALBOX_CALLS_PER_MINUTE', 60))
    limit = max(1, int(limit))
    minute = int(time.time()) // 60
    try:
        CentralboxUsageMinute.objects.get_or_create(minute=minute, key_id=key_id)
    except IntegrityError:
        pass  # another worker created it first
    updated = CentralboxUsageMinute.objects.filter(
        minute=minute, key_id=key_id, calls__lt=limit,
    ).update(calls=F('calls') + 1)
    return updated == 1


def _pause(until, reason):
    SiteConfig.get_solo()
    SiteConfig.objects.filter(pk=1).update(centralbox_paused_until=until, centralbox_pause_reason=reason[:200])


def _record_success():
    global _consecutive_failures
    with _failure_lock:
        _consecutive_failures = 0


def _retry_after_seconds(value):
    try:
        seconds = int(str(value).strip())
    except (TypeError, ValueError):
        seconds = RATE_PAUSE_MIN_SECONDS
    return min(RATE_PAUSE_MAX_SECONDS, max(RATE_PAUSE_MIN_SECONDS, seconds))


_last_failure = threading.local()


def _record_failure(failure, key_id=BUDGET_READS):
    """Count a failure (in the bucket of the call) and pause lookups when
    needed. Returns True when paused."""
    global _consecutive_failures
    _last_failure.kind = failure.kind
    try:
        CentralboxUsageMinute.objects.filter(
            minute=int(time.time()) // 60, key_id=key_id,
        ).update(failures=F('failures') + 1)
    except Exception:
        pass
    now = timezone.now()
    if failure.kind == 'auth':
        _pause(now + PAUSE_ON_AUTH_ERROR, f'centralbox rejected the API key ({failure.detail})')
        logger.error('centralbox rejected the API key (%s); lookups paused for 6 hours', failure.detail)
        return True
    if failure.kind == 'rate':
        seconds = _retry_after_seconds(failure.retry_after)
        _pause(now + timedelta(seconds=seconds), f'centralbox rate limit (HTTP 429), retry after {seconds}s')
        logger.warning('centralbox rate limited us; lookups paused for %ss', seconds)
        return True
    with _failure_lock:
        _consecutive_failures += 1
        should_pause = _consecutive_failures >= FAILURES_BEFORE_PAUSE
        if should_pause:
            _consecutive_failures = 0
    if should_pause:
        _pause(now + PAUSE_ON_FAILURE, f'centralbox failing ({failure.kind}: {failure.detail})'[:200])
        logger.warning('centralbox failed %s times in a row (%s: %s); lookups paused for 10 minutes',
                       FAILURES_BEFORE_PAUSE, failure.kind, failure.detail)
        return True
    logger.info('centralbox lookup failed (%s: %s)', failure.kind, failure.detail)
    return False


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _label(value):
    if isinstance(value, str):
        value = value.strip()
        if _LABEL_RE.match(value):
            return value
    return ''


def _score(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 0 <= value <= 100:
        return value
    if isinstance(value, float) and value.is_integer() and 0 <= value <= 100:
        return int(value)
    return None


def _parse_status(data, sha):
    """The usable part of /status/<sha>, or None while centralbox is still working on it."""
    if data.get('ok') is not True:
        raise _Failure('bad', 'status answer is not ok')
    analysed = data.get('analysed')
    if analysed is False:
        return {'state': HashVerdict.STATE_UNKNOWN}
    if analysed is not True:
        raise _Failure('bad', 'status answer has no analysed flag')
    if str(data.get('sha256') or '').lower() != sha:
        raise _Failure('bad', 'status answer is for another hash')
    verdict = data.get('verdict')
    if verdict not in HashVerdict.VERDICTS:
        if data.get('in_progress') is True:
            return None
        raise _Failure('bad', 'status answer has no valid verdict')
    return {
        'state': HashVerdict.STATE_KNOWN,
        'verdict': verdict,
        'family': _label(data.get('family')),
        'score': _score(data.get('score')),
    }


def _parse_verdict_details(data, sha):
    """malware_type, threat_score, provider counts and report links from /lookup/<sha>/verdict."""
    if data.get('ok') is not True or str(data.get('hash') or '').lower() != sha:
        raise _Failure('bad', 'verdict answer is not for this hash')
    counts = {}
    raw_counts = data.get('counts')
    if isinstance(raw_counts, dict):
        for key in _PROVIDER_STATUSES:
            value = raw_counts.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1000:
                counts[key] = value
    links = []
    providers = data.get('providers')
    if isinstance(providers, list):
        for entry in providers:
            if not isinstance(entry, dict):
                continue
            source = entry.get('source')
            status = entry.get('status')
            url = entry.get('link')
            if not (isinstance(source, str) and _SOURCE_RE.match(source.strip())):
                continue
            if status not in _FLAGGED:
                continue
            if not (isinstance(url, str) and url.startswith('https://') and len(url) <= 300
                    and not any(c.isspace() for c in url)):
                continue
            links.append({'source': source.strip(), 'status': status, 'url': url})
            if len(links) >= MAX_LINKS:
                break
    return {
        'malware_type': _label(data.get('malware_type'))[:32],
        'threat_score': _score(data.get('threat_score')),
        'provider_counts': counts,
        'links': links,
    }


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------

def _store(sha, fields):
    now = timezone.now()
    if fields['state'] == HashVerdict.STATE_KNOWN:
        ttl = timedelta(days=float(_setting('CENTRALBOX_KNOWN_TTL_DAYS', 7)))
    else:
        ttl = timedelta(hours=float(_setting('CENTRALBOX_UNKNOWN_TTL_HOURS', 24)))
    defaults = {
        'state': fields['state'],
        'verdict': fields.get('verdict', ''),
        'family': fields.get('family', ''),
        'malware_type': fields.get('malware_type', ''),
        'score': fields.get('score'),
        'threat_score': fields.get('threat_score'),
        'provider_counts': fields.get('provider_counts', {}),
        'links': fields.get('links', []),
        'checked_at': now,
        'next_check_at': now + ttl,
    }
    verdict, _ = HashVerdict.objects.update_or_create(sha256=sha, defaults=defaults)
    return verdict


def _lookup_one(sha):
    """(HashVerdict or None, calls used, stop) for one hash; `stop` ends the
    run (budget used up, or centralbox failing)."""
    if not take_budget():
        return None, 0, True
    calls = 1
    try:
        data = _http_get(f'/status/{sha}')
        if data is None:
            raise _Failure('bad', '/status answered 404')
        fields = _parse_status(data, sha)
    except _Failure as failure:
        _record_failure(failure)
        return None, calls, True
    if fields is None:
        _record_success()
        return None, calls, False
    paused = False
    if fields.get('verdict') in _FLAGGED and take_budget():
        calls += 1
        try:
            details = _http_get(f'/lookup/{sha}/verdict')
            if details is not None:
                fields.update(_parse_verdict_details(details, sha))
        except _Failure as failure:
            # The verdict itself is valid; store it without the extras.
            paused = _record_failure(failure)
    if not paused:
        _record_success()
    return _store(sha, fields), calls, paused


MANUAL_RECHECK_COOLDOWN_SECONDS = 30


def _manual_recheck_allowed(sha):
    """At most one forced re-check per hash per cooldown, so repeated clicks
    cannot burn the shared budget."""
    from django.core.cache import cache

    return cache.add(f'centralbox-recheck:{sha}', 1, timeout=MANUAL_RECHECK_COOLDOWN_SECONDS)


def check_hashes(sha256s, max_calls=25, deadline_seconds=8.0, force=False):
    """Look up the given hashes that have no fresh stored verdict.

    `force` (an analyst's explicit "check again") also re-asks centralbox for
    hashes with a fresh stored answer, at most once per hash every
    MANUAL_RECHECK_COOLDOWN_SECONDS.

    Returns {'available': bool, 'verdicts': {sha: dict}, 'pending': int}:
    every given hash with a stored verdict (fresh or stale, so pages keep
    showing old answers while centralbox is down), and how many still have
    none and may be retried later. Never raises."""
    result = {'available': False, 'verdicts': {}, 'pending': 0}
    try:
        wanted = []
        seen = set()
        for value in sha256s or []:
            sha = (value or '').strip().lower()
            if is_sha256(sha) and sha not in seen:
                seen.add(sha)
                wanted.append(sha)
        stored = {row.sha256: row for row in HashVerdict.objects.filter(sha256__in=wanted)} if wanted else {}
        available = is_available()
        result['available'] = available
        if available and wanted:
            now = timezone.now()
            todo = [
                sha for sha in wanted
                if sha not in stored or stored[sha].next_check_at <= now
                or (force and _manual_recheck_allowed(sha))
            ]
            deadline = time.monotonic() + max(0.0, float(deadline_seconds))
            calls = 0
            for sha in todo:
                if calls >= max_calls or time.monotonic() >= deadline:
                    break
                verdict, used, stop = _lookup_one(sha)
                calls += used
                if verdict is not None:
                    stored[sha] = verdict
                if stop:
                    break
        result['verdicts'] = {sha: stored[sha].as_dict() for sha in wanted if sha in stored}
        if available:
            result['pending'] = sum(1 for sha in wanted if sha not in stored)
    except Exception:
        logger.exception('centralbox hash check failed')
    return result


def stored_verdicts(sha256s):
    """{sha: dict} of the stored verdicts for these hashes. DB only, never raises."""
    try:
        wanted = {(s or '').lower() for s in sha256s or [] if is_sha256(s)}
        if not wanted:
            return {}
        return {row.sha256: row.as_dict() for row in HashVerdict.objects.filter(sha256__in=wanted)}
    except Exception:
        logger.exception('Reading stored centralbox verdicts failed')
        return {}


def auto_check_limit():
    """Logs with more automatic hashes than this are not checked by themselves;
    their hashes are only checked one by one from the hash menu."""
    return max(0, int(_setting('CENTRALBOX_MAX_AUTO_HASHES_PER_LOG', 50)))


def auto_hashes_of(upload_ids):
    """The automatic hashes of these logs, leaving out logs with too many (auto_check_limit)."""
    by_upload = {}
    for upload_id, sha in (
        UploadedLogFileHash.objects.filter(upload_id__in=upload_ids, auto=True)
        .values_list('upload_id', 'sha256').distinct()
    ):
        by_upload.setdefault(upload_id, set()).add(sha)
    limit = auto_check_limit()
    wanted = set()
    for shas in by_upload.values():
        if len(shas) <= limit:
            wanted |= shas
    return sorted(wanted)


def check_upload_hashes(upload, max_calls=60, deadline_seconds=120.0):
    """Look up an upload's auto hashes (used by the after-upload thread)."""
    try:
        return check_hashes(auto_hashes_of([upload.pk]), max_calls=max_calls, deadline_seconds=deadline_seconds)
    except Exception:
        logger.exception('centralbox check failed for upload_id=%s', getattr(upload, 'upload_id', '?'))
        return {'available': False, 'verdicts': {}, 'pending': 0}


def _check_uploads_in_thread(upload_pks):
    try:
        for pk in upload_pks:
            upload = UploadedLog.objects.filter(pk=pk).first()
            if upload is None:
                continue
            result = check_upload_hashes(upload)
            if not result.get('available'):
                break
    except Exception:
        logger.exception('Background centralbox check failed')
    finally:
        connections.close_all()


def schedule_uploads_check(upload_pks):
    """Look up these uploads' auto hashes in a background thread; returns at
    once. Never runs under tests, when unavailable, or twice for the same
    uploads within 5 minutes."""
    try:
        from django.core.cache import cache

        pks = sorted({int(pk) for pk in upload_pks or []})
        if not pks or getattr(settings, 'TESTING', False) or not is_available():
            return False
        # A digest, not a truncated list: two long sets with the same first
        # pks must not share a key (cache keys are length-limited).
        digest = hashlib.sha1(','.join(map(str, pks)).encode('ascii')).hexdigest()
        if not cache.add(f'centralbox-check:{digest}', 1, timeout=300):
            return False
        threading.Thread(
            target=_check_uploads_in_thread, args=(pks,),
            name=f'centralbox-check-{pks[0]}', daemon=True,
        ).start()
        return True
    except Exception:
        logger.exception('Scheduling a centralbox check failed')
        return False


# ---------------------------------------------------------------------------
# MD5s (Trojan Killer logs carry nothing else). An MD5 stands for a SHA256:
# known locally when a Malwarebytes log or a Fixlog File: block listed both,
# or learned from centralbox (HashAlias). Its verdict is the SHA256's.
# ---------------------------------------------------------------------------

def resolve_md5s(md5s):
    """{md5: sha256} for the MD5s whose SHA256 is known. DB only, never raises."""
    try:
        wanted = {(m or '').strip().lower() for m in md5s or [] if is_md5(m)}
        if not wanted:
            return {}
        result = dict(
            UploadedLogFileHash.objects.filter(md5__in=wanted).exclude(sha256='')
            .values_list('md5', 'sha256').distinct()
        )
        for md5, sha in HashAlias.objects.filter(md5__in=wanted).exclude(sha256='').values_list('md5', 'sha256'):
            result.setdefault(md5, sha)
        return result
    except Exception:
        logger.exception('Resolving MD5s failed')
        return {}


def unknown_md5s(md5s):
    """{md5: checked date} for MD5s centralbox did not know when last asked."""
    try:
        wanted = {(m or '').strip().lower() for m in md5s or [] if is_md5(m)}
        rows = HashAlias.objects.filter(md5__in=wanted, sha256='').values_list('md5', 'checked_at') if wanted else []
        return {md5: checked.date().isoformat() for md5, checked in rows}
    except Exception:
        logger.exception('Reading MD5 answers failed')
        return {}


def _store_alias(md5, sha=''):
    now = timezone.now()
    if sha:
        ttl = timedelta(days=float(_setting('CENTRALBOX_KNOWN_TTL_DAYS', 7)))
    else:
        ttl = timedelta(hours=float(_setting('CENTRALBOX_UNKNOWN_TTL_HOURS', 24)))
    HashAlias.objects.update_or_create(md5=md5, defaults={'sha256': sha, 'checked_at': now, 'next_check_at': now + ttl})


def _lookup_md5(md5):
    """Ask centralbox about an MD5: (HashVerdict of its SHA256 or None,
    'known' / 'unknown' / '' (no answer), stop). Stores the alias and the
    verdict."""
    if not take_budget():
        return None, '', True
    try:
        data = _http_get(f'/status/{md5}')
        if data is None or data.get('ok') is not True:
            raise _Failure('bad', 'status answer is not ok')
        if data.get('analysed') is False:
            _store_alias(md5)
            _record_success()
            return None, 'unknown', False
        sha = str(data.get('sha256') or '').lower()
        if not is_sha256(sha):
            if data.get('in_progress') is True:
                return None, '', False
            raise _Failure('bad', 'status answer for an MD5 has no SHA256')
        fields = _parse_status(data, sha)
    except _Failure as failure:
        _record_failure(failure)
        return None, '', True
    _store_alias(md5, sha)
    if fields is None:
        _record_success()
        return None, '', False
    paused = False
    if fields.get('verdict') in _FLAGGED and take_budget():
        try:
            details = _http_get(f'/lookup/{sha}/verdict')
            if details is not None:
                fields.update(_parse_verdict_details(details, sha))
        except _Failure as failure:
            paused = _record_failure(failure)
    if not paused:
        _record_success()
    return _store(sha, fields), 'known', paused


def check_md5(md5, force=False):
    """A manual check of one MD5 (centralbox only answers for MD5s someone ran
    a fresh lookup on). Returns {available, verdict, sha256, unknown}. Never raises."""
    result = {'available': False, 'verdict': None, 'sha256': '', 'unknown': False}
    try:
        md5 = (md5 or '').strip().lower()
        if not is_md5(md5):
            return result
        sha = resolve_md5s([md5]).get(md5, '')
        if sha:
            checked = check_hashes([sha], max_calls=2, force=force)
            result.update(available=checked['available'], verdict=checked['verdicts'].get(sha), sha256=sha)
            return result
        available = is_available()
        result['available'] = available
        alias = HashAlias.objects.filter(md5=md5).first()
        fresh = alias is not None and alias.next_check_at > timezone.now()
        if available and (not fresh or (force and _manual_recheck_allowed(md5))):
            verdict, state, _ = _lookup_md5(md5)
            if verdict is not None:
                result.update(verdict=verdict.as_dict(), sha256=verdict.sha256)
                return result
            result['unknown'] = state == 'unknown'
            return result
        result['unknown'] = alias is not None and not alias.sha256
    except Exception:
        logger.exception('centralbox MD5 check failed')
    return result


# ---------------------------------------------------------------------------
# Fresh lookups: any helper asks centralbox to analyse a hash anew, with the
# server key (centralbox then queries VirusTotal, Triage, Kaspersky, ...). One
# per hash per cooldown, for everyone, and at most
# CENTRALBOX_FRESH_LOOKUPS_PER_MINUTE across Fenris; the result lands in HashVerdict.
# ---------------------------------------------------------------------------

FRESH_LOOKUP_TIMEOUT = timedelta(minutes=15)
FRESH_POLL_MIN_SECONDS = 3


def fresh_lookup_cooldown():
    return timedelta(hours=float(_setting('CENTRALBOX_FRESH_LOOKUP_COOLDOWN_HOURS', 24)))


def _fresh_info(row):
    return {
        'state': row.state,
        'requested_at': row.requested_at.isoformat() if row.requested_at else '',
        'requested_by': row.requested_by.username if row.requested_by_id else '',
        'next_at': (row.requested_at + fresh_lookup_cooldown()).isoformat() if row.requested_at else '',
    }


def fresh_lookup_info(sha256s):
    """{sha: {state, requested_at, requested_by, next_at}} for hashes with a
    fresh lookup inside the cooldown. DB only, never raises."""
    try:
        wanted = {(s or '').lower() for s in sha256s or [] if is_sha256(s) or is_md5(s)}
        if not wanted:
            return {}
        since = timezone.now() - fresh_lookup_cooldown()
        rows = CentralboxFreshLookup.objects.filter(sha256__in=wanted, requested_at__gt=since).select_related('requested_by')
        return {row.sha256: _fresh_info(row) for row in rows}
    except Exception:
        logger.exception('Reading centralbox fresh lookups failed')
        return {}


def _claim(sha, user):
    """Take the hash's cooldown slot. None when taken, else the claimed row."""
    now = timezone.now()
    try:
        with transaction.atomic():
            return CentralboxFreshLookup.objects.create(
                sha256=sha, requested_by=user, requested_at=now, state=CentralboxFreshLookup.STATE_RUNNING,
            )
    except IntegrityError:
        pass
    updated = CentralboxFreshLookup.objects.filter(
        sha256=sha, requested_at__lte=now - fresh_lookup_cooldown(),
    ).update(requested_by=user, requested_at=now, state=CentralboxFreshLookup.STATE_RUNNING, finished_at=None)
    return CentralboxFreshLookup.objects.get(sha256=sha) if updated else None


def _release(row):
    """Give the cooldown slot back after a start that never reached centralbox."""
    CentralboxFreshLookup.objects.filter(pk=row.pk, requested_at=row.requested_at).delete()


def _finish(row, state):
    CentralboxFreshLookup.objects.filter(pk=row.pk).update(state=state, finished_at=timezone.now())
    row.state = state
    return row


def _result(ok, state='', message='', verdict=None, info=None, status=200):
    return {'ok': ok, 'state': state, 'message': message, 'verdict': verdict, 'fresh': info, 'http_status': status}


def _complete(row, sha):
    """centralbox finished: read and store the answer."""
    if is_md5(sha):
        verdict, state, _ = _lookup_md5(sha)
        if verdict is not None:
            _finish(row, CentralboxFreshLookup.STATE_DONE)
        elif state == 'unknown':
            _finish(row, CentralboxFreshLookup.STATE_NOT_FOUND)
        return verdict
    verdict, _, _ = _lookup_one(sha)
    if verdict is not None and verdict.state == HashVerdict.STATE_KNOWN:
        _finish(row, CentralboxFreshLookup.STATE_DONE)
        return verdict
    if verdict is not None:
        _finish(row, CentralboxFreshLookup.STATE_NOT_FOUND)
        return verdict
    return None


def fresh_lookups_per_minute():
    return max(1, int(_setting('CENTRALBOX_FRESH_LOOKUPS_PER_MINUTE', 15)))


def start_fresh_lookup(sha, user):
    """Ask centralbox for a fresh analysis of `sha` (a SHA256, or an MD5) with
    the server key, for any logged-in helper.

    Returns a dict {ok, state, message, verdict, fresh, http_status}. Never raises."""
    try:
        sha = (sha or '').strip().lower()
        if not (is_sha256(sha) or is_md5(sha)):
            return _result(False, message='Not a SHA-256 or MD5 hash.', status=400)
        if not is_available():
            return _result(False, message='centralbox lookups are switched off or paused right now.', status=503)
        row = _claim(sha, user)
        if row is None:
            existing = CentralboxFreshLookup.objects.select_related('requested_by').get(sha256=sha)
            info = _fresh_info(existing)
            who = info['requested_by'] or 'someone'
            return _result(False, state=existing.state, info=info, status=429,
                           message=f'Already looked up by {who}; a new lookup is possible after {info["next_at"][:16].replace("T", " ")} UTC.')
        if not take_budget(BUDGET_FRESH, fresh_lookups_per_minute()):
            _release(row)
            return _result(False, message='Too many fresh lookups this minute; try again shortly.', status=429)
        known_sha = resolve_md5s([sha]).get(sha, '') if is_md5(sha) else sha
        known = bool(known_sha) and HashVerdict.objects.filter(sha256=known_sha, state=HashVerdict.STATE_KNOWN).exists()
        try:
            data = _request('POST', '/lookup', api_key(), {'hash': sha, 'force': known, 'notify': False})
            if data is None or data.get('ok') is not True:
                raise _Failure('bad', 'lookup answer is not ok')
        except _Failure as failure:
            _release(row)
            _record_failure(failure, BUDGET_FRESH)
            if failure.kind == 'auth':
                return _result(False, message='centralbox rejected the server key; lookups are paused.', status=503)
            if failure.kind == 'rate':
                seconds = _retry_after_seconds(failure.retry_after)
                return _result(False, message=f'centralbox is rate limiting; try again in {seconds} s.', status=429)
            return _result(False, message='centralbox could not be reached; try again later.', status=503)
        status = data.get('status')
        if status == 'not_found':
            verdict = _store_unknown(sha)
            _finish(row, CentralboxFreshLookup.STATE_NOT_FOUND)
            return _result(True, state=row.state, verdict=verdict, info=_fresh_info(row))
        if status == 'done':
            verdict = _complete(row, sha)
            if verdict is not None:
                return _result(True, state=row.state, verdict=verdict.as_dict(), info=_fresh_info(row))
        return _result(True, state=CentralboxFreshLookup.STATE_RUNNING, info=_fresh_info(row))
    except Exception:
        logger.exception('Starting a centralbox fresh lookup failed')
        return _result(False, message='The lookup could not be started.', status=500)


def _store_unknown(hash_value):
    """Record that no provider knows the hash; the dict to show, or None for an MD5."""
    if is_md5(hash_value):
        _store_alias(hash_value)
        return None
    return _store(hash_value, {'state': HashVerdict.STATE_UNKNOWN}).as_dict()


def _stored_for(hash_value):
    sha = resolve_md5s([hash_value]).get(hash_value, '') if is_md5(hash_value) else hash_value
    return HashVerdict.objects.filter(sha256=sha).first() if sha else None


def poll_fresh_lookup(sha):
    """Progress of a fresh lookup: {ok, state, verdict, fresh}. While it runs,
    asks centralbox at most every FRESH_POLL_MIN_SECONDS and stores the
    answer once centralbox is done. Never raises."""
    try:
        from django.core.cache import cache

        sha = (sha or '').strip().lower()
        valid = is_sha256(sha) or is_md5(sha)
        row = CentralboxFreshLookup.objects.select_related('requested_by').filter(sha256=sha).first() if valid else None
        if row is None:
            return _result(False, state='none', status=404)
        stored = _stored_for(sha)
        if row.state != CentralboxFreshLookup.STATE_RUNNING:
            return _result(True, state=row.state, verdict=stored.as_dict() if stored else None, info=_fresh_info(row))
        if row.requested_at < timezone.now() - FRESH_LOOKUP_TIMEOUT:
            _finish(row, CentralboxFreshLookup.STATE_ERROR)
            return _result(True, state=row.state, verdict=stored.as_dict() if stored else None, info=_fresh_info(row))
        running = _result(True, state=row.state, info=_fresh_info(row))
        if not cache.add(f'centralbox-fresh-poll:{sha}', 1, timeout=FRESH_POLL_MIN_SECONDS):
            return running
        if not is_available() or not take_budget():
            return running
        try:
            data = _http_get(f'/status/{sha}')
            if data is None or data.get('ok') is not True:
                raise _Failure('bad', 'status answer is not ok')
        except _Failure as failure:
            _record_failure(failure)
            return running
        lookup = data.get('lookup')
        if lookup == 'running' or (data.get('in_progress') is True and data.get('analysed') is not True):
            return running
        if lookup == 'error':
            _finish(row, CentralboxFreshLookup.STATE_ERROR)
            return _result(True, state=row.state, verdict=stored.as_dict() if stored else None, info=_fresh_info(row))
        if lookup == 'not_found' or data.get('analysed') is False:
            verdict = _store_unknown(sha)
            _finish(row, CentralboxFreshLookup.STATE_NOT_FOUND)
            return _result(True, state=row.state, verdict=verdict, info=_fresh_info(row))
        verdict = _complete(row, sha)
        if verdict is None:
            return running
        return _result(True, state=row.state, verdict=verdict.as_dict(), info=_fresh_info(row))
    except Exception:
        logger.exception('Polling a centralbox fresh lookup failed')
        return _result(False, state='error', status=500)
