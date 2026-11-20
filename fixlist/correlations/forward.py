"""What other logs of the same infection case say about the files of an FRST
log's lines (the forward correlations), cached per viewer scope.

For each FRST / Addition line whose file (or Run value, service, task,
installed program, ...: correlation_keys) also appears in another log of one
of the upload's cases, collect what that log says (entries.py, sources.py,
spor_source.py), plus what is related without being the line's own file
(related.py, timing.py). Database and local parsing only: nothing is ever
sent to centralbox. Paths are compared with the analyzer's own key
(normalize_path, lowercased).
"""

import hashlib
import json
import logging
import ntpath

from django.db import IntegrityError, transaction
from django.db.models import Count, Max, Q

from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
from ..correlation_keys import MATCH_HOST, MATCH_PATH, is_path_key, line_keys
from ..log_types import LOG_TYPE_FRST_AND_ADDITION
from ..machine_signals import SYSTEM_DIFFERENT
from ..models import (
    CorrelationCache, HashAlias, HashVerdict, UploadedLog, UploadedLogAnalysis, UploadedLogFileHash,
    UploadedLogMachineSignal, sync_stat_correlated_hashes,
)
from .collector import MAX_ENTRIES_PER_LINE, LineEntries, match_strength
from .defender import iter_addition_defender_detections
from .entries import INFO_MATCHES, MATCH_DETAIL, MATCH_NAMED_BY, MATCH_SUMMARY, correlation_status, summary_note
from .related import _RelatedIndex, _add_inside, _add_related
from .scope import SCOPE_CASE, SCOPE_USER, _system_verdicts, related_upload_ids
from .sources import (
    _addition_entries, _detection_entries, _fixlog_entries, _frst_search_entries, _hash_entries, _mau_entries,
    _shortcut_entries, merge_same_line,
)
from .spor_source import _spor_entries
from .timing import _add_timing, _created_line

logger = logging.getLogger(__name__)


# Part of every cache signature: bump it when what is computed changes.
CORRELATION_VERSION = 21


def _fresh_payload(uploaded_log):
    """A fresh cached analysis of the upload: the log's own rule set's first
    (its rule verdicts pick the timing anchors), else any other in key order
    (the line texts are the same for every rule set)."""
    try:
        from ..rule_sets import resolve_effective_rule_set_key
        preferred = resolve_effective_rule_set_key(uploaded_log)
    except Exception:
        preferred = None
    fresh = UploadedLogAnalysis.objects.filter(upload=uploaded_log, source_content_hash=uploaded_log.content_hash)
    # The keys first: only the payload used is fetched and decoded.
    keys = sorted(fresh.values_list('rule_set_key', flat=True), key=lambda key: (key != preferred, key))
    for key in keys:
        payload = fresh.filter(rule_set_key=key).values_list('payload', flat=True).first()
        if isinstance(payload, dict) and payload.get('format') == ANALYSIS_PAYLOAD_FORMAT:
            return payload
    return None


def _signature(uploaded_log, upload_ids, scope, name):
    """sha1 over everything the correlations depend on (see CorrelationCache)."""
    related = sorted(
        UploadedLog.objects.filter(pk__in=upload_ids).values_list('pk', 'content_hash', 'log_type')
    )
    rows = UploadedLogFileHash.objects.filter(upload_id__in=upload_ids)
    # The related logs' own hash rows: they are rebuilt after the upload (in
    # the background, with the stats), without changing the content hash.
    rows_state = rows.aggregate(n=Count('pk'), latest=Max('pk'))
    md5s = rows.exclude(md5='').values('md5')
    # The SHA256s of the related logs, plus those their MD5s stand for
    # (pairs seen in any log, and centralbox's MD5 answers): a newer verdict
    # for any of them changes the correlations.
    verdicts_changed = HashVerdict.objects.filter(
        Q(sha256__in=rows.exclude(sha256='').values('sha256'))
        | Q(sha256__in=UploadedLogFileHash.objects.filter(md5__in=md5s).exclude(sha256='').values('sha256'))
        | Q(sha256__in=HashAlias.objects.filter(md5__in=md5s).exclude(sha256='').values('sha256')),
    ).aggregate(latest=Max('checked_at'))['latest']
    aliases_changed = HashAlias.objects.filter(md5__in=md5s).aggregate(latest=Max('checked_at'))['latest']
    pairs_changed = UploadedLogFileHash.objects.filter(md5__in=md5s).exclude(sha256='').aggregate(
        latest=Max('pk'),
    )['latest']
    # The machine signals of the upload and its related logs (same-system
    # badges): rebuilt with the stats, like the hash rows.
    signals_state = UploadedLogMachineSignal.objects.filter(
        upload_id__in=[uploaded_log.pk, *upload_ids],
    ).aggregate(n=Count('pk'), latest=Max('pk'))
    # The upload's own analyses: their rule verdicts pick the timing anchors.
    # A re-analysis rewrites the row (updated_at); tag updates do not.
    analyses = UploadedLogAnalysis.objects.filter(upload=uploaded_log).aggregate(
        n=Count('pk'), latest=Max('updated_at'),
    )
    raw = json.dumps([
        CORRELATION_VERSION, uploaded_log.content_hash, scope, name, related,
        signals_state['n'] or 0, signals_state['latest'] or 0,
        analyses['n'] or 0, analyses['latest'].isoformat() if analyses['latest'] else '',
        verdicts_changed.isoformat() if verdicts_changed else '',
        aliases_changed.isoformat() if aliases_changed else '',
        pairs_changed or 0,
        rows_state['n'] or 0, rows_state['latest'] or 0,
    ], default=str)
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()


def _empty(scope='', name=''):
    return {'scope': scope, 'name': name, 'lines': {}, 'statuses': {}, 'notes': {}}


def _own_defender_detections(uploaded_log):
    """True when a merged FRST&Addition log's own Addition part lists a
    Defender detection of a file."""
    if uploaded_log.log_type != LOG_TYPE_FRST_AND_ADDITION:
        return False
    return bool(iter_addition_defender_detections(uploaded_log.content or ''))


def _lookup(uploaded_log, user):
    """(answer, None) when there is nothing to correlate, else (None, (upload
    ids, scope, name, scope_key, signature, cache row or None))."""
    if uploaded_log.log_type not in UploadedLog.ANALYZED_LOG_TYPES:
        return _empty(), None
    upload_ids, scope, name = related_upload_ids(uploaded_log, user)
    # A merged FRST&Addition log speaks for itself through the Defender
    # events of its Addition part, with or without related logs.
    if not upload_ids and not _own_defender_detections(uploaded_log):
        return _empty(scope, name), None
    if scope == SCOPE_CASE and user is not None:
        scope_key = f'case:{user.pk}'
    else:
        scope_key = 'user' if scope == SCOPE_USER else 'self'
    signature = _signature(uploaded_log, upload_ids, scope, name)
    cached = CorrelationCache.objects.filter(upload=uploaded_log, scope_key=scope_key).first()
    if cached is not None and not isinstance(cached.payload, dict):
        cached = None
    return None, (upload_ids, scope, name, scope_key, signature, cached)


def cached_correlations(uploaded_log, user=None):
    """(answer or None, fresh) without computing anything: the stored answer
    even when it is outdated (fresh False), None when nothing is stored yet.
    For the log page, which shows it at once and asks
    correlations_for_upload (through the endpoint) when it is not fresh.
    Never raises."""
    try:
        answer, state = _lookup(uploaded_log, user)
        if answer is not None:
            return answer, True
        _ids, _scope, _name, _key, signature, cached = state
        if cached is None:
            return None, False
        return cached.payload, cached.signature == signature
    except Exception:
        logger.exception('Reading cached correlations failed for %s', getattr(uploaded_log, 'upload_id', '?'))
        return None, True


def correlations_for_upload(uploaded_log, user=None):
    """{scope, name, lines: {stripped line text: [entry]}, statuses: {line text:
    status letter}, notes: {line text: summary note}} for the upload's lines
    with a file seen in a related log (related_upload_ids). Cached per viewer
    scope (CorrelationCache) and recomputed when the signature changes. Empty
    lines for anything else. Never raises."""
    try:
        answer, state = _lookup(uploaded_log, user)
        if answer is not None:
            return answer
        upload_ids, scope, name, scope_key, signature, cached = state
        if cached is not None and cached.signature == signature:
            return cached.payload
        payload = _fresh_payload(uploaded_log)
        if payload is None:
            return _empty(scope, name)
        result = _compute(uploaded_log, upload_ids, payload)
        statuses = {text: correlation_status(entries) for text, entries in result.items()}
        answer = {
            'scope': scope, 'name': name, 'lines': result, 'statuses': statuses,
            'notes': {
                text: summary_note(result[text], status, uploaded_log.upload_id)
                for text, status in statuses.items() if status
            },
        }
        _store(uploaded_log, scope_key, signature, answer)
        try:
            sync_stat_correlated_hashes(uploaded_log.pk, correlated_sha256s(answer))
        except Exception:
            logger.exception('Storing correlated hashes in stats failed for %s', uploaded_log.upload_id)
        return answer
    except Exception:
        logger.exception('Case correlations failed for %s', getattr(uploaded_log, 'upload_id', '?'))
        return _empty()


def correlated_sha256s(answer):
    """The SHA256s an answer correlates with the log's lines, leaving out
    logs from another system and informational matches (as correlation_status
    does). For /stats/, which finds the hashes' centralbox tags (see
    tagging.centralbox_tags_by_sha)."""
    lines = answer.get('lines') if isinstance(answer, dict) else None
    return sorted({
        entry['sha256']
        for entries in (lines or {}).values() for entry in entries or ()
        if isinstance(entry, dict) and entry.get('sha256') and entry.get('system') != SYSTEM_DIFFERENT
        and entry.get('match') not in INFO_MATCHES
    })


def _store(uploaded_log, scope_key, signature, answer):
    """Cache a computed answer. Two requests computing it at once (the log
    page's refresh and its related-logs tab) race to create the row; the
    loser's answer is just as good, so a failed write is only logged."""
    try:
        with transaction.atomic():
            CorrelationCache.objects.update_or_create(
                upload=uploaded_log, scope_key=scope_key,
                defaults={'signature': signature, 'payload': answer},
            )
    except IntegrityError:
        pass
    except Exception:
        logger.exception('Storing correlations failed for %s', getattr(uploaded_log, 'upload_id', '?'))


def _compute(uploaded_log, upload_ids, payload):
    """{line text: [entry]} from scratch."""
    index = {}
    covered = _hash_entries(upload_ids, index)
    _detection_entries(upload_ids, index, covered)
    _fixlog_entries(upload_ids, index)
    _addition_entries(upload_ids, index, own=uploaded_log)
    spor_logs = []
    spor_facts = {}
    _spor_entries(upload_ids, index, spor_logs, spor_facts)
    _frst_search_entries(upload_ids, index)
    _shortcut_entries(upload_ids, index)
    _mau_entries(upload_ids, index)
    merge_same_line(index)
    # A scanner that detected a whole folder (e.g. AdwCleaner's Folders
    # section) also speaks for the files and folders inside it, and so does
    # a folder mention (a Defender path exclusion).
    detections = {}
    for key, entries in index.items():
        found = [entry for entry in entries if entry['kind'] == 'detection' or entry.get('folder')]
        if found:
            detections[key] = found
    related = _RelatedIndex(index)
    verdicts = _system_verdicts(uploaded_log, upload_ids)
    collectors = {}
    for line in payload.get('lines') or []:
        if not isinstance(line, dict):
            continue
        text = (line.get('line') or '').strip()
        if not text or text in collectors:
            continue
        collector = collectors[text] = LineEntries(text, verdicts)
        own_files = []
        keys = line_keys(line)
        for key, match in keys:
            for entry in index.get(key) or ():
                collector.add(entry, match)
            if not is_path_key(key) or match == MATCH_HOST:
                continue  # typed keys have no folders; a host program speaks for nothing
            own_files.append(key)
            parent, previous = ntpath.dirname(key), key
            while detections and parent and parent != previous and len(collector) < MAX_ENTRIES_PER_LINE:
                for entry in detections.get(parent, ()):
                    collector.add(entry, match, in_folder=True)
                parent, previous = ntpath.dirname(parent), parent
        for key in own_files:
            _add_related(collector, related, key)
        if spor_facts:
            _add_spor_links(collector, own_files, spor_facts)
        # line_keys gives the line's own file first.
        main = next((key for key, match in keys if match == MATCH_PATH), '')
        if main:
            collector.created, folder = _created_line(text, main, line.get('dominant_status') or '')
            if folder:
                _add_inside(collector, related, main)
    _add_timing(uploaded_log, collectors, spor_logs, verdicts)
    # Informational entries last; over the cap, status-giving ones first, so
    # the cap never drops one of those (LineEntries.finish).
    return {text: collector.finish(MAX_ENTRIES_PER_LINE) for text, collector in collectors.items() if len(collector)}


def _add_spor_links(collector, own_files, spor_facts):
    """What the related Spor logs' own links add to a line (spor_source.SporFacts):
    the Spor lines naming one of its files in their details ('named_by'), and
    for each Spor line about its own file or entry, the line it sums up or is
    summed up by ('summary') and the files it names in its details ('detail').
    Every Spor line about the file itself is in the index already."""
    for key in own_files:
        for facts in spor_facts.values():
            for entry in facts.named_in.get(key, ()):
                collector.add(entry, MATCH_NAMED_BY)
    typed = match_strength('*typed*')
    for entry, extra in list(collector.links):
        facts = spor_facts.get(entry.get('upload_id'))
        if facts is None or match_strength(extra.get('match'), extra.get('in_folder')) > typed:
            continue   # not about the line's own file or entry
        no = entry.get('line_no')
        for partner in facts.partners.get(no, ()):
            collector.add(partner, MATCH_SUMMARY)
        for key in facts.names.get(no, ()):
            for named in facts.index.get(key, ()):
                if not named.get('folder'):
                    collector.add(named, MATCH_DETAIL, other_path=named.get('path') or key)
