"""Which logs a log is correlated with (its viewer's cases, else the same
forum user's logs), and whether they come from the same machine
(machine_signals.py extracts and compares the signals; they are stored per
log when its stats are rebuilt)."""

import logging

from django.db.models import Q
from django.db.models.functions import Substr

from ..machine_signals import (  # noqa: F401 (re-exported)
    KIND_COMPUTER, KIND_DISK, KIND_HW, KIND_PROFILE, KIND_SID, STRONG_KINDS, SYSTEM_DIFFERENT, SYSTEM_LIKELY, SYSTEM_SAME,
    SYSTEM_SIGNAL_CHARS, SYSTEM_UNKNOWN, compare, compare_with_reason, extract_signals, log_signals,
)
from ..models import InfectionCaseLog, UploadedLog, UploadedLogMachineSignal

logger = logging.getLogger(__name__)


# Detections are read from the summary boxes of DETECTION_LOG_TYPES logs
# (log_highlighting); Defender events from the "Windows Defender:" section of
# ADDITION_LOG_TYPES logs (both in log_types).


SCOPE_CASE = 'case'
SCOPE_USER = 'user'


def related_upload_ids(uploaded_log, user):
    """(upload ids, scope, name): the logs to correlate the upload with.

    The other live logs of the viewer's own live cases that contain the
    upload (scope 'case'); if there are none, every other live log of the same
    forum user, any age, case-insensitive (scope 'user', name = the forum
    username); else nothing.

    The forum username is whatever the uploader typed (anonymous uploads
    included), so the 'user' scope trusts it; accepted as a known risk."""
    owner_id = getattr(user, 'pk', None)
    if owner_id is not None:
        case_ids = list(
            InfectionCaseLog.objects.filter(
                uploaded_log=uploaded_log, case__deleted_at__isnull=True, case__owner_id=owner_id,
            ).values_list('case_id', flat=True)
        )
        if case_ids:
            ids = list(
                InfectionCaseLog.objects.filter(case_id__in=case_ids, uploaded_log__deleted_at__isnull=True)
                .exclude(uploaded_log=uploaded_log)
                .values_list('uploaded_log_id', flat=True)
                .distinct()
            )
            return ids, SCOPE_CASE, ''
    name = (uploaded_log.forum_username or '').strip()
    if name:
        ids = list(
            UploadedLog.objects.filter(forum_username__iexact=name, deleted_at__isnull=True)
            .exclude(pk=uploaded_log.pk).values_list('pk', flat=True)
        )
        return ids, SCOPE_USER, name
    return [], '', ''


# --- Same system? machine_signals.py extracts and compares the signals; they
# are stored per log (UploadedLogMachineSignal) when its stats are rebuilt.


def system_signals(content):
    """(computer names, profile names), lowercased, from the start of a log's
    text (the head-only reading; the stored signals have more kinds)."""
    signals = extract_signals(content, head_only=True)
    return signals.get(KIND_COMPUTER, set()), signals.get(KIND_PROFILE, set())


def same_system(a, b):
    """'same', 'likely', 'different' or 'unknown' for two logs' signals:
    {kind: values} (machine_signals.compare), or (computers, profiles) pairs
    from system_signals."""
    def as_dict(signals):
        if isinstance(signals, tuple):
            computers, profiles = signals
            return {KIND_COMPUTER: set(computers), KIND_PROFILE: set(profiles)}
        return signals or {}
    return compare(as_dict(a), as_dict(b))


def system_verdicts(uploaded_log, upload_pks):
    """{upload pk: (verdict, deciding kind)} of these logs against the
    upload (stored signals, see stored_signals)."""
    signals = stored_signals({uploaded_log.pk, *upload_pks})
    own = signals.get(uploaded_log.pk) or {}
    return {pk: compare_with_reason(own, signals.get(pk) or {}) for pk in upload_pks}


def stored_signals(upload_pks):
    """{upload pk: {kind: hashed values}}: the stored machine signals, or for
    a log without any (stats not rebuilt since, or nothing found) the ones in
    the start of its text."""
    result = {pk: {} for pk in upload_pks}
    if not result:
        return result
    for upload_pk, kind, value in UploadedLogMachineSignal.objects.filter(upload_id__in=list(result)).values_list(
        'upload_id', 'kind', 'value',
    ):
        result[upload_pk].setdefault(kind, set()).add(value)
    missing = [pk for pk, signals in result.items() if not signals]
    if missing:
        heads = UploadedLog.objects.filter(pk__in=missing).annotate(
            head=Substr('content', 1, SYSTEM_SIGNAL_CHARS),
        ).values_list('pk', 'head')
        for pk, head in heads:
            result[pk] = log_signals(head or '')
    return result


def _system_verdicts(uploaded_log, upload_pks):
    """{upload_id: does that log come from the upload's machine?} for the
    related logs and the upload itself (its own entries: the Addition part,
    lines at the same time)."""
    pks = dict(UploadedLog.objects.filter(pk__in=list(upload_pks)).values_list('upload_id', 'pk'))
    signals = stored_signals({uploaded_log.pk, *pks.values()})
    own = signals.get(uploaded_log.pk) or {}
    verdicts = {upload_id: compare(own, signals.get(pk) or {}) for upload_id, pk in pks.items()}
    verdicts[uploaded_log.upload_id] = compare(own, own)
    return verdicts


# What a same-machine suggestion matched on, for the related-logs tab (the
# values themselves are never shown).
SAME_MACHINE_LABELS = {
    KIND_SID: 'machine SID',
    KIND_DISK: 'disk ID',
    'computer+hw': 'computer name and hardware',
}


def same_machine_logs(uploaded_log, exclude_pks=(), limit=20):
    """[(upload pk, [labels])] of live logs outside `exclude_pks` that look
    like they come from the upload's machine, newest first: a shared machine
    SID or Disk ID, or the same computer name together with the same
    hardware; never one the full comparison calls a different system. For
    logs uploaded under another forum name (or none). Never raises."""
    try:
        own = {}
        for kind, value in UploadedLogMachineSignal.objects.filter(upload=uploaded_log).values_list('kind', 'value'):
            own.setdefault(kind, set()).add(value)
        query = Q()
        for kind in STRONG_KINDS:
            if own.get(kind):
                query |= Q(kind=kind, value__in=own[kind])
        excluded = {uploaded_log.pk, *exclude_pks}
        live = UploadedLogMachineSignal.objects.filter(upload__deleted_at__isnull=True).exclude(upload_id__in=excluded)
        found = {}
        if query:
            for upload_pk, kind in live.filter(query).values_list('upload_id', 'kind').distinct():
                found.setdefault(upload_pk, set()).add(kind)
        if own.get(KIND_COMPUTER) and own.get(KIND_HW):
            # Hardware alone is shared by many machines ("System Product
            # Name"): only the logs with the same computer name are checked.
            named = set(
                live.filter(kind=KIND_COMPUTER, value__in=own[KIND_COMPUTER]).values_list('upload_id', flat=True)[:500]
            )
            if named:
                for upload_pk in set(
                    live.filter(upload_id__in=named, kind=KIND_HW, value__in=own[KIND_HW])
                    .values_list('upload_id', flat=True)
                ):
                    found.setdefault(upload_pk, set()).update({KIND_COMPUTER, KIND_HW})
        if not found:
            return []
        matched = {}
        for upload_pk, kinds in found.items():
            labels = [SAME_MACHINE_LABELS[kind] for kind in STRONG_KINDS if kind in kinds]
            if KIND_COMPUTER in kinds and KIND_HW in kinds:
                labels.append(SAME_MACHINE_LABELS['computer+hw'])
            if labels:
                matched[upload_pk] = labels
        if not matched:
            return []
        newest = list(
            UploadedLog.objects.filter(pk__in=list(matched)).order_by('-created_at', '-pk')
            .values_list('pk', flat=True)[:limit * 2]
        )
        theirs = stored_signals(newest)
        own_all = stored_signals([uploaded_log.pk])[uploaded_log.pk]
        result = [
            (pk, matched[pk]) for pk in newest if compare(own_all, theirs.get(pk) or {}) != SYSTEM_DIFFERENT
        ]
        return result[:limit]
    except Exception:
        logger.exception('Finding same-machine logs failed for %s', getattr(uploaded_log, 'upload_id', '?'))
        return []
