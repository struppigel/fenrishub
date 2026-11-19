"""One forum user under several forum names: find the names whose logs come
from the same machine (machine_signals, the same rules as
case_correlations.same_machine_logs) and rename them to one.

- same_user_groups: the admin's "same users" page.
- rename_forum_usernames: whole names, everywhere (logs, fixlists, cases,
  stats rows).
- rename_logs: only some logs (the related-logs tab of a log page).
"""

from collections import defaultdict

from django.db import transaction
from django.db.models import Count, Max, Q
from django.utils import timezone

from .case_correlations import stored_signals
from .machine_signals import KIND_COMPUTER, KIND_HW, STRONG_KINDS, SYSTEM_DIFFERENT, compare
from .models import (
    Fixlist,
    FixlistStat,
    InfectionCase,
    InfectionCaseUsername,
    UploadedLog,
    UploadedLogMachineSignal,
    UploadedLogStat,
    stat_username,
)

FORUM_USERNAME_MAX_LENGTH = 100
# A machine signal shared by more names than this is noise (a cloned image,
# a generic computer name and hardware), not one user.
MAX_NAMES_PER_KEY = 5
SAMPLE_UPLOADS = 3
COMPUTER_HW = 'computer+hw'
EVIDENCE_LABELS = {
    'sid': 'machine SID',
    'disk': 'disk ID',
    COMPUTER_HW: 'computer name and hardware',
}


def clean_forum_username(value):
    """The stripped name, or None if it isn't 1-100 characters (UploadedLog.clean)."""
    name = (value or '').strip()
    return name if 1 <= len(name) <= FORUM_USERNAME_MAX_LENGTH else None


def _machine_keys(live_names):
    """{key: {upload pk}} of the live logs: (kind, value) for SIDs and Disk
    IDs, (COMPUTER_HW, computer, hw) for each computer name + hardware."""
    by_upload = defaultdict(lambda: defaultdict(set))
    # Built from (upload, kind, value) rows only: the content is never read.
    rows = UploadedLogMachineSignal.objects.filter(
        upload__deleted_at__isnull=True, kind__in=(*STRONG_KINDS, KIND_COMPUTER, KIND_HW),
    ).values_list('upload_id', 'kind', 'value')
    for upload_pk, kind, value in rows.iterator(chunk_size=5000):
        if upload_pk in live_names:
            by_upload[upload_pk][kind].add(value)
    keys = defaultdict(set)
    for upload_pk, signals in by_upload.items():
        for kind in STRONG_KINDS:
            for value in signals.get(kind, ()):
                keys[(kind, value)].add(upload_pk)
        for computer in signals.get(KIND_COMPUTER, ()):
            for hw in signals.get(KIND_HW, ()):
                keys[(COMPUTER_HW, computer, hw)].add(upload_pk)
    return keys


class _Groups:
    def __init__(self):
        self.parent = {}

    def find(self, name):
        self.parent.setdefault(name, name)
        while self.parent[name] != name:
            self.parent[name] = self.parent[self.parent[name]]
            name = self.parent[name]
        return name

    def union(self, a, b):
        self.parent[self.find(a)] = self.find(b)


def same_user_groups(max_names_per_key=MAX_NAMES_PER_KEY):
    """Groups of forum names whose live logs look like one machine, newest
    first: [{'names': [{'name', 'logs', 'last_upload', 'samples', 'fixlists',
    'cases'}], 'evidence': [label], 'last_upload'}]. A pair of names joins
    only if their newest logs sharing the signal aren't a different system
    by the full comparison."""
    live = {}
    created = {}
    for pk, name, created_at in UploadedLog.objects.live().values_list('pk', 'forum_username', 'created_at'):
        live[pk] = name
        created[pk] = created_at
    keys = _machine_keys(live)
    # {(name a, name b, newest log of a, newest log of b): evidence kinds}
    pair_evidence = defaultdict(set)
    for key, upload_pks in keys.items():
        pks_by_name = defaultdict(list)
        for upload_pk in upload_pks:
            pks_by_name[live[upload_pk]].append(upload_pk)
        if not 2 <= len(pks_by_name) <= max_names_per_key:
            continue
        newest = {name: max(pks, key=lambda pk: (created[pk], pk)) for name, pks in pks_by_name.items()}
        names = sorted(newest)
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                pair_evidence[(a, b, newest[a], newest[b])].add(key[0])
    if not pair_evidence:
        return []

    # The full comparison of all stored signals, as same_machine_logs does.
    signals = stored_signals({pk for _a, _b, pk_a, pk_b in pair_evidence for pk in (pk_a, pk_b)})
    groups = _Groups()
    joined = []
    for (a, b, pk_a, pk_b), kinds in pair_evidence.items():
        if compare(signals.get(pk_a) or {}, signals.get(pk_b) or {}) == SYSTEM_DIFFERENT:
            continue
        groups.union(a, b)
        joined.append((a, kinds))
    if not joined:
        return []
    group_evidence = defaultdict(set)
    for name, kinds in joined:
        group_evidence[groups.find(name)].update(kinds)
    members = defaultdict(set)
    for name in groups.parent:
        members[groups.find(name)].add(name)

    all_names = sorted(set().union(*members.values()))
    details = _name_details(all_names)
    result = []
    for root, names in members.items():
        rows = sorted((details[name] for name in names), key=lambda row: (-row['logs'], row['name'].lower()))
        result.append({
            'names': rows,
            'evidence': [EVIDENCE_LABELS[kind] for kind in ('sid', 'disk', COMPUTER_HW) if kind in group_evidence[root]],
            'last_upload': max(row['last_upload'] for row in rows),
        })
    result.sort(key=lambda group: group['last_upload'], reverse=True)
    return result


def _name_details(names):
    """{name: row} with the live log, fixlist and case counts of each name."""
    logs = UploadedLog.objects.live().filter(forum_username__in=names)
    details = {
        row['forum_username']: {
            'name': row['forum_username'], 'logs': row['count'], 'last_upload': row['last'],
            'samples': [], 'fixlists': 0, 'cases': 0,
        }
        for row in logs.values('forum_username').annotate(count=Count('pk'), last=Max('created_at'))
    }
    for name, upload_id in logs.order_by('-created_at', '-pk').values_list('forum_username', 'upload_id'):
        if len(details[name]['samples']) < SAMPLE_UPLOADS:
            details[name]['samples'].append(upload_id)
    for row in (
        Fixlist.objects.filter(deleted_at__isnull=True, username__in=names)
        .values('username').annotate(count=Count('pk'))
    ):
        details[row['username']]['fixlists'] = row['count']
    case_names = defaultdict(set)
    cases = InfectionCase.objects.filter(deleted_at__isnull=True)
    for case_pk, name in cases.filter(username__in=names).values_list('pk', 'username'):
        case_names[name].add(case_pk)
    for case_pk, name in InfectionCaseUsername.objects.filter(
        case__deleted_at__isnull=True, username__in=names,
    ).values_list('case_id', 'username'):
        case_names[name].add(case_pk)
    for name, case_pks in case_names.items():
        details[name]['cases'] = len(case_pks)
    return details


def _rekey_stats(model, field, source_pks, old_names, new_name):
    """Point the stats rows of these sources, and the orphaned ones (source
    gone) of the old names, at the new name."""
    new_key = stat_username(new_name)
    model.objects.filter(source_id__in=source_pks).update(**{field: new_key})
    old_keys = {stat_username(name) for name in old_names} - {new_key}
    if not old_keys:
        return
    source_model = UploadedLog if model is UploadedLogStat else Fixlist
    orphans = model.objects.filter(**{f'{field}__in': old_keys}).values_list('pk', 'source_id')
    existing = set(source_model.objects.filter(
        pk__in=[source_id for _pk, source_id in orphans],
    ).values_list('pk', flat=True))
    model.objects.filter(pk__in=[pk for pk, source_id in orphans if source_id not in existing]).update(
        **{field: new_key},
    )


def rename_forum_usernames(old_names, new_name):
    """Rename whole forum names to `new_name`: their logs (trashed ones too),
    fixlists, infection cases (main and other usernames) and stats rows.
    Returns {'logs', 'fixlists', 'cases'} counts. Raises ValueError for an
    invalid new name."""
    new_name = clean_forum_username(new_name)
    if new_name is None:
        raise ValueError(f'The new name must be 1-{FORUM_USERNAME_MAX_LENGTH} characters.')
    old_names = sorted({name for name in old_names if name and name != new_name})
    if not old_names:
        return {'logs': 0, 'fixlists': 0, 'cases': 0}
    now = timezone.now()
    with transaction.atomic():
        log_pks = list(UploadedLog.objects.filter(forum_username__in=old_names).values_list('pk', flat=True))
        UploadedLog.objects.filter(pk__in=log_pks).update(forum_username=new_name, updated_at=now)
        _rekey_stats(UploadedLogStat, 'forum_username', log_pks, old_names, new_name)

        fixlist_pks = list(Fixlist.objects.filter(username__in=old_names).values_list('pk', flat=True))
        Fixlist.objects.filter(pk__in=fixlist_pks).update(username=new_name)
        _rekey_stats(FixlistStat, 'username', fixlist_pks, old_names, new_name)

        cases = InfectionCase.objects.filter(
            Q(username__in=old_names) | Q(extra_usernames__username__in=old_names),
        ).distinct()
        case_count = 0
        for case in cases:
            extras = case.extra_username_list()
            if case.username in old_names:
                case.username = new_name
                case.save(update_fields=['username', 'updated_at'])
            case.set_extra_usernames([new_name if name in old_names else name for name in extras])
            case_count += 1
    return {'logs': len(log_pks), 'fixlists': len(fixlist_pks), 'cases': case_count}


def rename_logs(uploads, new_name):
    """Rename only these logs; the stats signal updates their stats rows.
    Returns how many were renamed."""
    new_name = clean_forum_username(new_name)
    if new_name is None:
        raise ValueError(f'The new name must be 1-{FORUM_USERNAME_MAX_LENGTH} characters.')
    count = 0
    with transaction.atomic():
        for upload in uploads:
            if upload.forum_username == new_name:
                continue
            upload.forum_username = new_name
            upload.save(update_fields=['forum_username', 'updated_at'])
            count += 1
    return count
