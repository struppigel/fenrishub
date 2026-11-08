"""
Duplicate hints for uploads: the same scan uploaded more than once.

Helpers re-upload logs: the same text pasted twice, or FRST.txt first and the
merged FRST&Addition file later. Counting those as separate machines skews
every corpus search, so the token API marks them. Two uploads are copies of
one scan when

  - their content is identical (same content_hash), or
  - the same forum user uploaded them, they carry the same FRST scan date, and
    their log types are the same or one is the merged FRST&Addition holding
    the other. FRST.txt and Addition.txt of one run share a scan date but
    complement each other, so those two alone are never copies.

Copies are grouped transitively. The canonical upload of a group is the most
complete one: the merged FRST&Addition first, then the most analyzed lines,
then the oldest. Work is done on value rows, never on log content.
"""

from django.db.models import Q

DUPLICATE_ROW_FIELDS = (
    'pk', 'upload_id', 'content_hash', 'forum_username', 'scan_date',
    'log_type', 'total_line_count', 'created_at',
)
MERGED_LOG_TYPE = 'FRST&Addition'
MERGED_PART_TYPES = {'FRST', 'Addition'}
REASON_SAME_CONTENT = 'same_content'
REASON_SAME_SCAN = 'same_user_and_scan_date'


def _same_scan_types(first, second):
    if first == second:
        return True
    pair = {first, second}
    return MERGED_LOG_TYPE in pair and (pair - {MERGED_LOG_TYPE}) <= MERGED_PART_TYPES


def _completeness_key(row):
    return (
        0 if row['log_type'] == MERGED_LOG_TYPE else 1,
        -(row['total_line_count'] or 0),
        row['created_at'],
        row['pk'],
    )


def duplicate_groups(rows):
    """``{pk: info}`` for every row that has a copy among `rows`.

    The canonical row gets ``{'canonical': True, 'duplicates': [upload_id, ...]}``;
    each other copy ``{'canonical': False, 'duplicate_of': {'upload_id', 'reason'}}``,
    the reason being `same_content` when its text equals the canonical one's.
    Rows without a copy are left out. `rows` are dicts with DUPLICATE_ROW_FIELDS.
    """
    rows = list(rows)
    parent = {row['pk']: row['pk'] for row in rows}

    def find(pk):
        while parent[pk] != pk:
            parent[pk] = parent[parent[pk]]
            pk = parent[pk]
        return pk

    def union(first, second):
        root_first, root_second = find(first), find(second)
        if root_first != root_second:
            parent[root_second] = root_first

    by_hash = {}
    by_scan = {}
    for row in rows:
        if row['content_hash']:
            by_hash.setdefault(row['content_hash'], []).append(row['pk'])
        if row['scan_date'] is not None and row['forum_username']:
            by_scan.setdefault((row['forum_username'].lower(), row['scan_date']), []).append(row)
    for pks in by_hash.values():
        for pk in pks[1:]:
            union(pks[0], pk)
    for members in by_scan.values():
        for index, first in enumerate(members):
            for second in members[index + 1:]:
                if _same_scan_types(first['log_type'], second['log_type']):
                    union(first['pk'], second['pk'])

    groups = {}
    for row in rows:
        groups.setdefault(find(row['pk']), []).append(row)
    info = {}
    for members in groups.values():
        if len(members) < 2:
            continue
        members.sort(key=_completeness_key)
        canonical = members[0]
        info[canonical['pk']] = {
            'canonical': True,
            'duplicates': [member['upload_id'] for member in members[1:]],
        }
        for member in members[1:]:
            same_content = bool(member['content_hash']) and member['content_hash'] == canonical['content_hash']
            info[member['pk']] = {
                'canonical': False,
                'duplicate_of': {
                    'upload_id': canonical['upload_id'],
                    'reason': REASON_SAME_CONTENT if same_content else REASON_SAME_SCAN,
                },
            }
    return info


def duplicate_info_for(uploads, live_uploads):
    """``{pk: info}`` (see duplicate_groups) for `uploads`, against every upload in `live_uploads`.

    `uploads` are UploadedLog instances (content may be deferred); one query
    fetches their possible copies among `live_uploads`, the non-trashed ones.
    """
    uploads = list(uploads)
    if not uploads:
        return {}
    related = Q(pk__in=[upload.pk for upload in uploads])
    hashes = {upload.content_hash for upload in uploads if upload.content_hash}
    if hashes:
        related |= Q(content_hash__in=hashes)
    for upload in uploads:
        if upload.scan_date is not None and upload.forum_username:
            related |= Q(forum_username__iexact=upload.forum_username, scan_date=upload.scan_date)
    rows = live_uploads.filter(related).order_by().values(*DUPLICATE_ROW_FIELDS)
    wanted = {upload.pk for upload in uploads}
    return {pk: value for pk, value in duplicate_groups(rows).items() if pk in wanted}


def non_canonical_pks(uploads):
    """The pks of uploads in the queryset `uploads` that are copies of a more complete one in it."""
    rows = uploads.order_by().values(*DUPLICATE_ROW_FIELDS)
    return {pk for pk, value in duplicate_groups(rows).items() if not value['canonical']}


def duplicate_metadata(info):
    """The fields an upload's API metadata gains from its `duplicate_groups` entry (or None)."""
    if not info:
        return {'duplicate_of': None, 'duplicates': []}
    if info['canonical']:
        return {'duplicate_of': None, 'duplicates': info['duplicates']}
    return {'duplicate_of': info['duplicate_of'], 'duplicates': []}
