"""Files related to a line's file without sharing its path: detected files
in the same folder, copies (same SHA256), files of the same uncommon name,
and the files inside a folder line's folder."""

import bisect
import ntpath

from ..correlation_keys import is_path_key, name_key
from .collector import MAX_INSIDE_ENTRIES, MAX_RELATED_PER_LINE, _rank
from .entries import (
    FLAGGED_STATUSES, MALWARE_STATUSES, MATCH_INSIDE, MATCH_NAME, MATCH_SAME_HASH, MATCH_SIBLING,
    ROLE_FILES_INSIDE, _plain_mention, entry_status, file_name, finding_status,
)
from .folders import is_broad_parent


# The SHA256 of an empty file: copies of it are no copies of anything.
_EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


class _RelatedIndex:
    """Lookups over the index for files related to a line's file without
    sharing its path: detected files by folder, files by name, paths by
    content (SHA256) and the path keys in order (the files inside a folder)."""

    def __init__(self, index):
        self.index = index
        self.path_keys = sorted(key for key in index if is_path_key(key))
        self.detected_by_parent = {}
        self.by_name = {}
        self.paths_by_sha = {}
        self.shas_by_path = {}
        for key in self.path_keys:
            for entry in index[key]:
                if entry.get('folder'):
                    continue
                # A detection, or a hash with a malware verdict (a hash row, or file
                # facts it was merged into: sources.merge_same_line).
                if entry['kind'] == 'detection' or (
                    entry['kind'] in ('hash', 'file_info') and entry_status(entry) in MALWARE_STATUSES
                ):
                    self.detected_by_parent.setdefault(ntpath.dirname(key), []).append((key, entry))
                sha = entry.get('sha256') if entry['kind'] in ('hash', 'file_info') else ''
                if sha and sha != _EMPTY_SHA256:
                    self.paths_by_sha.setdefault(sha, set()).add(key)
                    self.shas_by_path.setdefault(key, set()).add(sha)
            name = name_key(key)
            if name:
                self.by_name.setdefault(name, []).append(key)

    def siblings(self, key):
        """(path, entry) of detections of other files in the key's folder."""
        parent = ntpath.dirname(key)
        if not parent or is_broad_parent(parent):
            return []
        return [(path, entry) for path, entry in self.detected_by_parent.get(parent, ()) if path != key]

    def same_name(self, key):
        """Other paths of a file with the key's (uncommon) name."""
        name = name_key(key)
        return [path for path in self.by_name.get(name, ()) if path != key] if name else []

    def same_content(self, key):
        """Other paths with a SHA256 the key's file has."""
        paths = set()
        for sha in self.shas_by_path.get(key, ()):
            paths |= self.paths_by_sha[sha]
        paths.discard(key)
        return sorted(paths)

    def inside(self, folder):
        """(path, entries) of the keys below a folder key, in order."""
        prefix = folder.rstrip('\\') + '\\'
        start = bisect.bisect_left(self.path_keys, prefix)
        for position in range(start, len(self.path_keys)):
            path = self.path_keys[position]
            if not path.startswith(prefix):
                break
            yield path, self.index[path]


# Where programs are installed: two copies of a file there (another version
# folder, a vendor's shared DLL) are what installers do.
_INSTALLED_PREFIXES = ('c:\\program files', 'c:\\windows\\')


def _both_installed(key, other):
    return key.startswith(_INSTALLED_PREFIXES) and other.startswith(_INSTALLED_PREFIXES)


def _add_related(collector, related, key):
    """The files related to one of the line's files without sharing its
    path: detected siblings, copies (same content: their detections and
    hashes) and files of the same name. Copies and names between two
    installed programs' folders only when the copy is flagged."""
    added = 0
    for path, entry in related.siblings(key):
        if added >= MAX_RELATED_PER_LINE:
            break
        added += collector.add(entry, MATCH_SIBLING, other_path=path)
    for path in related.same_content(key)[:MAX_RELATED_PER_LINE]:
        for entry in related.index.get(path, ()):
            if entry['kind'] not in ('hash', 'file_info', 'detection') or entry.get('folder'):
                continue
            if _both_installed(key, path) and entry_status(entry) not in FLAGGED_STATUSES:
                continue
            collector.add(entry, MATCH_SAME_HASH, other_path=path)
    added = 0
    for path in related.same_name(key):
        if _both_installed(key, path):
            continue
        for entry in sorted(related.index.get(path, ()), key=_rank):
            if added >= MAX_RELATED_PER_LINE:
                return
            if not entry.get('folder'):
                added += collector.add(entry, MATCH_NAME, other_path=path)


# What the files inside a folder line are, in a few words, per kind.
_INSIDE_WHAT = {
    'hash': 'file hashes', 'detection': 'detections', 'fixlog': 'Fixlog results', 'file_info': 'file details',
    'evidence': 'Spor timeline entries', 'mention': 'mentions',
}


def _inside_what(entry):
    """What an entry about a file inside a folder line is, in a few words:
    a mention's role when it reads as one ("deleted by MAU"), else where in
    its log it is ("mentions in AMCACHE"), else its kind."""
    if entry['kind'] != 'mention':
        return _INSIDE_WHAT.get(entry['kind'], entry['kind'])
    role = entry.get('role') or ''
    if ' ' in role:
        return role
    section = entry.get('section') or ''
    return f'mentions in {section}' if section else 'mentions'


def _add_inside(collector, related, folder):
    """What other logs say about the files inside a folder line's folder:
    flagged entries one by one, the others summed up per (log, what) in a
    'files inside' mention. Only malware and PUPs colour the line
    (_MATCH_STATUSES)."""
    if is_broad_parent(folder):
        return
    listed = 0
    groups = {}
    for path, entries in related.inside(folder):
        for entry in entries:
            if finding_status(entry) in FLAGGED_STATUSES and listed < MAX_INSIDE_ENTRIES:
                listed += collector.add(entry, MATCH_INSIDE, other_path=path)
                continue
            # The file names in order, each once (a dict keeps the order).
            group = groups.setdefault((entry['upload_id'], _inside_what(entry)), {'first': entry, 'files': {}})
            group['files'].setdefault(entry.get('file') or file_name(path))
    for (upload_id, what), group in groups.items():
        first, files = group['first'], list(group['files'])
        names = ', '.join(files[:5]) + (', ...' if len(files) > 5 else '')
        collector.add(
            _plain_mention(upload_id, first.get('log_type', ''), first.get('line_no'), f'{len(files)} {what}: {names}',
                           ROLE_FILES_INSIDE),
            MATCH_INSIDE, slot=(ROLE_FILES_INSIDE, upload_id, what),
        )
