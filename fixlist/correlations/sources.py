"""The index of the related logs ({key: [entry]}): hash rows, detections of
scanner logs, Fixlog results and Defender events, Addition logs' Defender
events, Spor logs (spor_source.py), FRST Search and Shortcut logs, MAU."""

import ntpath

from .. import spor_log
from ..correlation_keys import app_key, is_path_key, msi_key, software_keys, target_keys, task_key
from ..file_hashes import _as_path
from ..log_highlighting import highlight_log, threat_severity
from ..log_types import (
    ADDITION_LOG_TYPES, DETECTION_LOG_TYPES, LOG_TYPE_FRST_AND_ADDITION, LOG_TYPE_FRST_SEARCH, LOG_TYPE_SHORTCUT,
)
from ..models import HashAlias, HashVerdict, UploadedLog, UploadedLogFileHash, iter_fixlog_results
from ..tool_log_facts import SECTION_APP_INVESTIGATION, fixlog_app_facts, frst_search_facts, mau_facts, shortcut_mentions
from .defender import iter_addition_defender_detections, iter_defender_detections
from .entries import (
    _add_defender_entries, _add_folder_entry, _add_path_entry, _centralbox_result, _file_info_entry,
    _mention_entry, _plain_mention, file_name, worse_severity,
)


def _hash_entries(upload_ids, index):
    from ..centralbox import resolve_md5s

    rows = list(
        UploadedLogFileHash.objects.filter(upload_id__in=upload_ids).exclude(normalized_path='')
        .select_related('upload')
        .only('sha256', 'md5', 'line_no', 'anchor_line_no', 'detection', 'source', 'normalized_path', 'path',
              'upload__upload_id', 'upload__log_type')
    )
    md5_map = resolve_md5s({row.md5 for row in rows if row.md5 and not row.sha256})
    shas = {row.sha256 or md5_map.get(row.md5, '') for row in rows} - {''}
    verdicts = {row.sha256: row.as_dict() for row in HashVerdict.objects.filter(sha256__in=shas)}
    unknown_md5s = {
        md5: checked.date().isoformat()
        for md5, checked in HashAlias.objects.filter(
            md5__in={row.md5 for row in rows if row.md5}, sha256='',
        ).values_list('md5', 'checked_at')
    }
    covered = set()  # (upload pk, anchor line) of detections that have a hash row
    for row in rows:
        sha = row.sha256 or md5_map.get(row.md5, '')
        result = _centralbox_result(sha, row.md5, verdicts, unknown_md5s)
        covered.add((row.upload_id, row.anchor_line_no))
        index.setdefault(row.normalized_path, []).append({
            'kind': 'hash',
            'upload_id': row.upload.upload_id,
            'log_type': row.upload.log_type,
            'line_no': row.line_no,
            'anchor_line_no': row.anchor_line_no,
            'detection': row.detection,
            'severity': threat_severity(row.detection) if row.detection else '',
            'sha256': sha,
            'md5': row.md5,
            'centralbox': result,
            'file': file_name(row.path),
        })
    return covered


def _detection_entries(upload_ids, index, covered):
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type__in=DETECTION_LOG_TYPES).only(
        'pk', 'upload_id', 'log_type', 'content',
    ):
        highlight = highlight_log(upload.log_type, upload.content or '')
        if highlight is None:
            continue
        for item in highlight.summary:
            if (upload.pk, item.line_no) in covered:
                continue
            # A file path, or the typed keys of a registry value, service,
            # task, browser extension, ... (correlation_keys).
            entry = {
                'kind': 'detection',
                'upload_id': upload.upload_id,
                'log_type': upload.log_type,
                'line_no': item.line_no,
                'detection': item.name,
                'action': item.action,
                'severity': item.severity,
            }
            name = file_name(_as_path(item.target))
            if name:
                entry['file'] = name
            for key in target_keys(item.target):
                index.setdefault(key, []).append(entry)


def _fixlog_entries(upload_ids, index):
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type='Fixlog').only('pk', 'upload_id', 'content'):
        content = upload.content or ''
        if '<=== ' in content:
            _fixlog_app_entries(upload, index)
        for line_no, target, result in iter_fixlog_results(content):
            entry = {
                'kind': 'fixlog',
                'upload_id': upload.upload_id,
                'log_type': 'Fixlog',
                'line_no': line_no,
                'result': result.strip()[:200],
            }
            name = file_name(_as_path(target.strip().strip('"')))
            if name:
                entry['file'] = name
            for key in target_keys(target, result):
                index.setdefault(key, []).append(entry)
        if 'Threat' not in content:
            continue
        # Windows Defender events in the Fixlog: detections like a scanner's.
        _add_defender_entries(index, upload.upload_id, 'Fixlog', iter_defender_detections(content))


def _addition_entries(upload_ids, index, own=None):
    """Defender detections of the related Addition logs, and of the
    upload's own Addition part (`own`, a merged FRST&Addition log)."""
    uploads = list(
        UploadedLog.objects.filter(pk__in=upload_ids, log_type__in=ADDITION_LOG_TYPES)
        .only('pk', 'upload_id', 'content')
    )
    for upload in uploads:
        _add_defender_entries(
            index, upload.upload_id, 'Addition', iter_addition_defender_detections(upload.content or ''),
        )
    if own is not None and own.log_type == LOG_TYPE_FRST_AND_ADDITION:
        content = own.content or ''
        detections = iter_addition_defender_detections(content)
        if detections:
            _add_defender_entries(index, own.upload_id, 'Addition', detections, lines=content.split('\n'))


def _mau_mention(upload_id, line_no, text, role, file, extra=(), severity=''):
    return _plain_mention(upload_id, 'MAU', line_no, text, role, file, section='MAU', extra=extra, severity=severity)


def _mau_entries(upload_ids, index):
    """What the related MAU logs removed (tool_log_facts.mau_facts): each
    product under its MSI product code, Uninstall key and display name
    (Addition's Installed Programs line), and its install folder; the folder
    it was installed from (often a dropper's Temp folder); every deleted
    file, folder, registry key / value, service and task."""
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type='MAU').only('upload_id', 'log_type', 'content'):
        products, items = mau_facts(upload.content or '')
        for product in products:
            name = product.name if product.name and product.name != product.ident else ''
            text = name + (f' ({product.publisher})' if product.publisher else '') if name else product.ident
            extra = [('product code', product.ident[:80])] if msi_key(product.ident) else []
            if product.version:
                extra.append(('version', product.version[:80]))
            if product.install_location:
                extra.append(('install folder', product.install_location[:200]))
            if product.install_source:
                extra.append(('installed from', product.install_source[:200]))
            entry = _mau_mention(upload.upload_id, product.line_no, text, 'removed by MAU', name or product.ident, extra)
            if name:
                entry['version'] = product.version[:100]
            keys = {msi_key(product.ident), app_key(name)}
            for key in product.uninstall_keys:
                keys.update(software_keys(key))
            for key in sorted(keys - {''}):
                index.setdefault(key, []).append(entry)
            if product.install_location:
                _add_folder_entry(index, product.install_location, entry)
            if product.install_source:
                _add_folder_entry(index, product.install_source, {**entry, 'role': 'MAU install source'})
            for line_no, path in product.key_paths:
                # A file the product's MSI components point at: what it installed.
                _add_path_entry(index, path, _mau_mention(
                    upload.upload_id, line_no, f'{name or product.ident}: {path}', 'installed by product (MAU)',
                    file_name(path),
                ))
        for item in items:
            target = item.target.strip().strip('"')
            role = 'MAU failed to delete' if item.failed else 'deleted by MAU'
            path = _as_path(target) if item.kind in ('File', 'Dir') else ''
            entry = _mau_mention(
                upload.upload_id, item.line_no, f'[{item.kind}] {target}', role,
                file_name(path) if path else ntpath.basename(target.rstrip('\\')),
                severity='w' if item.failed else '',
            )
            if item.kind == 'Dir':
                if path:
                    _add_folder_entry(index, path, entry)
            elif item.kind == 'File':
                if path:
                    _add_path_entry(index, path, entry)
            elif item.kind == 'Service':
                index.setdefault(f'svc:{target.lower()}', []).append(entry)
            elif item.kind == 'Task':
                key = task_key(target)
                if key:
                    index.setdefault(key, []).append(entry)
            elif item.kind == 'RegValue':
                # "<key>\<value>": a Run value is "<Run key>|<value>" to
                # target_keys. The values of an Uninstall key stand for the
                # product, which its own entry (or the key's) already gives.
                key_path, _sep, value = target.rpartition('\\')
                for key in target_keys(f'{key_path}|{value}' if key_path else target):
                    if not is_path_key(key) and not key.startswith(('uninstall:', 'msi:')):
                        index.setdefault(key, []).append(entry)
            else:
                for key in target_keys(target):
                    if not is_path_key(key):
                        index.setdefault(key, []).append(entry)


def _fixlog_app_entries(upload, index):
    """The installed-app investigation of a Fixlog (a fixlist PowerShell
    snippet, tool_log_facts.fixlog_app_facts): each app under its display
    name (Addition's Installed Programs line; the versions are compared when
    matched) and its install folder (the files inside), or its one file."""
    for app in fixlog_app_facts(upload.content or ''):
        extra = []
        if app.path:
            extra.append(('path', app.path[:200]))
        if app.state:
            extra.append(('state', app.state[:80]))
        if app.files or app.folders:
            extra.append(('contents', f'{app.files} files, {app.folders} folders'))
        if app.unsigned:
            extra.append(('unsigned PE files', str(app.unsigned)))
        for path, signer in app.invalid[:5]:
            extra.append(('invalid signature', f'{file_name(path)}: {signer}'))
        if app.signers:
            extra.append(('signers', ', '.join(app.signers)[:200]))
        text = app.name + (f' [{app.version}]' if app.version else '') + (f' ({app.publisher})' if app.publisher else '')
        entry = {
            'kind': 'mention', 'upload_id': upload.upload_id, 'log_type': 'Fixlog', 'line_no': app.line_no,
            'section': SECTION_APP_INVESTIGATION, 'subsection': '', 'time': '', 'tags': '', 'text': text[:300],
            'role': 'installed app', 'parent': '', 'file_status': app.state[:40], 'flags': [],
            'extra': [list(pair) for pair in extra][:spor_log.MAX_EXTRA],
            'severity': 'w' if app.invalid else '', 'file': app.name[:120], 'version': app.version[:100],
        }
        key = app_key(app.name)
        if key:
            index.setdefault(key, []).append(entry)
        if not app.path or app.state:
            continue
        if app.is_folder:
            _add_folder_entry(index, app.path, entry)
        else:
            _add_path_entry(index, app.path, entry)


def _frst_search_entries(upload_ids, index):
    """File: entries (file_info) and folder / registry hits (mention) of the
    related FRST Search logs. (Their MD5s are hash rows too.)"""
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type=LOG_TYPE_FRST_SEARCH).only('upload_id', 'content'):
        files, mentions = frst_search_facts(upload.content or '')
        for facts in files:
            _add_path_entry(index, facts.path, _file_info_entry(
                upload.upload_id, LOG_TYPE_FRST_SEARCH, facts.line_no, facts.path, facts.source, facts.facts,
                {'md5': facts.md5},
            ))
        for mention in mentions:
            _add_path_entry(index, mention.path, _mention_entry(upload.upload_id, LOG_TYPE_FRST_SEARCH, mention))


def _shortcut_entries(upload_ids, index):
    """Shortcuts of the related Shortcut logs: under their target and their .lnk file."""
    for upload in UploadedLog.objects.filter(pk__in=upload_ids, log_type=LOG_TYPE_SHORTCUT).only('upload_id', 'content'):
        for mention in shortcut_mentions(upload.content or ''):
            _add_path_entry(index, mention.path, _mention_entry(upload.upload_id, LOG_TYPE_SHORTCUT, mention))


def merge_same_line(index):
    """One entry per line of a related log: a hash row of a line that also has
    file facts (a Spor log's FILES line is both; so is an FRST Search File:
    entry with its MD5) becomes part of the file facts entry - its hashes,
    centralbox result and detection go with the facts. Everywhere that entry
    is indexed, so every line gets the same one."""
    infos = {}
    for entries in index.values():
        for entry in entries:
            if entry['kind'] == 'file_info' and entry.get('upload_id') and entry.get('line_no'):
                infos.setdefault((entry['upload_id'], entry['line_no']), entry)
    if not infos:
        return
    merged = {}     # id(file facts entry) -> the merged entry
    absorbed = {}   # id(hash row) -> id(file facts entry)
    for entries in index.values():
        for entry in entries:
            if entry['kind'] != 'hash' or id(entry) in absorbed:
                continue
            info = infos.get((entry.get('upload_id'), entry.get('anchor_line_no') or entry.get('line_no')))
            if info is None:
                continue
            merged[id(info)] = _with_hash_row(merged.get(id(info), info), entry)
            absorbed[id(entry)] = id(info)
    if not merged:
        return
    for key, entries in index.items():
        # Where the hash row was (hash rows are indexed first: what decides a
        # line's note stays first), else where the facts were.
        here = {absorbed[id(entry)] for entry in entries if id(entry) in absorbed}
        out = []
        placed = set()
        for entry in entries:
            if id(entry) in absorbed:
                if absorbed[id(entry)] not in placed:
                    placed.add(absorbed[id(entry)])
                    out.append(merged[absorbed[id(entry)]])
            elif id(entry) in here:
                continue
            else:
                out.append(merged.get(id(entry), entry))
        index[key] = out


def _with_hash_row(info, row):
    """A copy of file facts with what a hash row of the same line adds."""
    out = dict(info)
    for name in ('sha256', 'md5'):
        if row.get(name) and not out.get(name):
            out[name] = row[name]
    if row.get('centralbox') is not None:
        out['centralbox'] = row['centralbox']
    if row.get('anchor_line_no'):
        out['anchor_line_no'] = row['anchor_line_no']
    if row.get('detection'):
        out['detection'] = row['detection']
        # The worse of the detection's severity and the facts' (a signature that does not hold).
        out['severity'] = worse_severity(row.get('severity') or '', info.get('severity') or '')
    return out
