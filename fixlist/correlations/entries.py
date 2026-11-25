"""Correlation entries: what one line of a related log says about a file,
and how entries get into the index ({key: [entry]}) correlations are looked
up in.

Kinds (`kind`): 'hash' (a hash row: detection, SHA256 / MD5, centralbox
result), 'detection' (a scanner or Defender detection without a hash),
'fixlog' (a fixlist result), 'file_info' (facts about the file: a Spor log's
FILES / AMCACHE FILES line, an FRST Search File: entry), 'evidence' (a Spor
timeline line), 'mention' (any other place a log names the file or entry),
'reverse' (an FRST / Addition line pointing at a line of another log:
reverse.py).

How an entry was found for a line is its `match` (MATCH_NOTES; none for the
line's own file). Informational matches (INFO_MATCHES) never give a status.
"""

import logging
import ntpath

from .. import spor_log
from ..correlation_keys import MATCH_ARGUMENT, MATCH_HOST
from ..file_hashes import normalized_path
from ..log_highlighting import defender_severity
from ..machine_signals import SYSTEM_DIFFERENT
from ..models import HashAlias, HashVerdict
from ..status_types import dominant_status
from .folders import is_broad_folder

logger = logging.getLogger(__name__)


# When a line has more entries than that, these come first (status-giving
# entries before all others), so what decides the line's status is never cut.
KIND_RANK = {'detection': 0, 'hash': 1, 'fixlog': 2, 'file_info': 3, 'evidence': 4, 'mention': 5}


def _first_line_numbers(content, wanted):
    """{stripped line text: its first line number} for the wanted texts."""
    numbers = {}
    for no, raw in enumerate((content or '').split('\n'), start=1):
        text = raw.strip()
        if text in wanted and text not in numbers:
            numbers[text] = no
            if len(numbers) == len(wanted):
                break
    return numbers


def _centralbox_result(sha, md5, verdicts, unknown_md5s):
    if sha and sha in verdicts:
        return verdicts[sha]
    if md5 and md5 in unknown_md5s:
        return {'state': HashVerdict.STATE_UNKNOWN, 'checked_at': unknown_md5s[md5]}
    return None


def add_stored_results(entries):
    """Give each file_info entry its hash's stored centralbox result (as hash
    entries have one): what the info box shows, and why it offers no lookup
    for a hash centralbox knows. Database only; never raises."""
    from ..centralbox import resolve_md5s

    try:
        infos = [entry for entry in entries if entry.get('kind') == 'file_info'
                 and (entry.get('sha256') or entry.get('md5'))]
        if not infos:
            return entries
        md5_map = resolve_md5s({entry['md5'] for entry in infos if entry.get('md5') and not entry.get('sha256')})
        shas = {entry.get('sha256') or md5_map.get(entry.get('md5', ''), '') for entry in infos} - {''}
        verdicts = {row.sha256: row.as_dict() for row in HashVerdict.objects.filter(sha256__in=shas)}
        unknown_md5s = {
            md5: checked.date().isoformat()
            for md5, checked in HashAlias.objects.filter(
                md5__in={entry['md5'] for entry in infos if entry.get('md5')}, sha256='',
            ).values_list('md5', 'checked_at')
        }
        for entry in infos:
            md5 = entry.get('md5', '')
            result = _centralbox_result(entry.get('sha256') or md5_map.get(md5, ''), md5, verdicts, unknown_md5s)
            if result:
                entry['centralbox'] = result
    except Exception:
        logger.exception('Adding stored centralbox results failed')
    return entries


def file_name(path):
    """The last part of a path as the log spells it ('' for none): which
    file an entry is about, as a line can name several (its own file, files
    in its command line, a detected folder above it)."""
    return ntpath.basename((path or '').strip().strip('"').rstrip('\\'))[:120]


def _add_defender_entries(index, upload_id, log_type, detections, lines=None):
    """`lines` (the log's content.split('\\n')) adds each entry's line text:
    for the log's own entries, which the analyzer finds by it."""
    for line_no, threat, action, path in detections:
        key = normalized_path(path)
        if not key:
            continue
        entry = {
            'kind': 'detection',
            'upload_id': upload_id,
            'log_type': log_type,
            'line_no': line_no,
            'detection': threat[:255],
            'action': action[:100],
            'severity': defender_severity(threat),
            'source': 'defender',
            'file': file_name(path),
        }
        if lines is not None and 0 < line_no <= len(lines):
            entry['line_text'] = lines[line_no - 1].strip()[:300]
        index.setdefault(key, []).append(entry)


def evidence_severity(flags, file_status):
    """'b' for a Spor entry of a known malware family (!known-malware); 'w'
    for one with a strong flag (not normal on many PCs, not a hint) or a file
    whose signature does not hold; 'i' with only a hint (!renamed-program)
    or a context flag (!remote-access, ...); '' otherwise."""
    tier = spor_log.worst_tier(flags)
    if tier == 'malware':
        return 'b'
    if tier == 'strong' or spor_log.is_bad_signature(file_status):
        return 'w'
    return 'i' if tier in ('hint', 'info') else ''


def original_name_differs(path, original_name):
    """True when a file's version resource names another file ("invoice.pdf.exe"
    whose original name is "svchost.exe"). Shown, never rated: renamed
    installers are common."""
    base = ntpath.basename(path or '').lower()
    original = (original_name or '').strip().lower()
    if not base or not original:
        return False
    stem = base.rsplit('.', 1)[0]
    return not (original == base or original.startswith(base + '.') or original.rsplit('.', 1)[0] == stem)


def _file_info_entry(upload_id, log_type, line_no, path, source, facts, hashes, severity=''):
    entry = {
        'kind': 'file_info', 'upload_id': upload_id, 'log_type': log_type, 'line_no': line_no,
        'source': source, 'file': file_name(path), 'path': path[:400], 'severity': severity,
    }
    entry.update({key: value[:300] for key, value in facts.items() if value})
    entry.update({key: value.lower() for key, value in hashes.items() if value})
    if entry.get('original_name') and original_name_differs(path, entry['original_name']):
        entry['original_name_differs'] = True
    return entry


def _mention_entry(upload_id, log_type, mention):
    entry = {
        'kind': 'mention', 'upload_id': upload_id, 'log_type': log_type, 'line_no': mention.line_no,
        'section': mention.section[:80], 'subsection': mention.subsection[:160], 'time': mention.time,
        'tags': mention.tags[:80], 'text': mention.text[:300], 'role': mention.role, 'parent': mention.parent[:200],
        # Not `status`: the API gives every entry its status letter under that name.
        'file_status': mention.status, 'flags': mention.flags[:10], 'extra': mention.extra[:spor_log.MAX_EXTRA],
        'severity': evidence_severity(mention.flags, mention.status),
        # A persistence entry without a file of its own: named by its value / service / task.
        'file': file_name(mention.path) or (mention.identity[1][:120] if mention.identity else ''),
    }
    if mention.folder:
        entry['folder'] = True
    return entry


def _add_folder_entry(index, folder, entry):
    """Index `entry` as a folder mention (the files inside get it too), unless
    the folder is too broad."""
    key = normalized_path(folder).rstrip('\\')
    if key and not is_broad_folder(key):
        index.setdefault(key, []).append({**entry, 'folder': True})


def _plain_mention(upload_id, log_type, line_no, text, role, file='', section='', time='', tags='', extra=(),
                   severity=''):
    """A mention entry built from parts (not from a parsed Spor item)."""
    return {
        'kind': 'mention', 'upload_id': upload_id, 'log_type': log_type, 'line_no': line_no,
        'section': section, 'subsection': '', 'time': time, 'tags': tags[:80], 'text': text[:300],
        'role': role, 'parent': '', 'file_status': '', 'flags': [],
        'extra': [list(pair) for pair in extra][:spor_log.MAX_EXTRA], 'severity': severity, 'file': file[:120],
    }


def _add_path_entry(index, path, entry):
    key = normalized_path(path)
    if key:
        index.setdefault(key, []).append(entry)


def mention_text(entry):
    """A mention in a few words: its flags, else where in the log it is."""
    loud = [flag for flag in entry.get('flags') or () if flag not in spor_log.QUIET_FLAGS]
    if loud:
        return ' '.join(loud)
    where = ' \u203a '.join(part for part in (entry.get('section') or '', entry.get('subsection') or '') if part)
    return ' '.join(part for part in (where, entry.get('file_status') or '') if part)


def evidence_text(entry):
    """A Spor timeline entry in a few words: its flags, else when and by
    which sources the file was seen."""
    loud = [flag for flag in entry.get('flags') or () if flag not in spor_log.QUIET_FLAGS]
    if loud:
        return ' '.join(loud)
    seen = ' '.join(part for part in (str(entry.get('time') or '')[:16], entry.get('sources') or '') if part)
    return ' '.join(part for part in (seen, entry.get('file_status') or '') if part)


# A finding as a line-verdict status letter (status_types): detection
# severities from the log pages, centralbox verdicts. Fixlog results and
# unchecked / unknown hashes have none.
_SEVERITY_STATUS = {'b': 'B', 'p': 'P', 'g': 'G', 'w': '!', 'c': 'C', 'j': 'J', 'i': 'I'}
_VERDICT_STATUS = {'malicious': 'B', 'suspicious': '!', 'clean': 'C'}


# Malware and PUPs; and every status that flags something.
MALWARE_STATUSES = frozenset({'B', 'P'})
FLAGGED_STATUSES = frozenset({'B', 'P', '!', 'G'})

MATCH_SIBLING = 'sibling'
MATCH_NAME = 'name'
MATCH_TIMING = 'timing'
MATCH_SAME_HASH = 'same_hash'
MATCH_INSIDE = 'inside'
# A Spor SUMMARY line and the section line it sums up; a file named in a
# line's details (command line, parent, "side-loads x.dll") and the other way
# round (spor_source.py).
MATCH_SUMMARY = 'summary'
MATCH_DETAIL = 'detail'
MATCH_NAMED_BY = 'named_by'
# A task, service or Run value named like a folder of a file in the log
# (spor_self.py): the task \HealthCheck and C:\Windows\System32\HealthCheck\x.exe.
MATCH_NAMED_LIKE = 'named_like'
# The role of the mention that sums up what is said about a folder line's files.
ROLE_FILES_INSIDE = 'files inside'
# The statuses an entry found through a match may give its line (all for a
# match not listed). Informational matches give none: a host program the line
# runs something through, a detected file in the same folder, a file of the
# same name elsewhere, a line or event at the same time, a file named in the
# details of a line about this one (or the other way round). A file inside a
# folder line's folder speaks for the folder only when it is malware or a PUP.
_MATCH_STATUSES = {
    MATCH_HOST: frozenset(), MATCH_SIBLING: frozenset(), MATCH_NAME: frozenset(), MATCH_TIMING: frozenset(),
    MATCH_DETAIL: frozenset(), MATCH_NAMED_BY: frozenset(), MATCH_NAMED_LIKE: frozenset(),
    MATCH_INSIDE: MALWARE_STATUSES,
}
INFO_MATCHES = frozenset(match for match, statuses in _MATCH_STATUSES.items() if not statuses)


def worse_severity(a, b):
    """The severity letter of the two whose status letter wins (B > P > ...)."""
    by_status = {_SEVERITY_STATUS[severity]: severity for severity in (b, a) if severity in _SEVERITY_STATUS}
    worst = dominant_status(list(by_status), default='')
    return by_status.get(worst, a or b)


def entry_status(entry):
    """The worst status letter one correlation entry stands for, or '' (as
    far as its match lets it: _MATCH_STATUSES)."""
    allowed = _MATCH_STATUSES.get(entry.get('match'))
    if allowed is not None and not allowed:
        return ''
    status = finding_status(entry)
    return status if allowed is None or status in allowed else ''


def finding_status(entry):
    """The worst status letter of what an entry says (its detection
    severity, its centralbox verdict), however it was matched; ''."""
    candidates = []
    result = entry.get('centralbox')
    if isinstance(result, dict) and result.get('verdict') in _VERDICT_STATUS:
        candidates.append(_VERDICT_STATUS[result['verdict']])
    severity = _SEVERITY_STATUS.get(entry.get('severity') or '')
    if severity:
        candidates.append(severity)
    return dominant_status(candidates, default='')


def correlation_status(entries):
    """The worst status of a line's entries by the line-verdict precedence
    (B > P > C > A > ! > G > S > I > J), skipping logs from another system; ''
    when no entry has one."""
    statuses = [
        status for status in (entry_status(entry) for entry in entries if entry.get('system') != SYSTEM_DIFFERENT)
        if status
    ]
    return dominant_status(statuses, default='')


# How an entry was matched when not through the line's own file (correlation_keys).
MATCH_NOTES = {
    MATCH_ARGUMENT: 'file in command line',
    'registry': 'same registry value',
    'service': 'same service',
    'task': 'same task',
    'extension': 'same extension',
    'clsid': 'same CLSID',
    'firewall': 'same firewall rule',
    'uninstall': 'same installed program',
    'msi': 'same installed program',
    'app': 'same installed program (by name)',
    'browser': 'same browser setting',
    MATCH_HOST: 'host program',
    MATCH_SIBLING: 'detected file in same folder',
    MATCH_NAME: 'same file name elsewhere',
    MATCH_SAME_HASH: 'same file content elsewhere',
    MATCH_INSIDE: 'inside this folder',
    MATCH_TIMING: 'at the same time',
    MATCH_SUMMARY: 'summary line',
    MATCH_DETAIL: 'named in the details',
    MATCH_NAMED_BY: 'names this file in its details',
    MATCH_NAMED_LIKE: 'named like its folder',
}
# Matches whose note names the file the entry is about.
_NOTE_FILE_MATCHES = frozenset({MATCH_ARGUMENT, MATCH_SIBLING, MATCH_NAME, MATCH_SAME_HASH, MATCH_INSIDE})


def summary_note(entries, status, own_upload_id=''):
    """What the entry that gave a line its correlation status says, for the
    log page's summary box: the detection name or family, the centralbox
    verdict if any, and the log type it was found in (never log ids)."""
    for entry in entries:
        if entry.get('system') == SYSTEM_DIFFERENT or entry_status(entry) != status:
            continue
        result = entry.get('centralbox') or {}
        name = result.get('family') or result.get('malware_type') or entry.get('detection') or ''
        if entry.get('kind') == 'evidence':
            name = evidence_text(entry)
        elif entry.get('kind') == 'mention':
            name = mention_text(entry)
        elif entry.get('kind') == 'file_info' and not name:
            # (File facts with a hash row merged in keep its family or detection.)
            name = 'signature ' + entry['signature'] if entry.get('signature') else 'file details'
        verdict = result.get('verdict') or ''
        where = 'in detected folder' if entry.get('in_folder') else ''
        how = MATCH_NOTES.get(entry.get('match') or '', '')
        if entry.get('match') in _NOTE_FILE_MATCHES and entry.get('file'):
            how = f"{how}: {entry['file']}"
        source = 'Defender' if entry.get('source') == 'defender' else ''
        # An entry of the log itself (Defender events of its Addition part).
        found_in = "this log's Addition part" if own_upload_id and entry.get('upload_id') == own_upload_id \
            else entry.get('log_type', '')
        parts = [
            part for part in (name, f'centralbox: {verdict}' if verdict else '', source, how, where, found_in)
            if part
        ]
        return ' · '.join(parts) or 'finding'
    return 'finding'
