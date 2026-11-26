"""The other way round: which FRST / Addition lines point at a line of
another log (its page and the analyzer show them on that log's lines)."""

import logging

from ..machine_signals import SYSTEM_DIFFERENT, SYSTEM_UNKNOWN
from ..models import UploadedLog
from ..status_types import dominant_status
from .collector import MAX_ENTRIES_PER_LINE
from .entries import FLAGGED_STATUSES, INFO_MATCHES, ROLE_FILES_INSIDE
from .entries import _first_line_numbers
from .forward import _fresh_payload, cached_correlations, correlations_for_upload
from .scope import related_upload_ids

logger = logging.getLogger(__name__)


# --- The other way round: which FRST / Addition lines point at a line of
# another log (its page and the analyzer show them on that log's lines).

# What a forward entry is, in a few words, for the reverse view.
_REVERSE_WHAT = {
    'hash': 'file hash', 'detection': 'detection', 'fixlog': 'fixlist result', 'file_info': 'file details',
    'evidence': 'timeline', 'mention': 'mention',
}
# FRST line verdicts that colour a reverse marker; the others stay neutral.
REVERSE_MARKER_STATUSES = FLAGGED_STATUSES


def _reverse_what(entry):
    if entry.get('kind') == 'mention' and entry.get('role'):
        return entry['role']
    return _REVERSE_WHAT.get(entry.get('kind'), entry.get('kind') or '')


def _frst_line_facts(frst, texts):
    """{stripped line text: (first line number, rule status)} of an FRST /
    Addition log, for the texts asked. The status comes from a fresh analysis,
    the log's own rule set first ('' when there is none)."""
    wanted = set(texts)
    numbers = _first_line_numbers(frst.content, wanted)
    statuses = {}
    for line in (_fresh_payload(frst) or {}).get('lines') or ():
        if isinstance(line, dict):
            text = (line.get('line') or '').strip()
            if text in wanted and text not in statuses:
                statuses[text] = line.get('dominant_status') or ''
    return {text: (numbers.get(text, 0), statuses.get(text, '')) for text in wanted}


def reverse_correlations(uploaded_log, user=None, compute=False):
    """{scope, name, fresh, missing, lines: {line no: [entry]}, texts: {line
    no: stripped text}} for a log that is not an FRST / Addition log: the lines
    of its related FRST / Addition logs (related_upload_ids) whose
    correlations name one of its lines, under that line's number.

    Read from those logs' correlations: the stored ones only (`fresh` False
    when one of them is outdated or missing, and `missing` True when one of
    them has nothing stored at all), or computed when needed with `compute`
    (the endpoint). Each entry: kind 'reverse', the FRST log's
    upload_id / log_type, its line_no and text, its rule status
    (`line_status`), `what` this log says there, and the forward entry's
    match, in_folder and system. Never raises."""
    answer = _empty_answer()
    try:
        if uploaded_log.log_type in UploadedLog.ANALYZED_LOG_TYPES:
            return answer
        upload_ids, scope, name = related_upload_ids(uploaded_log, user)
        answer['scope'], answer['name'] = scope, name
        if not upload_ids:
            return answer
        analyzed = UploadedLog.objects.filter(
            pk__in=upload_ids, log_type__in=UploadedLog.ANALYZED_LOG_TYPES,
        ).order_by('-created_at', '-pk')
        lines = {}
        seen = set()
        own_id = uploaded_log.upload_id
        from ..rule_sets import is_rule_restricted
        hide_verdicts = is_rule_restricted(user)
        for frst in analyzed:
            if compute:
                forward, fresh = correlations_for_upload(frst, user), True
            else:
                forward, fresh = cached_correlations(frst, user)
            answer['fresh'] = answer['fresh'] and bool(fresh)
            answer['missing'] = answer['missing'] or (forward is None and not fresh)
            texts = (forward or {}).get('lines') if isinstance(forward, dict) else None
            if not isinstance(texts, dict):
                continue
            hits = {}
            for text, entries in texts.items():
                # A 'files inside' summary stands for many lines, not its first.
                found = [
                    entry for entry in entries or ()
                    if isinstance(entry, dict) and entry.get('upload_id') == own_id and entry.get('line_no')
                    and entry.get('role') != ROLE_FILES_INSIDE
                ]
                if found:
                    hits[text] = found
            if not hits:
                continue
            facts = _frst_line_facts(frst, hits)
            for text, entries in hits.items():
                frst_no, status = facts.get(text, (0, ''))
                if hide_verdicts:
                    # Another rule set's verdict; a helper training with their own rules gets none.
                    status = ''
                for entry in entries:
                    no = str(entry['line_no'])
                    slot = (no, frst.upload_id, text)
                    if slot in seen:
                        continue
                    seen.add(slot)
                    reverse = {
                        'kind': 'reverse', 'upload_id': frst.upload_id, 'log_type': frst.log_type,
                        'line_no': frst_no, 'text': text[:300], 'line_status': status,
                        'what': _reverse_what(entry), 'system': entry.get('system', SYSTEM_UNKNOWN),
                    }
                    for key in ('match', 'in_folder'):
                        if entry.get(key):
                            reverse[key] = entry[key]
                    lines.setdefault(no, []).append(reverse)
        if not lines:
            return answer
        for entries in lines.values():
            # Lines that name this one directly before the files inside a
            # folder it names, each in line order, so the cap never drops them.
            entries.sort(key=lambda entry: (bool(entry.get('in_folder')), entry['line_no'] or 0))
            del entries[MAX_ENTRIES_PER_LINE:]
        content_lines = (uploaded_log.content or '').split('\n')
        answer['lines'] = lines
        answer['texts'] = {
            no: content_lines[int(no) - 1].strip() for no in lines if 0 < int(no) <= len(content_lines)
        }
        return answer
    except Exception:
        logger.exception('Reverse correlations failed for %s', getattr(uploaded_log, 'upload_id', '?'))
        return _empty_answer()


def _empty_answer():
    return {'scope': '', 'name': '', 'fresh': True, 'missing': False, 'lines': {}, 'texts': {}}


def reverse_status(entries):
    """The marker status of a line's reverse entries: the worst FRST rule
    verdict among REVERSE_MARKER_STATUSES (logs of another system and
    informational matches left out: a flagged task says nothing about the
    wscript.exe it runs through), else ''."""
    return dominant_status([reverse_entry_status(entry) for entry in entries], default='')


def reverse_entry_status(entry):
    """The marker status one reverse entry stands for: its FRST line's rule
    verdict when that may colour the line (see reverse_status), else ''."""
    return entry.get('line_status') or '' if _reverse_rates(entry) else ''


def _reverse_rates(entry):
    return (entry.get('line_status') in REVERSE_MARKER_STATUSES and entry.get('system') != SYSTEM_DIFFERENT
            and entry.get('match') not in INFO_MATCHES)


def reverse_note(entries, status):
    """What the reverse entry that gave a line its marker status says."""
    for entry in entries:
        if entry.get('line_status') == status and _reverse_rates(entry):
            return f"{entry.get('log_type', '')} L{entry.get('line_no') or '?'}: {entry.get('text', '')[:120]}"
    return ''
