"""At the same time: created-files lines of the log within a few minutes of
a flagged one, and the related Spor logs' timeline events of that time."""

import bisect
from collections import Counter, namedtuple
from datetime import datetime, timedelta

from .. import frst_extractors as ex
from .. import spor_log
from ..file_hashes import normalized_path
from ..log_types import LOG_TYPE_SPOR
from ..machine_signals import SYSTEM_DIFFERENT
from .collector import MAX_RELATED_PER_LINE
from .entries import (
    MALWARE_STATUSES, MATCH_TIMING, _first_line_numbers, _plain_mention, correlation_status, file_name,
)


# --- At the same time: created-files lines of the log within a few minutes of
# a flagged one, and the related Spor logs' timeline events then.

TIMING_WINDOW = timedelta(minutes=2)
# More created files in one minute than this is Windows Update or an
# installer: that minute ties nothing together.
_TIMING_CROWDED_MINUTE = 25
_TIMING_SKIP_PREFIXES = ('c:\\windows\\', 'c:\\program files\\windowsapps\\')
# Scheduled task files are Windows' files written for whoever made the task.
_TIMING_KEEP_PREFIXES = ('c:\\windows\\system32\\tasks\\',)
# A created-files line flagged by its rule verdict, or by its correlations
# (which flag more lines with '!', so only malware and PUPs count there).
_TIMING_RULE_ANCHORS = frozenset({'B', 'P', '!'})
_TIMING_TIME_FORMAT = '%Y-%m-%d %H:%M'
ROLE_SAME_TIME = 'same time'

# A created / modified files line: its text, created time (to the minute),
# path key and rule status.
CreatedLine = namedtuple('CreatedLine', 'text when key status')
# A Spor TIMELINE item in the PC's local time.
TimelineEvent = namedtuple('TimelineEvent', 'when upload_id line_no item key')


def _created_line(text, key, status):
    """The CreatedLine of a created / modified files line ('____D' folder
    lines too: (CreatedLine, is folder)), or (None, False)."""
    entry = ex.extract_onemonth(text) if text[:1].isdigit() else None
    if entry is None or not entry.date:
        return None, False
    try:
        when = datetime.fromisoformat(entry.date).replace(second=0)
    except ValueError:
        return None, False
    return CreatedLine(text, when, key, status), 'd' in (entry.attributes or '').lower()


def _timed_lines(collectors):
    """The created lines worth timing: not Windows' own files (task files
    are), not in a crowded minute."""
    found = [
        collector.created for collector in collectors.values()
        if collector.created is not None and not (
            collector.created.key.startswith(_TIMING_SKIP_PREFIXES)
            and not collector.created.key.startswith(_TIMING_KEEP_PREFIXES)
        )
    ]
    per_minute = Counter(line.when for line in found)
    return [line for line in found if per_minute[line.when] <= _TIMING_CROWDED_MINUTE]


def _spor_timeline_events(upload_id, lines, known):
    """[TimelineEvent] of a Spor log's TIMELINE items in the PC's local time;
    [] when its header does not tell the time base. UTC plus the offset when
    Spor ran is FRST's own rule (FileTimeToLocalFileTime uses the offset at
    scan time, also for files from the other DST season), so the times match
    FRST's to the minute when both ran under the same offset."""
    offset = spor_log.local_offset_minutes(lines)
    if offset is None:
        return []
    events = []
    for line_no, item in spor_log.iter_timeline_items(lines, known):
        try:
            when = datetime.fromisoformat(item.time) + timedelta(minutes=offset)
        except ValueError:
            continue
        key = normalized_path(item.item) if spor_log.is_path(item.item) else ''
        events.append(TimelineEvent(when, upload_id, line_no, item, key))
    return events


def _add_timing(uploaded_log, collectors, spor_logs, verdicts):
    """Created-files lines within TIMING_WINDOW of a flagged created-files
    line (its rule status B / P / !, or correlation status B / P) get that
    line; those lines and the flagged ones get the timeline events of that
    time of the related Spor logs of this machine (`spor_logs`: (upload_id,
    lines, known paths)). Informational: never a status."""
    created = _timed_lines(collectors)
    anchors = sorted((
        line for line in created
        if line.status in _TIMING_RULE_ANCHORS or correlation_status(collectors[line.text].entries) in MALWARE_STATUSES
    ), key=lambda line: line.when)
    if not anchors:
        return
    numbers = _first_line_numbers(uploaded_log.content, {anchor.text for anchor in anchors})
    anchor_times = [anchor.when for anchor in anchors]
    clustered = {anchor.text for anchor in anchors}
    for line in created:
        low = bisect.bisect_left(anchor_times, line.when - TIMING_WINDOW)
        high = bisect.bisect_right(anchor_times, line.when + TIMING_WINDOW)
        close = sorted(
            (anchor for anchor in anchors[low:high] if anchor.text != line.text),
            key=lambda anchor: abs(anchor.when - line.when),
        )[:MAX_RELATED_PER_LINE]
        for anchor in close:
            number = numbers.get(anchor.text, 0)
            collectors[line.text].add(_plain_mention(
                uploaded_log.upload_id, uploaded_log.log_type, number, anchor.text,
                ROLE_SAME_TIME, file_name(anchor.key), time=anchor.when.strftime(_TIMING_TIME_FORMAT),
            ), MATCH_TIMING,
                # A line whose number is not found (the payload splits lines
                # differently): kept under its text, not dropped as "no line".
                slot=None if number else (ROLE_SAME_TIME, uploaded_log.upload_id, anchor.text))
            clustered.add(line.text)
    events = sorted(
        (event for upload_id, lines, known in spor_logs if verdicts.get(upload_id) != SYSTEM_DIFFERENT
         for event in _spor_timeline_events(upload_id, lines, known)),
        key=lambda event: event.when,
    )
    times = [event.when for event in events]
    for line in created:
        if line.text not in clustered:
            continue
        # FRST gives the minute only: the window runs to its last second.
        low = bisect.bisect_left(times, line.when - TIMING_WINDOW)
        high = bisect.bisect_right(times, line.when + TIMING_WINDOW + timedelta(seconds=59))
        added = 0
        for event in sorted(events[low:high], key=lambda event: abs(event.when - line.when)):
            if added >= MAX_RELATED_PER_LINE:
                break
            if event.key == line.key:
                continue  # the line's own file: matched by its path already
            item = event.item
            added += collectors[line.text].add(_plain_mention(
                event.upload_id, LOG_TYPE_SPOR, event.line_no, item.text, ROLE_SAME_TIME,
                file_name(item.item) if spor_log.is_path(item.item) else '', section=spor_log.SECTION_TIMELINE,
                time=event.when.strftime('%Y-%m-%d %H:%M:%S'), tags=item.tags, extra=[('time in log', item.time)],
            ), MATCH_TIMING)
