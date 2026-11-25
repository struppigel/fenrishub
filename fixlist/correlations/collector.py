"""Collecting the entries of one line: each related log line once.

A line can reach the same line of another log in several ways: by its own
file, by a file in its command line, by the folder it is in, as a copy or a
file of the same name, at the same time, ... The info box groups entries by
how they matched, so a line reached twice would be listed twice. LineEntries
keeps one entry per source line (its slot), under the strongest match
(MATCH_STRENGTH); the weaker routes are dropped without a note.

Entries are kept as (shared index entry, extra) pairs: a Spor log links
thousands of its lines to the same entries, so they are copied only when
the line's entries are asked for (entries / finish).
"""

from ..correlation_keys import MATCH_ARGUMENT, MATCH_HOST, MATCH_PATH, installed_program, versions_differ
from ..machine_signals import SYSTEM_UNKNOWN
from .entries import (
    INFO_MATCHES, KIND_RANK, MATCH_DETAIL, MATCH_INSIDE, MATCH_NAME, MATCH_NAMED_BY, MATCH_NAMED_LIKE, MATCH_SAME_HASH,
    MATCH_SIBLING, MATCH_SUMMARY, MATCH_TIMING, entry_status,
)


MAX_ENTRIES_PER_LINE = 60
# How many entries a line gets per informational / copy match: detected
# siblings, files of the same name, other paths with the same content, lines
# and events at the same time.
MAX_RELATED_PER_LINE = 5
# Flagged entries of the files inside a folder line listed one by one; all
# others (and any beyond) are summed up per log and kind.
MAX_INSIDE_ENTRIES = 20

# How strongly a match ties a source line to the line, strongest first. A
# match not listed is a key of the same registry value, service, task,
# installed program, extension, ... (correlation_keys): right after a file in
# the command line. In a detected or excluded folder counts as IN_FOLDER,
# whatever the match.
IN_FOLDER = 'in_folder'
_ORDER = (
    # 'uninstall' before the MSI product code of the same Uninstall entry:
    # both say "same installed program", by its key first.
    None, MATCH_ARGUMENT, 'uninstall', '*typed*', MATCH_SUMMARY, MATCH_SAME_HASH, IN_FOLDER, MATCH_INSIDE, MATCH_DETAIL,
    MATCH_NAMED_BY, MATCH_HOST, MATCH_SIBLING, MATCH_NAMED_LIKE, MATCH_NAME, MATCH_TIMING,
)
MATCH_STRENGTH = {match: rank for rank, match in enumerate(_ORDER)}


def match_strength(match, in_folder=False):
    """The rank of a match (lower is stronger; see _ORDER)."""
    if in_folder:
        return MATCH_STRENGTH[IN_FOLDER]
    return MATCH_STRENGTH.get(match, MATCH_STRENGTH['*typed*'])


def slot_of(entry):
    """The source line an entry stands for: (log, line). A hash row by the line
    of its file (its anchor), like that file's other entries."""
    return entry.get('upload_id'), entry.get('anchor_line_no') or entry.get('line_no')


def _rank(entry):
    """Sort key: status-giving entries first, then by kind."""
    return (not entry_status(entry), KIND_RANK.get(entry.get('kind'), 9))


class LineEntries:
    """The entries of one line, each source line once (see the docstring).

    `text`: the line (an Installed Programs line keeps other versions of its
    program out); `verdicts`: {upload_id: same-system verdict}, given to each
    entry as `system` (forward correlations); `own`: the slot of the line
    itself, never added (links within one log)."""

    def __init__(self, text='', verdicts=None, own=None):
        self.links = []          # [(entry, extra)]
        self._slots = {}         # slot -> position in links
        self.program = installed_program(text) if text else None
        self.verdicts = verdicts
        self.own = own
        # A created / modified files line: CreatedLine (see timing.add_timing).
        self.created = None

    def __len__(self):
        return len(self.links)

    def add(self, entry, match=None, in_folder=False, other_path='', slot=None):
        """Add `entry` (`slot`: for an entry that stands for several lines). A
        source line listed already keeps the stronger of the two matches
        (ties: the lower KIND_RANK). True only when a new line was added."""
        if match == MATCH_PATH:
            match = None
        if match == 'app' and self.program and versions_differ(self.program[1], entry.get('version')):
            return False  # another version of a program with the same name
        slot = slot or slot_of(entry)
        if slot == self.own or not slot[-1]:
            return False
        extra = {}
        if match:
            extra['match'] = match
        if in_folder:
            extra['in_folder'] = True
        if other_path:
            extra['other_path'] = other_path[:400]
        if self.verdicts is not None:
            extra['system'] = self.verdicts.get(entry.get('upload_id'), SYSTEM_UNKNOWN)
        position = self._slots.get(slot)
        if position is None:
            self._slots[slot] = len(self.links)
            self.links.append((entry, extra))
            return True
        old_entry, old_extra = self.links[position]
        new = (match_strength(match, in_folder), KIND_RANK.get(entry.get('kind'), 9))
        old = (match_strength(old_extra.get('match'), old_extra.get('in_folder')), KIND_RANK.get(old_entry.get('kind'), 9))
        if new < old:
            self.links[position] = (entry, extra)
        return False

    @property
    def entries(self):
        """The line's entries now (copies), in the order they were added."""
        return [{**entry, **extra} for entry, extra in self.links]

    def finish(self, cap=MAX_ENTRIES_PER_LINE, key=None):
        """The line's entries for the answer: sorted by `key`, else
        informational matches last; over the cap, status-giving entries first
        so the cap never drops one of those."""
        entries = self.entries
        if key is None:
            capped = len(entries) > cap
            entries.sort(key=lambda entry: (entry.get('match') in INFO_MATCHES, *(_rank(entry) if capped else ())))
        else:
            entries.sort(key=key)
        return entries[:cap]
