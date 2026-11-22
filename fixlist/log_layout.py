"""Which lines of a log the analyzer classifies, and where each one is.

The analyzer keeps one entry per non-blank line, stripped, in order. The log
page numbers lines by `content.split('\\n')` from 1 (its L<no> anchors).
`analyzed_lines` walks the text once in a way that gives both: the analyzer's
sequence of lines and, for each, the log page's line number. Everything that
pairs analysis entries with log lines walks through here, so the two can never
disagree.

Walking `split('\\n')` and then `splitlines()` within each piece gives the
same non-blank lines as `splitlines()` over the whole text: the only boundary
the two treat differently is "\\r\\n", which leaves nothing but an empty piece
behind, and empty pieces are skipped either way.

`layout` adds where each analyzed line sits, for rules whose conditions look
at a block or a section:

- a section is the part of a log after a "===== Title =====" banner (FRST,
  Addition, Spor, FRST Search). An "End of ..." banner closes its section;
  the lines after it start an untitled one, so merged logs stay apart.
- a block is one logical entry, usually a single line. Spor: an item line
  and the indented "    key: value" sub-lines under it. FRST Search: a
  file's path line and the meta line below it. Addition "Event log errors":
  an event ("Error: (...)" / "TimeCreated : ..." / "Date: ...") and the lines
  that follow it up to a blank line or the next event. A line underlined by
  "=====" (a sub-section header such as "Windows Defender:") and its
  underline are blocks of their own.

Pure functions; imports only the pure text parsers.
"""

import re
from typing import NamedTuple

from .log_types import LOG_TYPE_SPOR
from .spor_log import _is_item_line, is_path, is_sub_line
from .tool_log_facts import _FS_HEADER_RE, _FS_META_RE


class AnalyzedLine(NamedTuple):
    index: int      # position among the analyzed lines (the payload's `lines`)
    line_no: int    # 1-based number of the split('\n') line it is on
    raw: str        # the piece before stripping: indentation still there
    text: str       # the stripped line the analyzer classifies


def analyzed_lines(text):
    """Every non-blank line of `text` as an AnalyzedLine, in order.

    A split('\\n') line holding other line breaks (a lone "\\r", "\\x0c",
    "\\u2028", ...) gives several entries with the same line_no.
    """
    result = []
    for line_no, raw_line in enumerate((text or '').split('\n'), start=1):
        for piece in raw_line.splitlines():
            stripped = piece.strip()
            if stripped:
                result.append(AnalyzedLine(len(result), line_no, piece, stripped))
    return result


class Layout(NamedTuple):
    block_of: list      # analyzed-line index -> block id
    section_of: list    # analyzed-line index -> section id
    sections: list      # section id -> (title, first analyzed-line index)


# "==== Title ====" (FRST and Spor banners); Spor titles go on after " - ".
_BANNER_RE = re.compile(r'^={3,} (.+?) ={2,}\s*$')
_UNDERLINE_RE = re.compile(r'^={3,}$')
_EVENT_START_RE = re.compile(r'^(?:(?:Error|Warning|Information|Critical): \(|TimeCreated\s*:|Date: \d)')
_EVENT_SECTION_PREFIX = 'event log'

_PLAIN, _SPOR_ITEM, _EVENT, _FS_PATH = range(4)


def _banner_title(stripped):
    """The title of a section banner, or None for any other line."""
    match = _BANNER_RE.match(stripped.lstrip('﻿'))
    if not match:
        return None
    return match.group(1).split(' - ', 1)[0].strip()


def _pieces(text):
    """Every piece of the analyzed-lines walk, blank ones included: (raw, stripped)."""
    for raw_line in (text or '').split('\n'):
        for piece in raw_line.splitlines() or ['']:
            yield piece, piece.strip()


def block_members(structure):
    """The analyzed-line indexes of every block of a layout, in order: block id -> [index]."""
    members = {}
    for index, block in enumerate(structure.block_of):
        members.setdefault(block, []).append(index)
    return members


def normalize_block_text(text):
    """A block's text in the form block rules match and store: every line
    stripped, blank lines left out, joined with "\\n" (the analyzed lines of
    the block, in order)."""
    return '\n'.join(stripped for _raw, stripped in _pieces(text) if stripped)


def layout(text, log_type=None):
    """The block and section of every analyzed line of `text` (same indexes
    as analyzed_lines)."""
    pieces = list(_pieces(text))
    block_of, section_of, sections = [], [], []
    block = -1
    open_kind = _PLAIN          # what the open block can still take in
    in_event_section = False
    in_fs_files = False
    close_section = False       # the last banner was an "End of ..." one
    spor = log_type == LOG_TYPE_SPOR

    def underlined(position):
        following = pieces[position + 1][1] if position + 1 < len(pieces) else ''
        return bool(_UNDERLINE_RE.match(following))

    for position, (raw, stripped) in enumerate(pieces):
        if not stripped:
            open_kind = _PLAIN
            continue
        index = len(block_of)
        title = _banner_title(stripped)
        if title is not None:
            if title.lower().startswith('end of'):
                if not sections:
                    sections.append(('', index))
                close_section = True
            else:
                sections.append((title, index))
                close_section = False
            in_event_section = title.lower().startswith(_EVENT_SECTION_PREFIX)
            in_fs_files = False
            block += 1
            open_kind = _PLAIN
        else:
            if not sections or close_section:
                sections.append(('', index))
                close_section = False
                in_event_section = in_fs_files = False
            if _UNDERLINE_RE.match(stripped) or underlined(position):
                # A sub-section header ("Windows Defender:", "File:") or its underline.
                if _FS_HEADER_RE.match(stripped):
                    in_fs_files = stripped.startswith('File')
                block += 1
                open_kind = _PLAIN
            elif spor and open_kind == _SPOR_ITEM and is_sub_line(raw):
                pass                                    # belongs to the item above
            elif in_fs_files and open_kind == _FS_PATH and _FS_META_RE.match(stripped):
                open_kind = _PLAIN                      # the file's meta line closes it
            elif in_event_section and _EVENT_START_RE.match(stripped):
                block += 1
                open_kind = _EVENT
            elif in_event_section and open_kind == _EVENT:
                pass                                    # Description:, wrapped values
            else:
                block += 1
                if spor and _is_item_line(raw):
                    open_kind = _SPOR_ITEM
                elif in_fs_files and is_path(stripped):
                    open_kind = _FS_PATH
                else:
                    open_kind = _PLAIN
        block_of.append(block)
        section_of.append(len(sections) - 1)
    return Layout(block_of, section_of, sections)
