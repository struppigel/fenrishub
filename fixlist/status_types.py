"""Single source of truth for FRST classification status codes.

Each status has a code (single character used in the database), a Title-case
form label (used in admin and form choice rendering), a lowercase short label
(used in analyzer JSON output), a CSS class (for log line and badge styling),
and a precedence rank (lower = higher priority when combining matches).
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class StatusType:
    code: str
    label: str
    short_label: str
    css_class: str
    precedence: int


# Declared in form-display order. STATUS_PRECEDENCE below is derived separately
# from the `precedence` field, so reordering this tuple changes form rendering
# but not analyzer ranking.
STATUS_TYPES = (
    StatusType('B', 'Malware',              'malware',              'status-b',       0),
    StatusType('P', 'Potentially unwanted', 'potentially unwanted', 'status-p',       1),
    StatusType('C', 'Clean',                'clean',                'status-c',       2),
    StatusType('!', 'Warning',              'warning',              'status-w',       4),
    StatusType('A', 'Alert',                'alert',                'status-a',       3),
    StatusType('G', 'Grayware',             'grayware',             'status-g',       5),
    StatusType('S', 'Security software',    'security',             'status-s',       6),
    StatusType('I', 'Informational',        'informational',        'status-i',       7),
    StatusType('J', 'Junk',                 'junk',                 'status-j',       8),
    StatusType('?', 'Unknown',              'unknown',              'status-unknown', 9),
)

BY_CODE = {s.code: s for s in STATUS_TYPES}

STATUS_CHOICES = [(s.code, s.label) for s in STATUS_TYPES]
STATUS_LABELS = {s.code: s.short_label for s in STATUS_TYPES}
STATUS_CSS_CLASS = {s.code: s.css_class for s in STATUS_TYPES}
STATUS_PRECEDENCE = ''.join(
    s.code for s in sorted(STATUS_TYPES, key=lambda s: s.precedence)
)
VALID_STATUSES = frozenset(s.code for s in STATUS_TYPES)
