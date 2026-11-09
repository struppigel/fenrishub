"""Tool-aware syntax highlighting for non-FRST logs on the uploaded-log page.

`highlight_log(log_type, content)` turns a log of one of the `HIGHLIGHTERS`
types (MAU, ESET, Malwarebytes, HitmanPro, Emsisoft, AdwCleaner, Fixlog,
Shortcut, KpRm, SecurityCheck, FRST Search) into sections of tokenised lines
plus a summary of detections (or failures) for the box at the top of the page.
`render_highlighted_html()` turns that into HTML, and `compute_tool_stats()`
derives the small chips stored on UploadedLog.tool_stats for the list views.

Colour rule shared by every count (summary box, list chips): a count of 0 is
grey ('j'), so a coloured number always means something was found.

Invariant: for every line, the concatenated token texts equal the original
line, and lines are split on '\\n' exactly like the `chunk_log` filter, so the
page can rebuild the byte-identical log for copy / download.

Patterns are written against real logs. They stay simple and linear (no
nested ambiguous quantifiers) because they run on every line of user-supplied
text.
"""

import logging
import re
from dataclasses import dataclass, field
from html import escape as html_escape

from django.utils.safestring import mark_safe

logger = logging.getLogger(__name__)

LINES_PER_CHUNK = 100
SUMMARY_LIMIT = 200
# Highlighted HTML is roughly 3x the log size; huge logs (one Fixlog in the
# data is 44 MB) keep the plain chunked view instead.
MAX_HIGHLIGHT_CHARS = 3_000_000


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Line:
    no: int
    tokens: list  # list of (css_class, text); '' class means plain text
    # FRST types only: the analyzer's rule status letter (B, P, C, !, ...) and
    # the colour class it paints the line with ('b', 'p', 'w', ...).
    status: str = ''
    paint: str = ''

    @property
    def text(self):
        return ''.join(t for _, t in self.tokens)


@dataclass
class Section:
    header: 'Line | None'
    lines: list = field(default_factory=list)


@dataclass
class SummaryItem:
    line_no: int
    severity: str  # b / p / g / w / c / j / i
    name: str
    target: str = ''
    action: str = ''


@dataclass
class Stat:
    label: str
    value: str
    severity: str = ''

    def __post_init__(self):
        # A zero count is always grey, whatever colour it would have otherwise.
        digits = re.sub(r'[^\d]', '', str(self.value))
        if digits and int(digits) == 0:
            self.severity = 'j'


@dataclass
class HighlightResult:
    sections: list
    summary: list
    summary_title: str = ''
    stats: list = field(default_factory=list)

    @property
    def summary_shown(self):
        return self.summary[:SUMMARY_LIMIT]

    @property
    def summary_hidden_count(self):
        return max(0, len(self.summary) - SUMMARY_LIMIT)

    @property
    def has_summary(self):
        return bool(self.summary or self.stats)

    @property
    def summary_line_ch(self):
        """Width in `ch` of the summary's "L<n>" labels: as wide as the longest."""
        shown = self.summary_shown
        return 1 + len(str(max((item.line_no for item in shown), default=1)))

    @property
    def has_sections(self):
        return any(section.header is not None for section in self.sections)

    @property
    def has_status(self):
        """True when FRST rule statuses were applied (the gutter shows letters)."""
        return any(line.status for line in iter_lines(self))

    @property
    def gutter_ch(self):
        """Width of the line-number gutter in `ch`: the longest line number,
        plus room for the status letter when there are statuses."""
        last = 0
        for section in self.sections:
            if section.lines:
                last = max(last, section.lines[-1].no)
            elif section.header is not None:
                last = max(last, section.header.no)
        return len(str(last or 1)) + (2 if self.has_status else 0)


class _Builder:
    """Collects lines into sections and summary items."""

    def __init__(self, title=''):
        self.sections = [Section(None)]
        self.summary = []
        self.stats = []
        self.title = title

    def add(self, line):
        self.sections[-1].lines.append(line)

    def header(self, line):
        self.sections.append(Section(line))

    def end_section(self):
        """Following lines are no longer part of the current header's block."""
        self.sections.append(Section(None))

    def item(self, *args, **kwargs):
        item = SummaryItem(*args, **kwargs)
        self.summary.append(item)
        return item

    def result(self):
        sections = [s for s in self.sections if s.header is not None or s.lines]
        return HighlightResult(sections, self.summary, self.title, self.stats)


# ---------------------------------------------------------------------------
# Shared tokenizers
# ---------------------------------------------------------------------------

_INLINE_RE = re.compile(
    r'(?P<url>\bhttps?://[^\s"\'<>()]+)'
    r'|(?P<guid>\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})'
    r'|(?P<hash>\b(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})\b)'
    # A drive letter may follow "_" (Defender prints "file:_C:\..."), but not
    # another letter or digit ("ABC:\" is no path).
    r'|(?P<path>(?<![A-Za-z0-9\\])[A-Za-z]:\\|\\\\[?.]\\'
    r'|(?<![A-Za-z0-9\\])(?:HKLM|HKCU|HKU|HKCR|HKCC|HKEY_[A-Z_]+)(?=\\|$))'
)
# Where a path that started mid-line ends:
# - "->", "=>" and " <": '>' and '<' can't be in Windows file names, so this
#   covers FRST "x.exe ->)", Defender archive members "a.ipa->Payload/..." and
#   "<==== ATTENTION";
# - "; " / ";" at the end: Defender separates resources with "; ";
# - a " (...)" group only when it isn't followed by "\": "Program Files (x86)\..."
#   and "New folder (2)\..." are part of the path, "C:\x.exe (Company)" is not.
_PATH_STOP_RE = re.compile(r' ?->| ?=>| <|\t|"|, |;(?=\s|$)| \((?!x86\))(?![^()\\]*\)\\)| \[|$')

_CLASS_FOR_KIND = {'url': 'hl-url', 'guid': 'hl-guid', 'hash': 'hl-hash'}


def _inline(text, base=''):
    """Tokenize free text: paths, registry keys, GUIDs, URLs, hashes."""
    out = []
    pos = 0
    while True:
        m = _INLINE_RE.search(text, pos)
        if not m:
            break
        kind = m.lastgroup
        start = m.start()
        if kind == 'path':
            end = _PATH_STOP_RE.search(text, m.end()).start()
            while end > m.end() and text[end - 1] == ' ':
                end -= 1
            end = max(end, m.end())
            cls = 'hl-reg' if text[start] in 'Hh' else 'hl-path'
        else:
            end = m.end()
            cls = _CLASS_FOR_KIND[kind]
        if start > pos:
            out.append((base, text[pos:start]))
        out.append((cls, text[start:end]))
        pos = end
    if pos < len(text):
        out.append((base, text[pos:]))
    return out


_PATH_START_RE = re.compile(r'(?:[A-Za-z]:\\|\\\\)')
_REG_START_RE = re.compile(r'(?:HKLM|HKCU|HKU|HKCR|HKCC|HKEY_)', re.I)


def _target(text):
    """Tokenize a field known to be a path / registry key / other target."""
    stripped = text.strip()
    if not stripped:
        return [('', text)] if text else []
    if ' -> ' in stripped or ' => ' in stripped:
        # "C:\a.lnk -> C:\b.exe": tokenize each side so a click copies one path.
        return _inline(text)
    if _PATH_START_RE.match(stripped):
        cls = 'hl-path'
    elif _REG_START_RE.match(stripped):
        cls = 'hl-reg'
    else:
        return _inline(text)
    lead = text[:len(text) - len(text.lstrip())]
    trail = text[len(text.rstrip()):]
    out = []
    if lead:
        out.append(('', lead))
    out.append((cls, stripped))
    if trail:
        out.append(('', trail))
    return out


def _split_cr(raw):
    if raw.endswith('\r'):
        return raw[:-1], '\r'
    return raw, ''


def _mk(no, tokens, cr=''):
    tokens = [t for t in tokens if t[1]]
    if cr:
        tokens.append(('', cr))
    return Line(no, tokens)


_COLON_KV_RE = re.compile(r'^(\s*)([^:\t]{1,60}?:)(\s.*|)$')


def _kv_colon(text, value_cls=''):
    """`Key: value` -> key dimmed, value tokenized."""
    m = _COLON_KV_RE.match(text)
    if not m:
        return None
    lead, key, value = m.groups()
    return [('', lead), ('hl-key', key)] + _value_tokens(value, value_cls)


def _value_tokens(value, cls=''):
    if cls:
        return [(cls, value)]
    return _inline(value)


_SUCCESS_ACTION_RE = re.compile(
    r'quarant|removed|deleted|clean|cuarentena|eliminad|gel[öo]scht|gesäubert|supprim|nettoy'
    r'|verwijder|usuni|rimoss|limpi|excluído|excluido|quarentena',
    re.I,
)
_FAIL_ACTION_RE = re.compile(r'unable|not |no action|sin acciones|failed|error|denied|nicht|impossible', re.I)


def _action_severity(action):
    if _FAIL_ACTION_RE.search(action):
        return 'w'
    if _SUCCESS_ACTION_RE.search(action):
        return 'c'
    return 'w'


def threat_severity(name):
    """Map a detection name to a status letter: b (malware), p (PUP), g (gray)."""
    lower = (name or '').lower()
    if 'potentially unwanted' in lower:
        return 'p'
    if ('potentially unsafe' in lower or 'suspicious' in lower or lower.startswith('pum.')
            or 'hacktool' in lower or 'riskware' in lower):
        return 'g'
    if (lower.startswith(('pup.', 'adware', 'application.')) or '.application.' in lower
            or 'adware' in lower):
        return 'p'
    return 'b'


def _count_sev(value, sev='b'):
    digits = re.sub(r'[^\d]', '', value)
    if digits and int(digits) > 0:
        return sev
    return 'j'


_TIMESTAMP_RE = re.compile(r'^\[\d{1,2}:\d{2}:\d{2}\] ')


# ---------------------------------------------------------------------------
# ESET
# ---------------------------------------------------------------------------

def _highlight_eset(lines):
    b = _Builder('ESET detections')
    for i, raw in enumerate(lines):
        no = i + 1
        body, cr = _split_cr(raw)
        if '\t' in body:
            parts = body.split('\t')
            path, threat = parts[0], parts[1]
            action = '\t'.join(parts[2:])
            sev = threat_severity(threat)
            tokens = _target(path) + [('', '\t'), ('hl-sev-' + sev, threat)]
            if len(parts) > 2:
                acls = ('hl-sev-' + _action_severity(action)) if action.strip() else ''
                tokens += [('', '\t'), (acls, action)]
            b.add(_mk(no, tokens, cr))
            b.item(no, sev, threat, path, action)
            continue
        if i == 0 and re.match(r'^[\d/.\-: ]+(?:[AP]M)?\s*$', body):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        m = re.match(r'^(.*?)(:?\s)(\d+)(\s*)$', body)
        if m and m.group(1) and not re.search(r'\d', m.group(1)):
            key, sep, value, trail = m.groups()
            sev = ''
            if re.search(r'detect|erkannt|détect|detectad|gevonden|rilevat', key, re.I):
                sev = 'hl-sev-' + _count_sev(value)
                b.stats.append(Stat(key, value, _count_sev(value)))
            b.add(_mk(no, [('hl-key', key + sep), (sev or 'hl-value', value), ('', trail)], cr))
            continue
        kv = _kv_colon(body)
        b.add(_mk(no, kv if kv else _inline(body), cr))
    return b.result()


# ---------------------------------------------------------------------------
# Malwarebytes
# ---------------------------------------------------------------------------

_MB_DETECTION_RE = re.compile(
    r'^(?P<name>[^,]+), (?P<target>.+?), (?P<action>[^,]+), (?P<rest>\d+, \d+, [\d.]+, .*)$'
)
_MB_HEADER_RE = re.compile(r'^-[^-].*-$')
_MB_CATEGORY_RE = re.compile(r'^([^,:]+:) (\d+)$')


def _highlight_malwarebytes(lines):
    b = _Builder('Malwarebytes detections')
    for i, raw in enumerate(lines):
        no = i + 1
        body, cr = _split_cr(raw)
        if i < 2 and body.strip():
            b.add(_mk(no, [('hl-title' if i == 0 else 'hl-dim', body)], cr))
            continue
        if _MB_HEADER_RE.match(body):
            b.header(_mk(no, [('hl-header', body)], cr))
            continue
        m = _MB_DETECTION_RE.match(body)
        if m:
            name, target, action, rest = m.group('name', 'target', 'action', 'rest')
            sev = threat_severity(name)
            tokens = ([('hl-sev-' + sev, name), ('hl-dim', ', ')] + _target(target)
                      + [('hl-dim', ', '), ('hl-sev-' + _action_severity(action), action)]
                      + _inline(', ' + rest, 'hl-dim'))
            b.add(_mk(no, tokens, cr))
            b.item(no, sev, name, target, action)
            continue
        m = _MB_CATEGORY_RE.match(body)
        if m and _next_is_mb_detail(lines, i):
            key, count = m.groups()
            b.add(_mk(no, [('hl-subheader', key + ' '), ('hl-sev-' + _count_sev(count), count)], cr))
            continue
        stripped = body.strip()
        if stripped.startswith('(') and stripped.endswith(')'):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        kv = _kv_colon(body)
        if kv:
            key = kv[1][1]
            value = body[len(kv[0][1]) + len(key):]
            if re.search(r'threats detected|amenazas detectadas|bedrohungen erkannt|menaces détectées', key, re.I):
                sev = _count_sev(value)
                b.stats.append(Stat(key.rstrip(':'), value.strip(), sev))
                kv = [kv[0], ('hl-key', key), ('hl-sev-' + sev, value)]
            b.add(_mk(no, kv, cr))
            continue
        b.add(_mk(no, _inline(body), cr))
    return b.result()


def _next_is_mb_detail(lines, i):
    for raw in lines[i + 1:i + 2]:
        nxt = raw.strip()
        return nxt.startswith('(') or bool(_MB_DETECTION_RE.match(nxt))
    return False


# ---------------------------------------------------------------------------
# HitmanPro
# ---------------------------------------------------------------------------

_HMP_SECTION_RE = re.compile(r'^(\S.*?) _{5,}\s*$')
_HMP_DOTTED_RE = re.compile(r'^( +)(> )?(\S.*?)((?: +\.)+ *:|  +:)(.*)$')
_HMP_FORENSIC_RE = re.compile(r'^ {6,}-?\d+(?:\.\d+)?s ')


def _hmp_section_severity(title):
    lower = title.lower()
    if 'malware' in lower:
        return 'b'
    if 'pup' in lower or 'potentially' in lower or 'adware' in lower:
        return 'p'
    if 'suspicious' in lower:
        return 'g'
    if 'trace' in lower or 'cookie' in lower or 'remnant' in lower:
        return 'j'
    return 'w'


def _highlight_hitmanpro(lines):
    b = _Builder('HitmanPro findings')
    section_title = ''
    section_sev = ''
    current_item = None
    for i, raw in enumerate(lines):
        no = i + 1
        body, cr = _split_cr(raw)
        stripped = body.strip()
        if stripped in ('[code]', '[/code]'):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        if re.match(r'^HitmanPro \d', body):
            b.add(_mk(no, [('hl-title', body)], cr))
            continue
        if re.match(r'^www\.', body):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        m = _HMP_SECTION_RE.match(body)
        if m:
            section_title = m.group(1)
            section_sev = _hmp_section_severity(section_title)
            current_item = None
            b.header(_mk(no, [('hl-header hl-sev-' + section_sev, section_title),
                              ('hl-dim', body[len(section_title):])], cr))
            continue
        if section_title and re.match(r'^   \S', body):
            current_item = b.item(no, section_sev, section_title, stripped)
            entry_cls = 'hl-entry hl-sev-' + section_sev
            if _PATH_START_RE.match(stripped) or _REG_START_RE.match(stripped):
                entry_cls = 'hl-entry hl-path hl-sev-' + section_sev
            b.add(_mk(no, [('', body[:3]), (entry_cls, body[3:])], cr))
            continue
        m = _HMP_DOTTED_RE.match(body)
        if m:
            lead, marker, key, sep, value = m.groups()
            tokens = [('', lead)]
            if marker:
                tokens.append(('hl-accent', marker))
                tokens += [('hl-key', key + sep), ('hl-sev-' + (section_sev or 'b'), value)]
                if current_item is not None:
                    current_item.name = value.strip()
                    current_item.action = key.strip()
            else:
                tokens.append(('hl-key', key + sep))
                key_l = key.strip().lower()
                if key_l in ('threats', 'traces') and not section_title:
                    sev = _count_sev(value, 'b' if key_l == 'threats' else 'w')
                    tokens.append(('hl-sev-' + sev, value))
                    b.stats.append(Stat(key.strip(), value.strip(), sev))
                elif key_l == 'authenticode' and 'invalid' in value.lower():
                    tokens.append(('hl-sev-w', value))
                else:
                    tokens += _inline(value)
            b.add(_mk(no, tokens, cr))
            continue
        if _HMP_FORENSIC_RE.match(body):
            b.add(_mk(no, _inline(body, 'hl-dim'), cr))
            continue
        if re.match(r'^ {9}\S', body):
            b.add(_mk(no, _inline(body, 'hl-note'), cr))
            continue
        if re.match(r'^ {6}\S', body):
            b.add(_mk(no, [('hl-subheader', body)], cr))
            continue
        b.add(_mk(no, _inline(body), cr))
    return b.result()


# ---------------------------------------------------------------------------
# AdwCleaner
# ---------------------------------------------------------------------------

_ADW_SECTION_RE = re.compile(r'^\*{5} \[ (.+) \] \*{5}\s*$')
_ADW_ENTRY_RE = re.compile(r'^(Not Deleted|\S+)( {2,})(\S.*)$')


def _highlight_adwcleaner(lines):
    b = _Builder('AdwCleaner detections')
    clean_mode = False
    for i, raw in enumerate(lines):
        no = i + 1
        body, cr = _split_cr(raw)
        if body.startswith('#'):
            if re.match(r'^# Mode:\s*Clean', body):
                clean_mode = True
                b.title = 'AdwCleaner failures'
            m = re.match(r'^(#\s*)(Detected|Failed|Cleaned):(\s*)(\d+)', body)
            if m:
                prefix, key, space, value = m.groups()
                sev = _count_sev(value, {'Cleaned': 'c', 'Detected': 'b'}.get(key, 'w'))
                b.stats.append(Stat(key, value, sev))
                b.add(_mk(no, [('hl-dim', prefix), ('hl-key', key + ':' + space),
                               ('hl-sev-' + sev, body[m.end(3):])], cr))
                continue
            if re.match(r'^# Malwarebytes AdwCleaner', body):
                b.add(_mk(no, [('hl-title', body)], cr))
                continue
            b.add(_mk(no, _inline(body, 'hl-dim'), cr))
            continue
        m = _ADW_SECTION_RE.match(body)
        if m:
            b.header(_mk(no, [('hl-header', body)], cr))
            continue
        if re.match(r'^\*+\s*$', body):
            b.end_section()
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        if re.match(r'^No .*\.\s*$', body) or body.startswith('#####'):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        if body.startswith('[+]') or body.startswith('[-]'):
            b.add(_mk(no, [('hl-accent', body[:3])] + _inline(body[3:]), cr))
            continue
        if re.match(r'^AdwCleaner\[', body):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        m = _ADW_ENTRY_RE.match(body)
        if m:
            name, gap, target = m.groups()
            if name == 'Deleted':
                sev = 'c'
            elif name == 'Not Deleted':
                sev = 'w'
            else:
                sev = threat_severity(name)
            b.add(_mk(no, [('hl-sev-' + sev, name), ('', gap)] + _target(target), cr))
            # Scan mode lists every detection; clean mode only what failed.
            if not clean_mode or sev == 'w':
                b.item(no, sev, name, target.strip())
            continue
        b.add(_mk(no, _inline(body), cr))
    return b.result()


# ---------------------------------------------------------------------------
# Emsisoft
# ---------------------------------------------------------------------------

_EMSI_DETECTION_RE = re.compile(r'^(\S+?:) (.+?)( \(\w\))?( \[[^\]]*\])?\s*$')


def _highlight_emsisoft(lines):
    b = _Builder('Emsisoft detections')
    for i, raw in enumerate(lines):
        no = i + 1
        body, cr = _split_cr(raw)
        if i == 0 and body.startswith('Emsisoft'):
            b.add(_mk(no, [('hl-title', body)], cr))
            continue
        if '\t' in body:
            left, right = body.split('\t', 1)
            m = _EMSI_DETECTION_RE.match(right)
            if m and ('\\' in left or ':' in left.rstrip(':')):
                label, name = m.group(1, 2)
                sev = threat_severity(name)
                tokens = _target(left) + [('', '\t'), ('hl-dim', label + ' '), ('hl-sev-' + sev, name),
                                          ('hl-dim', right[m.end(2):])]
                b.add(_mk(no, tokens, cr))
                b.item(no, sev, name, left.strip())
                continue
            key = left
            if re.match(r'^\s*(Found|Gefunden|Trouvé|Encontrado)\s*$', key):
                sev = _count_sev(right)
                b.stats.append(Stat(key.strip(), right.strip(), sev))
                b.add(_mk(no, [('hl-key', key + '\t'), ('hl-sev-' + sev, right)], cr))
                continue
            b.add(_mk(no, [('hl-key', key + '\t')] + _inline(right), cr))
            continue
        if re.match(r'^Scanning .*\.\.\.\s*$', body):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        if re.match(r'^\S[^:]*:\s*$', body):
            b.add(_mk(no, [('hl-subheader', body)], cr))
            continue
        kv = _kv_colon(body)
        b.add(_mk(no, kv if kv else _inline(body), cr))
    return b.result()


# ---------------------------------------------------------------------------
# MAU (Malicious App Uninstaller) - banner report and timestamped console form
# ---------------------------------------------------------------------------

_MAU_DASH_RE = re.compile(r'^-{20,}\s*$')
_MAU_CONSOLE_SECTION_RE = re.compile(r'^\d{1,2}\. [A-Z][A-Z0-9 /&()-]*$')
_MAU_COUNTS_RE = re.compile(r'Deleted=(\d+) Scheduled=(\d+) Failed=(\d+)')
_MAU_ANALYZING_RE = re.compile(r'^Analyzing (\{[0-9A-Fa-f-]+\}|.+?)\.\.\.\s*$')
_MAU_TAG_RE = re.compile(r'^(\s*)(\[(?:RegValue|RegKey|File|Dir|Directory|Service|Task)\]|EXISTS|MISSING)( )(.*)$')
_MAU_DELETED_RE = re.compile(r'^(\s*)(Deleted [a-z ]+:)( )(.*)$')
_MAU_PROBLEM_RE = re.compile(r'\b(fail(?:ed|ure)?|error|access (?:is )?denied|could not|cannot|unable|scheduled)\b', re.I)
_MAU_KV_EQ_RE = re.compile(r'^(\s+)([A-Za-z_][\w.]*)(=)(.*)$')
_MAU_RESOLVED_RE = re.compile(r'^(RESOLVED:)( )([A-Za-z_][\w]*)(=)(.*)$')
_MAU_DIM_VALUE_RE = re.compile(r'^\s*(<[^>]*>|skipped|Skipped)\s*$')


def _highlight_mau(lines):
    b = _Builder('MAU removal')
    products = {}
    current = None
    traces = None
    counts = None
    n = len(lines)
    for i, raw in enumerate(lines):
        no = i + 1
        full, cr = _split_cr(raw)
        ts = _TIMESTAMP_RE.match(full)
        prefix = [('hl-dim', ts.group(0))] if ts else []
        body = full[ts.end():] if ts else full

        def emit(tokens, header=False):
            line = _mk(no, prefix + tokens, cr)
            if header:
                b.header(line)
            else:
                b.add(line)

        stripped = body.strip()
        if re.match(r'^=+ .* =+\s*$', body) or (ts and i == 0):
            emit([('hl-title', body)])
            continue
        m = _MAU_ANALYZING_RE.match(body)
        if m:
            ident = m.group(1)
            current = products.get(ident)
            if current is None:
                current = b.item(no, 'i', ident, ident, '')
                products[ident] = current
            emit([('hl-header hl-product', 'Analyzing '), ('hl-guid', ident),
                  ('hl-header hl-product', body[m.end(1):])], header=True)
            continue
        if _MAU_DASH_RE.match(body):
            emit([('hl-dim', body)])
            continue
        # Banner title: a non-blank line between two dash lines.
        if (i > 0 and _MAU_DASH_RE.match(_split_cr(lines[i - 1])[0])
                and i + 1 < n and _MAU_DASH_RE.match(_split_cr(lines[i + 1])[0]) and stripped):
            emit([('hl-header', body)], header=True)
            continue
        if _MAU_CONSOLE_SECTION_RE.match(body):
            emit([('hl-header', body)], header=True)
            continue
        m = _MAU_COUNTS_RE.search(body)
        if m:
            deleted, scheduled, failed = (int(x) for x in m.groups())
            counts = (deleted, scheduled, failed)
            tokens = [('hl-key', body[:m.start()])]
            tokens += [('hl-sev-' + ('c' if deleted else 'j'), 'Deleted=' + m.group(1)), ('', ' '),
                       ('hl-sev-' + ('w' if scheduled else 'j'), 'Scheduled=' + m.group(2)), ('', ' '),
                       ('hl-sev-' + ('b' if failed else 'j'), 'Failed=' + m.group(3)),
                       ('', body[m.end():])]
            emit(tokens)
            continue
        m = re.match(r'^(Found:? )(\d+)( traces?(?:\(s\))?\.?)\s*$', stripped)
        if m and not body.startswith(' '):
            traces = m.group(2)
        m = _MAU_RESOLVED_RE.match(body)
        if m:
            label, space, key, eq, value = m.groups()
            vcls = 'hl-dim' if _MAU_DIM_VALUE_RE.match(value) or not value else 'hl-value-strong'
            emit([('hl-accent', label), ('', space), ('hl-key', key + eq)]
                 + ([(vcls, value)] if vcls == 'hl-dim' else _inline(value, vcls)))
            if current is not None and value and vcls != 'hl-dim':
                _mau_note_product(current, key, value)
            continue
        m = re.match(r'^(\s+)(Resolved|Publisher)(: )(.*)$', body)
        if m and current is not None:
            lead, key, sep, value = m.groups()
            _mau_note_product(current, 'DisplayName' if key == 'Resolved' else 'Publisher', value)
            emit([('', lead), ('hl-key', key + sep), ('hl-value-strong', value)])
            continue
        m = _MAU_TAG_RE.match(body)
        if m:
            lead, tag, space, rest = m.groups()
            emit([('', lead), ('hl-accent', tag), ('', space)] + _target(rest))
            continue
        m = _MAU_DELETED_RE.match(body)
        if m:
            lead, label, space, rest = m.groups()
            emit([('', lead), ('hl-sev-c', label), ('', space)] + _target(rest))
            continue
        if re.match(r'^\[[A-Za-z]+\]\s*$', body):
            emit([('hl-subheader', body)])
            continue
        if re.match(r'^(Deleted items|Selected(?: traces)?|Cached MSI|Removal started|Removal finished)', body):
            emit([('hl-subheader', body)])
            continue
        if _MAU_DIM_VALUE_RE.match(body) or re.search(r'\bskipped\b|\bhits: 0\b', body, re.I):
            emit([('hl-dim', body)])
            continue
        m = _MAU_KV_EQ_RE.match(body)
        if m:
            lead, key, eq, value = m.groups()
            emit([('', lead), ('hl-key', key + eq)]
                 + ([('hl-dim', value)] if _MAU_DIM_VALUE_RE.match(value) else _inline(value)))
            continue
        # Checked after the Key=Value form so MSI property values can't trigger it.
        if _MAU_PROBLEM_RE.search(body) and not re.match(r'^\s*Selected', body):
            scheduled_only = (re.search(r'schedul', body, re.I)
                              and not re.search(r'fail|error|denied|could not|cannot|unable', body, re.I))
            sev = 'w' if scheduled_only else 'b'
            emit(_inline(body, 'hl-sev-' + sev))
            b.item(no, sev, stripped, '', 'scheduled' if sev == 'w' else 'failed')
            continue
        kv = _kv_colon(body)
        emit(kv if kv else _inline(body))

    # Products first, then any failures, in log order.
    b.summary.sort(key=lambda item: (item.severity not in ('i',), item.line_no))
    if traces is not None:
        b.stats.append(Stat('Traces found', traces, 'w'))
    if counts is not None:
        deleted, scheduled, failed = counts
        b.stats.append(Stat('Deleted', str(deleted), 'c'))
        b.stats.append(Stat('Scheduled', str(scheduled), 'w'))
        b.stats.append(Stat('Failed', str(failed), 'b'))
    return b.result()


def _mau_note_product(item, key, value):
    value = value.strip()
    if not value or value.startswith('<'):
        return
    if key == 'DisplayName' and item.name == item.target:
        item.name = value
    elif key == 'Publisher' and not item.action:
        item.action = value


# ---------------------------------------------------------------------------
# Fixlog
# ---------------------------------------------------------------------------

_FIX_BANNER_RE = re.compile(r'^(=+ )(.+?)( =+)\s*$')
_FIX_RULE_RE = re.compile(r'^(?:=+|\*+)\s*$')
_FIX_STARS_RE = re.compile(r'^\*{5,}\s*$')
_FIX_SCHEDULED_RE = re.compile(r'schedul', re.I)
_FIX_MOVE_HEADER_RE = re.compile(r'^"[^"]*" (?:Folder|File) move:\s*$')
_FIX_DIRECTIVE_RE = re.compile(r'^([A-Za-z][A-Za-z0-9]+::?)(.*)$')
_FIX_FAIL_RE = re.compile(r'\b(could not|cannot|can\'t|access (?:is )?denied|error|failed|unable)\b', re.I)
_FIX_PS_ERROR_RE = re.compile(r'^(?:\s*\+ (?:CategoryInfo|FullyQualifiedErrorId)|.*\bException\b)')


def _fixlog_result_severity(subject, status):
    """Same buckets as UploadedLog._compute_fixlog_stats, plus failure wording."""
    if 'successfully' in status:
        return 'c'
    if 'not found' in status:
        return 'w'
    if 'Error' in status or _FIX_FAIL_RE.search(status) or _FIX_FAIL_RE.search(subject):
        return 'b'
    if _FIX_SCHEDULED_RE.search(status):
        return 'w'
    if 'No running process' in status:
        return 'j'
    return ''


def _highlight_fixlog(lines):
    b = _Builder('Fixlog failures')
    in_fixlist = False
    fixlist_stars = 0  # the echoed fixlist sits between two '*****' lines
    ps_block = None  # title of the current command output block
    ps_reported = False
    for i, raw in enumerate(lines):
        no = i + 1
        body, cr = _split_cr(raw)
        stripped = body.strip()
        if i == 0 and body.startswith('Fix result'):
            b.add(_mk(no, [('hl-title', body)], cr))
            continue
        if re.match(r'^fixlist content:\s*$', body, re.I):
            in_fixlist = True
            b.header(_mk(no, [('hl-header', body)], cr))
            continue
        if in_fixlist:
            if _FIX_STARS_RE.match(body):
                b.add(_mk(no, [('hl-dim', body)], cr))
                fixlist_stars += 1
                if fixlist_stars >= 2:
                    in_fixlist = False
                    b.end_section()
                continue
            tokens = []
            m = _FIX_DIRECTIVE_RE.match(body)
            rest = body
            if m:
                tokens.append(('hl-accent', m.group(1)))
                rest = m.group(2)
            att = rest.find('<====')
            if att != -1:
                tokens += _inline(rest[:att]) + [('hl-sev-w', rest[att:])]
            else:
                tokens += _inline(rest)
            b.add(_mk(no, tokens, cr))
            continue
        if _FIX_RULE_RE.match(body):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        m = _FIX_BANNER_RE.match(body) if body.startswith('=') else None
        if m:
            title = m.group(2)
            if title.startswith('End of'):
                b.add(_mk(no, [('hl-dim', body)], cr))
                b.end_section()
                ps_block = None
            else:
                b.header(_mk(no, [('hl-dim', m.group(1)), ('hl-header', title), ('hl-dim', body[m.end(2):])], cr))
                ps_block = title
                ps_reported = False
            continue
        idx = body.find(' => ')
        if idx != -1:
            status = body[idx + 4:]
            sev = _fixlog_result_severity(body[:idx], status)
            tokens = _target(body[:idx]) + [('hl-dim', ' => '), (('hl-sev-' + sev) if sev else '', status)]
            b.add(_mk(no, tokens, cr))
            if sev in ('w', 'b'):
                b.item(no, sev, status.strip(), body[:idx].strip().strip('"'))
            continue
        if ps_block is not None and _FIX_PS_ERROR_RE.match(body):
            b.add(_mk(no, _inline(body, 'hl-sev-b'), cr))
            if not ps_reported:
                ps_reported = True
                b.item(no, 'b', 'PowerShell error', ps_block[:120], stripped[:160])
            continue
        if 'successfully' in body:
            b.add(_mk(no, _inline(body, 'hl-sev-c'), cr))
            continue
        if ps_block is None and _FIX_FAIL_RE.search(body):
            b.add(_mk(no, _inline(body, 'hl-sev-b'), cr))
            b.item(no, 'b', stripped[:160])
            continue
        if _FIX_MOVE_HEADER_RE.match(body):
            b.add(_mk(no, _inline(body, 'hl-subheader'), cr))
            continue
        if i < 6:
            kv = _kv_colon(body)
            if kv:
                b.add(_mk(no, kv, cr))
                continue
        b.add(_mk(no, _inline(body), cr))
    return b.result()


# ---------------------------------------------------------------------------
# Shortcut
# ---------------------------------------------------------------------------

_SC_ENTRY_RE = re.compile(r'^([A-Za-z]+:)( )(.*)$')


def _highlight_shortcut(lines):
    b = _Builder('')
    for i, raw in enumerate(lines):
        no = i + 1
        body, cr = _split_cr(raw)
        if i == 0:
            b.add(_mk(no, [('hl-title', body)], cr))
            continue
        m = _FIX_BANNER_RE.match(body)
        if m:
            b.header(_mk(no, [('hl-dim', m.group(1)), ('hl-header', m.group(2)), ('hl-dim', body[m.end(2):])], cr))
            continue
        stripped = body.strip()
        if stripped.startswith('(') and stripped.endswith(')'):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        if re.match(r'^=+\s*$', body):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        m = _SC_ENTRY_RE.match(body)
        if m and ' -> ' in body:
            label, space, rest = m.groups()
            lnk, target = rest.split(' -> ', 1)
            company_tokens = []
            if target.endswith(')') and ' (' in target:
                cut = target.rfind(' (')
                company = target[cut + 2:-1]
                target, company_part = target[:cut], target[cut:]
                if company in ('', 'No File'):
                    company_tokens = [('hl-sev-w', company_part)]
                else:
                    company_tokens = [('hl-dim', ' ('), ('hl-company', company), ('hl-dim', ')')]
            tokens =([('hl-accent', label), ('', space)] + _target(lnk) + [('hl-dim', ' -> ')]
                      + _target(target) + company_tokens)
            b.add(_mk(no, tokens, cr))
            continue
        if i < 5:
            kv = _kv_colon(body)
            if kv:
                b.add(_mk(no, kv, cr))
                continue
        b.add(_mk(no, _inline(body), cr))
    return b.result()


# ---------------------------------------------------------------------------
# KpRm
# ---------------------------------------------------------------------------

_KP_RULE_RE = re.compile(r'^(?:=+|-{20,})\s*$')
_KP_ITEM_RE = re.compile(r'^(\s+)(\[[A-Z ]+\])(\s+)(.+?)(\s+\(\w+\))?\s*$')
_KP_COUNT_RE = re.compile(r'^(\s+)(\S.*?)(\s*:\s*)(\d+)(\s*)$')


def _kprm_count_severity(label, value):
    lower = label.lower()
    count = int(value)
    if count == 0:
        return 'j'
    if 'fail' in lower:
        return 'b'
    if 'schedul' in lower:
        return 'w'
    if 'removed' in lower:
        return 'c'
    return 'j'


def _highlight_kprm(lines):
    b = _Builder('KpRm')
    section = ''
    n = len(lines)
    for i, raw in enumerate(lines):
        no = i + 1
        body, cr = _split_cr(raw)
        if _KP_RULE_RE.match(body):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        if body.startswith('#'):
            if re.match(r'^#\s*KpRm\b', body):
                b.add(_mk(no, [('hl-title', body)], cr))
            else:
                b.add(_mk(no, _inline(body, 'hl-dim'), cr))
            continue
        # Section title: a non-indented line directly above a dash rule.
        if (body.strip() and not body[0].isspace() and i + 1 < n
                and re.match(r'^-{20,}\s*$', _split_cr(lines[i + 1])[0])):
            section = body.strip()
            b.header(_mk(no, [('hl-header', body)], cr))
            continue
        m = _KP_ITEM_RE.match(body)
        if m:
            lead, marker, gap, path, category = m.groups()
            end = m.end(5) if category else m.end(4)
            if marker == '[OK]':
                sev = 'c'
            else:
                sev = 'b' if re.search(r'FAIL|ERR', marker) else 'w'
                b.item(no, sev, marker, path.strip(), section)
            tokens = [('', lead), ('hl-sev-' + sev, marker), ('', gap)] + _target(path)
            if category:
                tokens.append(('hl-dim', category))
            tokens.append(('', body[end:]))
            b.add(_mk(no, tokens, cr))
            continue
        m = _KP_COUNT_RE.match(body) if section.lower() == 'summary' else None
        if m:
            lead, label, sep, value, trail = m.groups()
            sev = _kprm_count_severity(label, value)
            b.stats.append(Stat(label, value, sev))
            b.add(_mk(no, [('', lead), ('hl-key', label + sep), ('hl-sev-' + sev, value), ('', trail)], cr))
            continue
        if re.match(r'^End of report\.?\s*$', body):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        kv = _kv_colon(body) if not section else None
        b.add(_mk(no, kv if kv else _inline(body), cr))
    return b.result()


# ---------------------------------------------------------------------------
# SecurityCheck (BBCode report; tags are hidden by CSS, styles applied)
# ---------------------------------------------------------------------------

_BB_TAG_RE = re.compile(r'\[(/?)(color|b|i|u|s|url|size)(=[^\]\[]*)?\]', re.I)
_BB_COLOR_CLASS = {'red': 'hl-sev-b', 'blue': 'hl-url', 'green': 'hl-sev-c'}
_SC_SECTION_RE = re.compile(r'^-{3,} \[ (.+?) \] -{3,}\s*$')
_SC_SERVICE_RE = re.compile(r'^(.*? - )(The service .*)$')


def _bb_text(segment, colors, bold, italic, in_url):
    classes = []
    if in_url:
        classes.append('hl-url')
    elif colors:
        classes.append(colors[-1])
    if bold:
        classes.append('hl-bold')
    if italic:
        classes.append('hl-note')
    if not classes:
        return _inline(segment)
    return [(' '.join(classes), segment)]


def _bbcode_tokens(text):
    """Tokenize a BBCode line: tags become hidden tokens, text gets their styles."""
    out = []
    pos = 0
    colors = []
    bold = italic = in_url = 0
    for m in _BB_TAG_RE.finditer(text):
        if m.start() > pos:
            out += _bb_text(text[pos:m.start()], colors, bold, italic, in_url)
        out.append(('hl-bbtag', m.group(0)))
        closing = m.group(1) == '/'
        name = m.group(2).lower()
        step = -1 if closing else 1
        if name == 'color':
            if closing:
                if colors:
                    colors.pop()
            else:
                value = (m.group(3) or '=')[1:].strip().lower()
                colors.append(_BB_COLOR_CLASS.get(value, 'hl-accent'))
        elif name == 'b':
            bold = max(0, bold + step)
        elif name == 'i':
            italic = max(0, italic + step)
        elif name == 'url':
            in_url = max(0, in_url + step)
        pos = m.end()
    if pos < len(text):
        out += _bb_text(text[pos:], colors, bold, italic, in_url)
    return out


def _highlight_securitycheck(lines):
    b = _Builder('')
    in_header = True
    for i, raw in enumerate(lines):
        no = i + 1
        body, cr = _split_cr(raw)
        if i == 0 and body.startswith('SecurityCheck'):
            b.add(_mk(no, [('hl-title', body)], cr))
            continue
        m = _SC_SECTION_RE.match(body)
        if m:
            in_header = False
            b.header(_mk(no, [('hl-dim', body[:m.start(1)]), ('hl-header', m.group(1)),
                              ('hl-dim', body[m.end(1):])], cr))
            continue
        if re.match(r'^_{10,}\s*$', body):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        if '[' in body and _BB_TAG_RE.search(body):
            b.add(_mk(no, _bbcode_tokens(body), cr))
            continue
        m = _SC_SERVICE_RE.match(body)
        if m:
            b.add(_mk(no, _inline(m.group(1)) + [('hl-dim', m.group(2))], cr))
            continue
        kv = _kv_colon(body) if in_header else None
        b.add(_mk(no, kv if kv else _inline(body), cr))
    return b.result()


# ---------------------------------------------------------------------------
# FRST Search (Search Files / SearchAll output)
# ---------------------------------------------------------------------------

_FS_FILE_META_RE = re.compile(r'^(\[[^\]]*\]\[[^\]]*\])(.*?)(\(([^()]*)\))(.*)$')
_FS_FOLDER_RE = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d - \d{4}-\d\d-\d\d \d\d:\d\d )(\S+ )(.*)$')
_FS_REG_KEY_RE = re.compile(r'^(\[)(HKEY_[^\]]*|HK[A-Z]+\\[^\]]*)(\])\s*$')
_FS_REG_VALUE_RE = re.compile(r'^("[^"]*"|@)(=)(.*)$')
_FS_SUBHEADER_RE = re.compile(r'^(File|Folder|Registry|Files|Folders):\s*$')


def _highlight_frst_search(lines):
    b = _Builder('')
    for i, raw in enumerate(lines):
        no = i + 1
        body, cr = _split_cr(raw)
        if i == 0 and body.startswith('Farbar'):
            b.add(_mk(no, [('hl-title', body)], cr))
            continue
        if i < 5 and not body.startswith('='):
            kv = _kv_colon(body)
            b.add(_mk(no, kv if kv else _inline(body), cr))
            continue
        if _FIX_RULE_RE.match(body):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        m = _FIX_BANNER_RE.match(body) if body.startswith('=') else None
        if m:
            if m.group(2).startswith('End of'):
                b.add(_mk(no, [('hl-dim', body)], cr))
                b.end_section()
            else:
                b.header(_mk(no, [('hl-dim', m.group(1)), ('hl-header', m.group(2)),
                                  ('hl-dim', body[m.end(2):])], cr))
            continue
        if _FS_SUBHEADER_RE.match(body):
            b.add(_mk(no, [('hl-subheader', body)], cr))
            continue
        m = _FS_FILE_META_RE.match(body)
        if m:
            dates, middle, paren, company, rest = m.groups()
            company_tokens = ([('hl-dim', '('), ('hl-company', company), ('hl-dim', ')')]
                              if company else [('hl-dim', paren)])
            unsigned = rest.find('[File not signed]')
            if unsigned != -1:
                rest_tokens = (_inline(rest[:unsigned], 'hl-dim') + [('hl-sev-w', '[File not signed]')]
                               + _inline(rest[unsigned + len('[File not signed]'):], 'hl-dim'))
            else:
                rest_tokens = _inline(rest, 'hl-dim')
            b.add(_mk(no, [('hl-dim', dates), ('hl-dim', middle)] + company_tokens + rest_tokens, cr))
            continue
        m = _FS_FOLDER_RE.match(body)
        if m:
            dates, attrs, path = m.groups()
            b.add(_mk(no, [('hl-dim', dates), ('hl-dim', attrs)] + _target(path), cr))
            continue
        m = _FS_REG_KEY_RE.match(body)
        if m:
            b.add(_mk(no, [('hl-dim', m.group(1)), ('hl-reg', m.group(2)), ('hl-dim', body[m.end(2):])], cr))
            continue
        m = _FS_REG_VALUE_RE.match(body)
        if m:
            name, eq, value = m.groups()
            b.add(_mk(no, _inline(name, 'hl-key') + [('hl-dim', eq)] + _inline(value), cr))
            continue
        b.add(_mk(no, _target(body), cr))
    return b.result()


# ---------------------------------------------------------------------------
# FRST / Addition / FRST&Addition: syntax here, rule statuses from the cached
# analysis via apply_analysis_statuses()
# ---------------------------------------------------------------------------

_FRST_TITLE_RE = re.compile(r'^(?:Additional scan|Scan) result of Farbar', re.I)
_FRST_SPECIAL_RE = re.compile(
    r'(?P<attention><=+ ?ATTENTION.*$)'
    r'|(?P<unsigned>\[File not signed\]|\(No File\)|\[No File\]|=> No File\b)'
    r'|(?P<company>\((?:[^()\\]{0,160}) -> (?:[^()\\]{0,160})\))'
    r'|(?P<sizedate>\[\d+ \d{4}-\d\d-\d\d\])'
    r'|(?P<count> <\d+>$)'
)
_FRST_FILE_DATES_RE = re.compile(
    r'^\d{4}-\d\d-\d\d \d\d:\d\d - \d{4}-\d\d-\d\d \d\d:\d\d - \d+ [_A-Z]{5} '
)
_FRST_SPECIAL_CLASS = {
    'attention': 'hl-sev-w', 'unsigned': 'hl-sev-w', 'company': 'hl-company',
    'sizedate': 'hl-dim', 'count': 'hl-dim',
}


def _frst_tokens(text):
    """Tokenize one FRST entry: companies, size/date, warnings, then paths."""
    out = []
    m = _FRST_FILE_DATES_RE.match(text)
    pos = 0
    if m:
        out.append(('hl-dim', m.group(0)))
        pos = m.end()
    for m in _FRST_SPECIAL_RE.finditer(text, pos):
        if m.start() > pos:
            out += _inline(text[pos:m.start()])
        out.append((_FRST_SPECIAL_CLASS[m.lastgroup], m.group(0)))
        pos = m.end()
    if pos < len(text):
        out += _inline(text[pos:])
    return out


def _highlight_frst(lines):
    b = _Builder('')
    since_title = 99
    for i, raw in enumerate(lines):
        no = i + 1
        body, cr = _split_cr(raw)
        since_title += 1
        if _FRST_TITLE_RE.match(body):
            since_title = 0
            b.add(_mk(no, [('hl-title', body)], cr))
            continue
        m = _FIX_BANNER_RE.match(body) if body.startswith('=') else None
        if m:
            if m.group(2).startswith('End of'):
                b.add(_mk(no, [('hl-dim', body)], cr))
                b.end_section()
            else:
                b.header(_mk(no, [('hl-dim', m.group(1)), ('hl-header', m.group(2)),
                                  ('hl-dim', body[m.end(2):])], cr))
            continue
        stripped = body.strip()
        # Explanatory notes under a section banner, e.g. "(If an entry is ...)".
        if stripped.startswith('(If ') or (stripped.startswith('(') and stripped.endswith(')')
                                            and ' ' in stripped and '\\' not in stripped
                                            and ' -> ' not in stripped):
            b.add(_mk(no, [('hl-dim', body)], cr))
            continue
        if since_title < 8:
            kv = _kv_colon(body)
            if kv:
                b.add(_mk(no, kv, cr))
                continue
        b.add(_mk(no, _frst_tokens(body), cr))
    return b.result()


_STATUS_SUMMARY_SEVERITY = {'B': 'b', 'P': 'p', '!': 'w'}
_STATUS_PAINT = {'B': 'b', 'P': 'p', 'C': 'c', '!': 'w', 'A': 'a', 'G': 'g', 'S': 's', 'I': 'i', 'J': 'j'}


def apply_analysis_statuses(result, content, payload):
    """Mark each line of a FRST-type result with its cached analyzer verdict.

    The analyzer stores one entry per non-blank line, in order, without line
    numbers (it walks `splitlines()` and strips). Walk the content the same way
    and check every entry's text, so a stale or mismatched cache is never
    painted onto the wrong lines. Adds B / P / ! lines to the summary.
    Returns False (and changes nothing) when the payload doesn't line up.
    """
    entries = payload.get('lines') if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        return False
    matched = []
    index = 0
    for no, raw in enumerate(content.split('\n'), start=1):
        for piece in raw.splitlines():
            stripped = piece.strip()
            if not stripped:
                continue
            if index >= len(entries) or not isinstance(entries[index], dict) \
                    or entries[index].get('line') != stripped:
                return False
            matched.append((no, stripped, entries[index]))
            index += 1
    if index != len(entries):
        return False
    by_no = {line.no: line for line in iter_lines(result)}
    items = []
    for no, text, entry in matched:
        status = entry.get('dominant_status') or '?'
        line = by_no.get(no)
        if line is None or status == '?' or line.status:
            continue
        paint = (entry.get('css_class') or '').replace('status-', '')
        if paint in ('', 'unknown'):
            paint = _STATUS_PAINT.get(status, '')
        line.status = status
        line.paint = paint
        severity = _STATUS_SUMMARY_SEVERITY.get(status)
        if severity:
            items.append(SummaryItem(no, severity, text[:200], '', status))
    result.summary = items + result.summary
    result.summary.sort(key=lambda item: item.line_no)
    return True


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

HIGHLIGHTERS = {
    'FRST': _highlight_frst,
    'Addition': _highlight_frst,
    'FRST&Addition': _highlight_frst,
    'FRST Search': _highlight_frst_search,
    'KpRm': _highlight_kprm,
    'SecurityCheck': _highlight_securitycheck,
    'MAU': _highlight_mau,
    'ESET': _highlight_eset,
    'Malwarebytes': _highlight_malwarebytes,
    'HitmanPro': _highlight_hitmanpro,
    'Emsisoft': _highlight_emsisoft,
    'AdwCleaner': _highlight_adwcleaner,
    'Fixlog': _highlight_fixlog,
    'Shortcut': _highlight_shortcut,
}


def highlight_log(log_type, content):
    """Return a HighlightResult for supported log types, else None.

    Never raises: a highlighter bug falls back to the plain view.
    """
    func = HIGHLIGHTERS.get(log_type)
    if func is None or not content or len(content) > MAX_HIGHLIGHT_CHARS:
        return None
    try:
        return func(content.split('\n'))
    except Exception:
        logger.exception('Log highlighting failed for log type %s', log_type)
        return None


def _escape(text):
    # A raw CR would be normalised to LF by the HTML parser; a character
    # reference survives into the DOM, so copy/download stay byte-identical.
    escaped = html_escape(text, quote=True)
    if '\r' in escaped:
        escaped = escaped.replace('\r', '&#13;')
    return escaped


# Only VirusTotal URLs become clickable; any other URL in a user-supplied log
# could point anywhere, so it stays plain text.
_VT_URL_RE = re.compile(r'^https://(?:www\.)?virustotal\.com/[^\s"\'<>]*$', re.I)


def _line_html(line, tag='span', extra_class='', extra_attrs=''):
    parts = []
    for cls, text in line.tokens:
        if not text:
            continue
        if cls and 'hl-url' in cls.split() and _VT_URL_RE.match(text):
            href = _escape(text)
            parts.append(f'<a class="{cls} hl-vt" href="{href}" target="_blank" '
                         f'rel="noopener noreferrer">{href}</a>')
        elif cls:
            parts.append(f'<span class="{cls}">{_escape(text)}</span>')
        else:
            parts.append(_escape(text))
    if line.status:
        extra_class += f' hl-st-{line.paint}' if line.paint else ''
        extra_attrs += f' data-st="{_escape(line.status)}"'
    return (f'<{tag} class="hl-line{extra_class}" id="L{line.no}" data-n="{line.no}"{extra_attrs}>'
            f'{"".join(parts)}</{tag}>')


def _chunks_html(lines):
    out = []
    for start in range(0, len(lines), LINES_PER_CHUNK):
        chunk = lines[start:start + LINES_PER_CHUNK]
        est = len(chunk) * 15
        out.append(f'<div class="log-chunk" style="contain-intrinsic-size:auto {est}px">')
        out.extend(_line_html(line) for line in chunk)
        out.append('</div>')
    return out


def render_highlighted_html(result):
    """Render a HighlightResult's sections as safe HTML for #uploadedContent."""
    if result is None:
        return ''
    out = []
    for section in result.sections:
        if section.header is not None:
            count = len(section.lines)
            out.append('<details open class="hl-section">')
            out.append(_line_html(section.header, 'summary', ' hl-section-header',
                                  f' data-count="{count}"'))
            out.extend(_chunks_html(section.lines))
            out.append('</details>')
        else:
            out.append('<div class="hl-section">')
            out.extend(_chunks_html(section.lines))
            out.append('</div>')
    return mark_safe(''.join(out))


# ---------------------------------------------------------------------------
# List-view chips: computed once when stats are recalculated and stored on
# UploadedLog.tool_stats, so the uploads / cases lists never parse logs.
# ---------------------------------------------------------------------------

DETECTION_CHIP_TYPES = {'ESET', 'Malwarebytes', 'HitmanPro', 'Emsisoft', 'AdwCleaner'}
# These keep their analyzer-based count_* fields (and chips) instead.
FRST_TYPES = {'FRST', 'Addition', 'FRST&Addition'}


def _chip(label, value, severity):
    value = int(value)
    return [label, value, severity if value else 'j']


def _stat_value(result, *labels):
    wanted = {label.lower() for label in labels}
    values = [int(s.value) for s in result.stats if s.label.lower() in wanted and str(s.value).isdigit()]
    return sum(values) if values else None


def compute_tool_stats(log_type, content):
    """Return [[label, value, severity], ...] chips for the uploads/cases lists.

    Fixlog and the FRST types keep their dedicated count fields; types without
    a highlighter (or logs over the size cap) get no chips.
    """
    if log_type == 'SecurityCheck':
        from .log_converters import parse_securitycheck
        counts = {}
        for item in parse_securitycheck(content or ''):
            counts[item['type']] = counts.get(item['type'], 0) + 1
        return [
            _chip('upd', counts.get('update', 0), 'w'),
            _chip('eol', counts.get('eol', 0), 'b'),
            _chip('pup', counts.get('unwanted', 0), 'p'),
            _chip('rdp', counts.get('remote_desktop', 0), 'g'),
            _chip('set', counts.get('setting', 0), 'w'),
        ]
    if log_type in FRST_TYPES or log_type == 'Fixlog' or log_type not in HIGHLIGHTERS:
        return []
    result = highlight_log(log_type, content)
    if result is None:
        return []
    if log_type == 'AdwCleaner' and result.summary_title == 'AdwCleaner failures':
        return [_chip('cleaned', _stat_value(result, 'Cleaned') or 0, 'c'),
                _chip('failed', _stat_value(result, 'Failed') or 0, 'w')]
    if log_type in DETECTION_CHIP_TYPES:
        severities = [item.severity for item in result.summary]
        chips = [_chip('B', severities.count('b'), 'b'),
                 _chip('P', severities.count('p'), 'p'),
                 _chip('G', severities.count('g'), 'g')]
        if log_type == 'HitmanPro':
            chips.append(_chip('traces', severities.count('j'), 'j'))
        return chips
    if log_type == 'MAU':
        deleted = _stat_value(result, 'Deleted')
        if deleted is None:
            return [_chip('traces', _stat_value(result, 'Traces found') or 0, 'w')]
        return [_chip('deleted', deleted, 'c'),
                _chip('sched', _stat_value(result, 'Scheduled') or 0, 'w'),
                _chip('failed', _stat_value(result, 'Failed') or 0, 'b')]
    if log_type == 'KpRm':
        scheduled = sum(int(s.value) for s in result.stats if 'schedul' in s.label.lower())
        return [_chip('removed', _stat_value(result, 'Removed') or 0, 'c'),
                _chip('sched', scheduled, 'w'),
                _chip('failed', _stat_value(result, 'Failed') or 0, 'b')]
    if log_type == 'Shortcut':
        shortcuts = no_file = 0
        for line in iter_lines(result):
            if ('hl-dim', ' -> ') in line.tokens:
                shortcuts += 1
                # "()" only means no company; "(No File)" is a missing target.
                if ('hl-sev-w', ' (No File)') in line.tokens:
                    no_file += 1
        return [_chip('shortcuts', shortcuts, 'i'), _chip('no file', no_file, 'w')]
    if log_type == 'FRST Search':
        files = folders = registry = 0
        for raw in content.split('\n'):
            body = _split_cr(raw)[0]
            if _FS_FILE_META_RE.match(body):
                files += 1
            elif _FS_FOLDER_RE.match(body):
                folders += 1
            elif _FS_REG_VALUE_RE.match(body):
                registry += 1
        return [_chip('files', files, 'i'), _chip('folders', folders, 'i'), _chip('reg', registry, 'i')]
    return []


def iter_lines(result):
    """All lines of a result in document order (header lines included)."""
    for section in result.sections:
        if section.header is not None:
            yield section.header
        yield from section.lines
