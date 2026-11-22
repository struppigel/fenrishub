"""SHA256 hashes in scanner logs and Fixlogs, each with the file it belongs to.

Pure text parsing: no network, no database. The rows feed the centralbox
verdict markers on the log page, the detection flags in its summary box and
the case suggestions in the analyzer (see centralbox.py).

Only SHA256 is extracted, and only from the log types whose 64-hex values are
real file hashes. In FRST / Addition / SecurityCheck logs they are file names,
crash bucket ids or URL parts, so those types yield nothing.

MD5s are kept where they name a file: next to its SHA256 (Malwarebytes,
Fixlog File:), or alone (Trojan Killer, the entries of a Fixlog Folder: or
FilesInDirectory: block, the File: entries of an FRST Search log, a Spor
log run with -algo MD5).

A row is `auto` when it may be checked on centralbox without anyone asking:
scanner detections, MAU file hashes, the hashes of a Fixlog `File:` block
and the files a Spor log flags.
Everything else (Fixlog folder listings with thousands of hashes, PowerShell
output, stray hashes, MD5-only rows) is only checked when an analyst asks
from the hash menu.

Line numbers count `content.split('\\n')` from 1, exactly like the `L{no}` ids
of log_highlighting.render_highlighted_html, so the page can find the token.
"""

import re
from dataclasses import dataclass

from . import frst_extractors, spor_log
from .log_highlighting import _MB_DETECTION_RE, _TK_DETECTION_RE, _inline
from .log_types import LOG_TYPE_FRST_SEARCH, LOG_TYPE_SPOR

HASH_LOG_TYPES = frozenset({
    'Malwarebytes', 'HitmanPro', 'MAU', 'Fixlog', 'Trojan Killer', LOG_TYPE_SPOR, LOG_TYPE_FRST_SEARCH,
})

# Folder listings reach ~6,000 hashes; anything beyond this is not stored.
MAX_ROWS_PER_LOG = 10000
# Real logs have at most ~60 auto hashes; more than this is not a normal log.
MAX_AUTO_PER_LOG = 300

# The same boundaries as the highlighter's hash token (`\b`), so a stored row
# always corresponds to an `hl-hash` span on the page.
_SHA256_RE = re.compile(r'\b[0-9A-Fa-f]{64}\b')
_SHA256_FULL_RE = re.compile(r'^[0-9a-f]{64}$')
_MD5_FULL_RE = re.compile(r'^[0-9a-f]{32}$')
# FRST File: block and Trojan Killer: "MD5: <md5>" / "\tMD5: <md5>:<size>"
_MD5_LINE_RE = re.compile(r'^\s*MD5:\s*([0-9A-Fa-f]{32})(?::\d+)?\s*$')

_PATH_START_RE = re.compile(r'^(?:[A-Za-z]:\\|\\\\)')
# Prefixes in front of a path on the line above a hash: a console timestamp,
# a MAU "[File]" tag, "Path:" (MAU cached MSI) or "FullPath :" (PowerShell).
_PATH_PREFIX_RE = re.compile(
    r'^(?:\[\d{1,2}:\d{2}:\d{2}\]\s*)?(?:\[(?:File|Dir|Directory)\]\s*|Path:\s*|FullPath\s*:\s*)?',
    re.IGNORECASE,
)

# "SHA256: <hash>" (FRST File:, MAU), optionally behind a console timestamp
# or tab-separated (PowerShell Get-FileHash in a Fixlog).
_SHA256_LINE_RE = re.compile(r'^\s*(?:\[\d{1,2}:\d{2}:\d{2}\]\s*)?SHA256\s*:\s*([0-9A-Fa-f]{64})\s*$')
# HitmanPro: "      SHA-256  . . . . . : <hash>"
_HMP_SHA_RE = re.compile(r'^\s+SHA-256(?: +\.)+ *:\s*([0-9A-Fa-f]{64})\s*$')
_HMP_SECTION_RE = re.compile(r'^\S.*? _{5,}\s*$')
_HMP_ITEM_RE = re.compile(r'^   \S')
_HMP_DETECTION_RE = re.compile(r'^\s+> .*?(?:(?: +\.)+ *:|  +:)(.*)$')

# Fixlog File: block: "===== File: <paths> =====" ... "====== End of File: ======".
_FIXLOG_FILE_BANNER_RE = re.compile(r'^=+ File: ')
_FIXLOG_BANNER_RE = re.compile(r'^={5,}')
# Fixlog folder listing: "  [<hash>] date - date - size - Signer: X - <path>"
_FOLDER_LIST_RE = re.compile(r'^\s*\[([0-9A-Fa-f]{64})\]\s')
# Fixlog "Folder:" / "FilesInDirectory:" block: "===== Folder: <path> =====" ...
# "====== End of Folder: ======",
# one line per entry with its MD5 (all zeros for directories):
# "2026-11-11 17:32 - 2026-11-11 17:32 - 000000312 ____H [<md5>] (<signer>) <path>"
_FIXLOG_FOLDER_BANNER_RE = re.compile(r'^=+ (?:Folder|FilesInDirectory): ')
_FOLDER_MD5_RE = re.compile(
    r'^\s*\d{4}-\d\d-\d\d \d\d:\d\d - \d{4}-\d\d-\d\d \d\d:\d\d - \d+ \S+ '
    r'\[([0-9A-Fa-f]{32})\] \(.*?\) ((?:[A-Za-z]:\\|\\\\).*?)\s*$'
)
_ZERO_MD5 = '0' * 32


@dataclass
class FileHash:
    """One file hash in a log. `sha256` is '' for an MD5-only row (Trojan
    Killer); rows with both (Malwarebytes, Fixlog File:) tell which SHA256
    an MD5 stands for. `line_no` is the line of the token that is marked:
    the SHA256 when there is one, else the MD5."""

    sha256: str
    line_no: int
    anchor_line_no: int
    path: str = ''
    detection: str = ''
    source: str = 'other'
    auto: bool = False
    md5: str = ''

    @property
    def normalized_path(self):
        return normalized_path(self.path)


def normalized_path(path):
    """The comparison key the analyzer's filepath matcher uses for FRST lines."""
    if not path:
        return ''
    try:
        return frst_extractors.path_key(path)
    except Exception:
        return ''


def is_sha256(value):
    return bool(_SHA256_FULL_RE.match((value or '').strip().lower()))


def is_md5(value):
    return bool(_MD5_FULL_RE.match((value or '').strip().lower()))


def _as_path(text):
    """The path in a line like "  [File] c:\\x\\y.exe", or '' if it holds none."""
    stripped = (text or '').strip()
    stripped = _PATH_PREFIX_RE.sub('', stripped, count=1).strip().strip('"')
    return stripped if _PATH_START_RE.match(stripped) else ''


def _path_above(bodies, index, max_lines=3):
    """(line_no, path) of the nearest path among the few non-blank lines above."""
    seen = 0
    for j in range(index - 1, -1, -1):
        if not bodies[j].strip():
            continue
        seen += 1
        path = _as_path(bodies[j])
        if path:
            return j + 1, path
        if seen >= max_lines:
            break
    return None, ''


def _folder_list_path(body):
    tail = body.rsplit(' - ', 1)[-1] if ' - ' in body else ''
    return _as_path(tail)


class _Collector:
    def __init__(self):
        self.rows = []
        self._seen = set()

    def add(self, sha, line_no, anchor_line_no=None, path='', detection='', source='other', auto=False, md5=''):
        sha = (sha or '').lower()
        md5 = (md5 or '').lower() if is_md5(md5) else ''
        key = (sha or 'md5:' + md5, line_no)
        if (not sha and not md5) or key in self._seen or len(self.rows) >= MAX_ROWS_PER_LOG:
            return None
        self._seen.add(key)
        row = FileHash(sha, line_no, anchor_line_no or line_no, path or '', (detection or '')[:255], source, auto, md5)
        self.rows.append(row)
        return row

    def add_leftovers(self, bodies):
        """Every other SHA256 token: checkable from the hash menu only."""
        for i, body in enumerate(bodies):
            for m in _SHA256_RE.finditer(body):
                self.add(m.group(0), i + 1)


def _extract_malwarebytes(bodies, out):
    for i, body in enumerate(bodies):
        m = _MB_DETECTION_RE.match(body)
        if not m:
            continue
        fields = [field.strip() for field in m.group('rest').split(',')]
        last = fields[-1]
        md5 = fields[-2] if len(fields) >= 2 and is_md5(fields[-2]) else ''
        if is_sha256(last):
            out.add(last, i + 1, i + 1, _as_path(m.group('target')), m.group('name').strip(), 'malwarebytes', True,
                    md5=md5)


def _extract_hitmanpro(bodies, out, source='hitmanpro', auto=True):
    """HitmanPro: "      SHA-256 . . . : <hash>" under the file's item line
    (the path, indented by three spaces), with the item's "> engine :
    detection". Also the HitmanPro output in a Fixlog (source
    'fixlog_hitmanpro', manual only)."""
    in_section = False
    item = None  # (anchor line_no, path, [rows])
    for i, body in enumerate(bodies):
        if _HMP_SECTION_RE.match(body):
            in_section, item = True, None
            continue
        if in_section and _HMP_ITEM_RE.match(body):
            item = (i + 1, _as_path(body), [])
            continue
        m = _HMP_SHA_RE.match(body)
        if m and item is not None:
            row = out.add(m.group(1), i + 1, item[0], item[1], '', source, auto)
            if row is not None:
                item[2].append(row)
            continue
        m = _HMP_DETECTION_RE.match(body)
        if m and item is not None:
            for row in item[2]:
                row.detection = m.group(1).strip()[:255]


def _extract_sha256_lines(bodies, out, source):
    """MAU / Trojan Killer: "SHA256: <hash>" right under the file's path."""
    for i, body in enumerate(bodies):
        m = _SHA256_LINE_RE.match(body) or _HMP_SHA_RE.match(body)
        if m:
            anchor, path = _path_above(bodies, i)
            out.add(m.group(1), i + 1, anchor, path, '', source, True)


def _extract_trojan_killer(bodies, out):
    """Trojan Killer: the file MD5 ("\tMD5: <md5>:<size>") under each
    "----- <path> ---- General Threat" header; PE section MD5s are skipped.
    MD5 only, so these are checked from the hash menu, never by themselves."""
    detection = None  # [header line_no, path, name]
    for i, body in enumerate(bodies):
        m = _TK_DETECTION_RE.match(body)
        if m:
            detection = [i + 1, _as_path(m.group(2)), None]
            continue
        if detection is None:
            continue
        if detection[2] is None and body.startswith('\t') and not body.startswith('\t\t') and body.strip():
            detection[2] = body.strip() if ': ' not in body.strip() else ''
            if detection[2]:
                continue
        if body.startswith('\t\t'):
            continue
        m = _MD5_LINE_RE.match(body)
        if m:
            out.add('', i + 1, detection[0], detection[1], detection[2] or '', 'trojan_killer', False, md5=m.group(1))
    _extract_sha256_lines(bodies, out, 'trojan_killer')


# Defender lines name the process that touched the file ("; process C:\x.exe")
# and a process resource ("process: C:\x.exe, pid:N:M", Spor 0.4.0+; after
# unfold() also right after " => "): not flagged files.
_SPOR_PROCESS_RE = re.compile(r'(?:; |(?<= => ))process:? [^;]*')
# SUMMARY: "... .pdf.lnk  !double-extension  (loaded by C:\...\host.exe)" names the
# program that loaded the flagged file: not flagged itself. Spor 0.7.2+ writes
# "... .pdf.lnk => loaded by C:\...\host.exe <==== !double-extension" (the flags
# are cut off before this applies).
# At the end of the line: the path itself can hold parens ("Program Files (x86)").
_SPOR_LOADED_BY_RE = re.compile(r'(?: \(loaded by [^\r\n]{1,600}\)| => loaded by [^\r\n]{1,600})\s*$')


def _line_paths(text):
    return [value for cls, value in _inline(text) if cls == 'hl-path']


def _spor_flagged_paths(bodies, detections):
    """Normalized paths Spor itself points at: Defender detections, lines
    with a flag other than the ones normal on many PCs, and the SUMMARY."""
    flagged = {normalized_path(path) for _no, _threat, _action, path in detections}
    # Spor 0.7.0+: a line's details back on the line (its sub-lines stay below it)
    bodies = spor_log.unfold(bodies)
    summary = spor_log.section_ranges(bodies).get(spor_log.SECTION_SUMMARY)
    known = None
    for index, body in enumerate(bodies):
        in_summary = summary is not None and summary[0] < index < summary[1]
        if in_summary and spor_log.is_sub_line(body):
            # A SUMMARY line's sub-lines (a download's addresses, a Defender
            # detection's items) are on its unfolded line already.
            continue
        cut = body.find(spor_log.FLAGS_MARK)
        loud = cut != -1 and any(flag not in spor_log.QUIET_FLAGS for flag in body[cut:].split()[1:])
        if (in_summary or loud) and cut != -1 and spor_log.SYNTAX_FLAG in body[cut:].split():
            # A path made to look like log text: only the whole path FILES lists counts.
            if known is None:
                known = spor_log.known_paths(bodies)
            item = spor_log.split_item(body.strip(), known)
            if item.resolved:
                flagged.add(normalized_path(item.item))
            continue
        if in_summary or loud:
            text = body if cut == -1 else body[:cut]
            # Defender lines name the process that touched the file: not flagged itself.
            text = _SPOR_PROCESS_RE.sub('', text)
            text = _SPOR_LOADED_BY_RE.sub('', text)
            inline = spor_log.INLINE_FLAG_RE.search(text)
            if inline:
                # "path  !flag  ...": the flagged path ends before its flags.
                text = text[:inline.start()]
            for path in _line_paths(text):
                flagged.add(normalized_path(path))
    flagged.discard('')
    return flagged


def _extract_spor(bodies, out):
    """Spor: the FILES section, one "path => <hash>, signature ..." line per
    file (SHA256, or MD5 with -algo MD5; SHA1 is not stored). A Defender
    detection of the same file gives the row its name. Only files Spor
    flags are `auto`: a log lists hundreds of unsigned files, which would
    switch off the automatic checks of the whole log."""
    detections = spor_log.iter_defender_detections(bodies)
    threats = {}
    for _no, threat, _action, path in detections:
        threats.setdefault(normalized_path(path), threat)
    flagged = _spor_flagged_paths(bodies, detections)
    for parsed in spor_log.iter_file_lines(bodies):
        line_no, path, value, signature = parsed.line_no, parsed.path, parsed.hash, parsed.signature
        key = normalized_path(path)
        auto = key in flagged or signature in spor_log.BAD_SIGNATURES
        detection = threats.get(key, '')
        if is_sha256(value):
            # With the file's MD5 ("md5" detail): the pair lets the MD5-only rows
            # of other logs (FRST Search, Fixlog folders) find this SHA256's verdict.
            out.add(value, line_no, line_no, path, detection, 'spor', auto, md5=parsed.details.get('md5', ''))
        elif is_md5(value):
            out.add('', line_no, line_no, path, detection, 'spor', False, md5=value)


def _extract_frst_search(content, out):
    """FRST Search: the MD5 of each File: entry, on the line below its path.
    MD5 only, like Trojan Killer: checked from the hash menu, never by itself."""
    from .tool_log_facts import frst_search_facts

    files, _mentions = frst_search_facts(content)
    for facts in files:
        if facts.md5:
            out.add('', facts.hash_line_no, facts.line_no, facts.path, '', 'frst_search', False, md5=facts.md5)


def _extract_fixlog(bodies, out):
    in_file_block = in_folder_block = False
    current = (None, '')  # (line_no, path) of the file the block is describing
    current_md5 = ''
    for i, body in enumerate(bodies):
        if _FIXLOG_BANNER_RE.match(body):
            in_file_block = bool(_FIXLOG_FILE_BANNER_RE.match(body))
            in_folder_block = bool(_FIXLOG_FOLDER_BANNER_RE.match(body))
            current, current_md5 = (None, ''), ''
            continue
        if in_folder_block:
            # MD5 only, like Trojan Killer: checked from the hash menu, never by itself.
            m = _FOLDER_MD5_RE.match(body)
            if m and m.group(1) != _ZERO_MD5:
                out.add('', i + 1, i + 1, m.group(2), '', 'fixlog_folder', False, md5=m.group(1))
                continue
        if in_file_block:
            if _PATH_START_RE.match(body.strip()):
                # "C:\x\y.exe [symlink -> ...]": keep only the file's own path.
                current, current_md5 = (i + 1, body.strip().split(' [symlink', 1)[0].strip()), ''
                continue
            m = _MD5_LINE_RE.match(body)
            if m:
                current_md5 = m.group(1)
                continue
            m = _SHA256_LINE_RE.match(body)
            if m:
                out.add(m.group(1), i + 1, current[0], current[1], '', 'fixlog_file', True, md5=current_md5)
            continue
        m = _FOLDER_LIST_RE.match(body)
        if m:
            out.add(m.group(1), i + 1, i + 1, _folder_list_path(body), '', 'fixlog_folder', False)
            continue
        m = _SHA256_LINE_RE.match(body)
        if m:
            anchor, path = _path_above(bodies, i)
            out.add(m.group(1), i + 1, anchor, path, '', 'fixlog_other', False)


def extract_file_hashes(log_type, content):
    """The file-hash rows of a log (SHA256, plus MD5 where the log gives one), in line order. Never raises."""
    if log_type not in HASH_LOG_TYPES or not content:
        return []
    try:
        bodies = [raw[:-1] if raw.endswith('\r') else raw for raw in content.split('\n')]
        out = _Collector()
        if log_type == 'Malwarebytes':
            _extract_malwarebytes(bodies, out)
        elif log_type == 'HitmanPro':
            _extract_hitmanpro(bodies, out)
        elif log_type == 'MAU':
            _extract_sha256_lines(bodies, out, 'mau')
        elif log_type == 'Trojan Killer':
            _extract_trojan_killer(bodies, out)
        elif log_type == LOG_TYPE_SPOR:
            _extract_spor(bodies, out)
        elif log_type == LOG_TYPE_FRST_SEARCH:
            _extract_frst_search(content, out)
        elif log_type == 'Fixlog':
            _extract_fixlog(bodies, out)
            # HitmanPro results in the Fixlog: the path is on the item line
            # above the hash. Checked from the hash menu only, like the rest.
            _extract_hitmanpro(bodies, out, source='fixlog_hitmanpro', auto=False)
        if log_type != LOG_TYPE_FRST_SEARCH:
            # FRST Search lists file and registry names, which can be 64 hex characters.
            out.add_leftovers(bodies)
        auto_seen = 0
        for row in out.rows:
            if row.auto:
                auto_seen += 1
                if auto_seen > MAX_AUTO_PER_LOG:
                    row.auto = False
        return sorted(out.rows, key=lambda r: (r.line_no, r.sha256, r.md5))
    except Exception:
        import logging
        logging.getLogger(__name__).exception('SHA256 extraction failed for a %s log', log_type)
        return []
