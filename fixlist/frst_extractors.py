import ntpath
import re
from dataclasses import dataclass

DESCRIPTION_SEP = "|||Description:"
FIREFOX_PROFILE_RE = re.compile(r"(?i)(\\mozilla\\firefox\\profiles\\)[^\\]+")
# Chromium-family browsers (Chrome, Edge, Brave, Vivaldi, Opera, ...) all keep
# per-profile dirs under `\User Data\` with one of a fixed set of names. Anchor
# on the trailing `\` so we never collapse `\User Data\` itself or non-profile
# sibling dirs (Crashpad, GrShaderCache, etc.).
CHROMIUM_PROFILE_RE = re.compile(
    r"(?i)(\\User Data\\)(?:Default|Profile\s+\d+|Guest Profile|System Profile)(?=\\)"
)

# FRST's Installed Programs section appends ` Hidden` after the closing paren
# for hidden products. Anchored to end of line so it cannot match arbitrary
# occurrences of "Hidden" mid-string in other entry types.
_HIDDEN_SUFFIX_RE = re.compile(r"\)\s+Hidden\s*$")

# Entry types whose CLSID/GUID is randomly assigned by Windows per machine
# (firewall rule IDs, scheduled task IDs) rather than being a semantic COM
# class ID. We intentionally don't store or compare these — they would
# prevent any cross-system rule match.
SYSTEM_SPECIFIC_CLSID_TYPES = frozenset({
    "firewall",
    "scheduled_task",
    "scheduled_task_command",
})


@dataclass
class FrstEntry:
    clsid: str = ""
    name: str = ""
    filepath: str = ""
    filename: str = ""
    date: str = ""
    company: str = ""
    description: str = ""
    arguments: str = ""
    file_not_signed: bool = False
    entry_type: str = ""
    # FRST file-attribute flags (e.g. "____D" for directory). Only populated for
    # entry types that carry them — currently the "One month (created/modified)"
    # section. Empty for all other entry types and compares equal to empty.
    attributes: str = ""
    # `Hidden` suffix used by FRST in the Installed Programs section to mark
    # entries that wouldn't appear in Programs and Features (typically MSI
    # components, runtime redistributables, or installer leftovers).
    is_hidden: bool = False

    def __eq__(self, other):
        if not isinstance(other, FrstEntry):
            return NotImplemented
        compare_clsid = (
            self.entry_type not in SYSTEM_SPECIFIC_CLSID_TYPES
            and other.entry_type not in SYSTEM_SPECIFIC_CLSID_TYPES
        )
        return (
            (not compare_clsid or self.clsid.lower() == other.clsid.lower())
            and self.name == other.name
            and self.filepath.lower() == other.filepath.lower()
            and self.filename.lower() == other.filename.lower()
            and self.file_not_signed == other.file_not_signed
            and self.is_hidden == other.is_hidden
            and self.company == other.company
            and self.entry_type == other.entry_type
            and self.arguments == other.arguments
            and self.attributes == other.attributes
        )

    def __hash__(self):
        clsid_key = (
            "" if self.entry_type in SYSTEM_SPECIFIC_CLSID_TYPES
            else self.clsid.lower()
        )
        return hash(
            (
                clsid_key,
                self.name,
                self.filepath.lower(),
                self.filename.lower(),
                self.company,
                self.file_not_signed,
                self.is_hidden,
                self.entry_type,
                self.arguments,
                self.attributes,
            )
        )


def get_description(line):
    parts = line.split(DESCRIPTION_SEP)
    return parts[1].strip() if len(parts) > 1 else ""


def strip_description(line):
    if DESCRIPTION_SEP in line:
        return line.split(DESCRIPTION_SEP)[0].strip()
    return line.strip()


def normalize_path(path):
    default_username = "username"
    if len(path) >= 2 and path[1] == ":" and not path.startswith("C:"):
        path = "C:" + path[2:]
    path = re.sub(r"(?i)(C:\\Users\\)[^\\]+", r"\1" + default_username, path)
    path = FIREFOX_PROFILE_RE.sub(r"\1profile", path)
    return CHROMIUM_PROFILE_RE.sub(r"\1profile", path)


_PATH_DRIVE_MARK = "\x00DRIVE\x00"
_PATH_USER_MARK = "\x00USER\x00"
_PATH_FFPROFILE_MARK = "\x00FFPROFILE\x00"
_PATH_CHROMIUMPROFILE_MARK = "\x00CHROMIUMPROFILE\x00"


def _denormalize_path_pattern(normalized_path):
    """Build a regex matching the original (un-normalized) form of a path.

    normalize_path() rewrites four things; this reverses each as a wildcard:
    drive letter (forced to C:), \\Users\\<user>\\ (forced to username),
    Firefox profile name (forced to "profile"), and Chromium profile dir
    (forced to "profile" under \\User Data\\). Other characters are matched
    literally (case-insensitively).
    """
    if not normalized_path:
        return None

    work = normalized_path
    if len(work) >= 2 and work[1] == ":":
        work = _PATH_DRIVE_MARK + work[2:]

    work = re.sub(
        r"(?i)(\\Users\\)username(\\)",
        r"\1" + _PATH_USER_MARK + r"\2",
        work,
    )
    work = re.sub(
        r"(?i)(\\Mozilla\\Firefox\\Profiles\\)profile",
        r"\1" + _PATH_FFPROFILE_MARK,
        work,
    )
    work = re.sub(
        r"(?i)(\\User Data\\)profile(?=\\)",
        r"\1" + _PATH_CHROMIUMPROFILE_MARK,
        work,
    )

    pattern = re.escape(work)
    pattern = pattern.replace(re.escape(_PATH_DRIVE_MARK), r"[A-Za-z]:")
    pattern = pattern.replace(re.escape(_PATH_USER_MARK), r"[^\\]+")
    pattern = pattern.replace(re.escape(_PATH_FFPROFILE_MARK), r"[^\\]+")
    pattern = pattern.replace(re.escape(_PATH_CHROMIUMPROFILE_MARK), r"[^\\]+")
    return pattern


def find_value_position(value, source, field_name=None):
    """Locate value inside source. Returns (start, end) or None.

    Tries a case-insensitive literal find first. For path-bearing fields
    (filepath, filename), falls back to a denormalized regex so values that
    were rewritten by normalize_path still align with the original line.
    """
    if not value or not source:
        return None

    lower_source = source.lower()
    lower_value = value.lower()
    pos = lower_source.find(lower_value)
    if pos != -1:
        return (pos, pos + len(value))

    if field_name not in ("filepath", "filename"):
        return None

    pattern = _denormalize_path_pattern(value)
    if not pattern:
        return None
    try:
        match = re.search(pattern, source, re.IGNORECASE)
    except re.error:
        return None
    if match:
        return (match.start(), match.end())
    return None


_FRST_FILEPATH_TRAILING_MARKERS_RE = re.compile(
    r"\s*<====.*$|\s+\(No File\)\s*$"
)

# When an extractor's filepath capture has no separate arguments group (typical
# for runkey/service), it can swallow trailing command-line args. We split at the
# first executable-extension boundary followed by whitespace — paths like
# `C:\Program Files\app\app.exe -flag` and `conhost.exe --headless ... "" args`.
_BINARY_PATH_ENDINGS = r"exe|dll|bat|cmd|ps1|scr|vbs|wsf|com|msi"
_FRST_BINARY_AND_ARGS_RE = re.compile(
    r'^(?:"(?P<quoted>[^"]+)"|(?P<bare>\S.*?\.(?:' + _BINARY_PATH_ENDINGS + r')))'
    r'(?P<sep>\s+|"\s+)(?P<args>\S.*)$',
    re.IGNORECASE,
)


def _split_binary_and_args(value: str) -> tuple[str, str]:
    if not value:
        return value, ""
    match = _FRST_BINARY_AND_ARGS_RE.match(value)
    if not match:
        return value, ""
    binary = match.group("quoted") or match.group("bare")
    args = match.group("args").strip()
    return binary, args


def _strip_frst_filepath_markers(value: str) -> str:
    """Strip FRST status markers that some extractors otherwise pull into the filepath.

    `(No File)` flags that FRST couldn't locate the referenced file on disk and
    `<==== ATTENTION` is FRST's malware-suspect highlight — neither belongs in
    a filepath. Both are always trailing, never embedded in a real path.

    Also strips the surrounding quotes FRST puts around paths containing spaces
    (e.g. `"C:\\Program Files (x86)\\App\\bin.exe"`).
    """
    if not value:
        return value
    prev = None
    while prev != value:
        prev = value
        value = _FRST_FILEPATH_TRAILING_MARKERS_RE.sub("", value).rstrip()
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1].strip()
    return value


def extract_frst_entry(line, regexp, group_map, entry_type=""):
    pattern = re.compile(regexp)
    no_desc_line = strip_description(line)
    match = pattern.match(no_desc_line)
    if not match:
        return None

    def get_value(key):
        if key not in group_map:
            return ""
        value = match.group(group_map.get(key))
        return (value or "").strip()

    clsid = "" if entry_type in SYSTEM_SPECIFIC_CLSID_TYPES else get_value("clsid")
    name = get_value("name")
    filepath = normalize_path(_strip_frst_filepath_markers(get_value("filepath")))
    arguments = get_value("arguments")
    if not arguments:
        filepath, arguments = _split_binary_and_args(filepath)
    filename = (ntpath.basename(filepath) or "").strip()
    date = get_value("date")
    company = get_value("company")
    attributes = get_value("attributes")
    file_not_signed = "[File not signed]" in line
    # The Hidden suffix is currently only meaningful for the Installed Programs
    # section. Scoped by entry_type so unrelated lines that happen to end with
    # ") Hidden" can never flip the flag.
    is_hidden = (
        entry_type == "installed_software"
        and bool(_HIDDEN_SUFFIX_RE.search(line))
    )
    description = get_description(line)

    return FrstEntry(
        clsid,
        name,
        filepath,
        filename,
        date,
        company,
        description,
        arguments,
        file_not_signed,
        entry_type,
        attributes,
        is_hidden,
    )


# Company captures must accept nested parens like `Intel(R) Client Connectivity
# Division SW -> Intel Corporation`. Replace `[^\)]*` with `(.*?)` plus a lookahead
# requiring the closing `)` to be followed by valid trailing content — never
# just any `)`. The `\(` alternative covers concatenated entries where another
# `(...)` group follows the company (e.g. process-style continuations).
_COMPANY_GROUP = r"(.*?)\)(?=\s*(?:<====|\(No File\)|\[File not signed\]|\(|$))"


def extract_frst_service(line):
    regexp = r"[RSU][0-5] ([^;]+); ([^[\n]+)(\[([^]]*)\] \(" + _COMPANY_GROUP + r")?"
    group_map = {"name": 1, "filepath": 2, "date": 4, "company": 5}
    return extract_frst_entry(line, regexp, group_map, entry_type="service")


def extract_frst_runkey(line):
    regexp = (
        r"HK(LM)?(U\\S[0-9-]+)?(-x32)?\\\.\.\.\\Run(Once)?: \[([^]]*)\] => "
        r"([^[\n]+)(\[([^]]*)\] \(" + _COMPANY_GROUP + r")?"
    )
    group_map = {"name": 5, "filepath": 6, "date": 8, "company": 9}
    return extract_frst_entry(line, regexp, group_map, entry_type="runkey")


def extract_frst_activesetup(line):
    regexp = (
        r"HKLM\\[\w \\]+\\Installed Components: \[\{([^]{}]*)\}\] -> "
        r"([^[\n]+)(\[([^]]*)\] \(" + _COMPANY_GROUP + r")?"
    )
    group_map = {"clsid": 1, "filepath": 2, "date": 4, "company": 5}
    return extract_frst_entry(line, regexp, group_map, entry_type="activesetup")


def extract_print_monitors(line):
    regexp = r"HKLM\\\.\.\.\\Print\\Monitors\\(.*): (.*) \[(.*)\] \((.*)\)"
    group_map = {"name": 1, "filepath": 2, "date": 3, "company": 4}
    return extract_frst_entry(line, regexp, group_map, entry_type="printmonitor")


def extract_custom_appcompatflags(line):
    regexp = r"HKLM\\Software\\\.\.\.\\AppCompatFlags\\Custom\\(.*): \[\{(.*)\}.*\] -> (.*)"
    group_map = {"clsid": 2, "name": 3}
    return extract_frst_entry(line, regexp, group_map, entry_type="appcompatflags")


def extract_custom_appcompatsdb(line):
    regexp = r"HKLM\\Software\\\.\.\.\\AppCompatFlags\\InstalledSDB\\\{([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})\}: \[(.*)\] -> (.*\.sdb) \[(.*)\]"
    group_map = {"clsid": 1, "filepath": 3, "date": 4}
    return extract_frst_entry(line, regexp, group_map, entry_type="appcompatsdb")


def extract_frst_shortcut(line):
    if "ShortcutTarget:" in line:
        regexp = r"ShortcutTarget:(.*)?->(.*)\((.*?)\)"
        group_map = {"name": 1, "filepath": 2, "company": 3}
        return extract_frst_entry(line, regexp, group_map, entry_type="shortcut")
    if "ShortcutWithArgument:" in line:
        regexp = r"ShortcutWithArgument: (.*) -> (.*) (\((.*)\) )-> (.*)"
        group_map = {"name": 1, "filepath": 2, "company": 4, "arguments": 5}
        return extract_frst_entry(line, regexp, group_map, entry_type="shortcut")
    return None


def extract_frst_scheduled_task_command(line):
    # Capture the task path (e.g. `System32\Tasks\Foo`) into `name` so two
    # tasks at different paths but running the same schtasks command don't
    # collapse into a single FrstEntry under __eq__.
    regexp = r"Task:\s*?\{(.*?)\}\s*(?:-\s*)?(.+?)\s*=>\s*Command\(\d+\):\s*(.+?)\s*$"
    group_map = {"clsid": 1, "name": 2, "arguments": 3}
    return extract_frst_entry(line, regexp, group_map, entry_type="scheduled_task_command")


def extract_frst_scheduled_task(line):
    # Binary form: `Task: {GUID} - <task path> => <filepath>` followed by any of:
    #   - `[<size date>] (<company>)`     (canonical FRST output)
    #   - `-> <args>`                     (e.g. Opera/iTop autoupdate tasks, vbs droppers)
    #   - `<==== ATTENTION`               (FRST malware marker)
    #   - `[File not signed]` / end-of-line
    # The filepath ends at the first ` [`, ` ->`, ` <====`, or end-of-line — `(x86)`
    # in `C:\Program Files (x86)\...` and an empty `()` company both parse correctly.
    # The task path (group 2) goes into `name`, and any trailing `-> args` goes into
    # `arguments`. Both are needed in __eq__ so two tasks at different paths or with
    # different vbs/exe arguments do not collapse into a single FrstEntry.
    regexp = (
        r"Task:\s*?\{(.*?)\}\s*(?:-\s*)?(.+?)\s*=>"
        r"(?!\s*(?:\{|Command\(\d+\):))"   # exclude `=> {GUID}` and `=> Command(N):` forms
        r"\s*(.+?)"
        r"(?=\s+\[|\s+->|\s+\(No File\)|\s*<====|\s*$)"
        # Optional `[date] (company)` block. Company may contain nested parens
        # (e.g. `Intel(R) Client Connectivity Division SW -> Intel Corporation`) —
        # the closing `)` must be followed by valid trailing content, not just any `)`.
        r"(?:\s+\[(.*?)\]\s*\((.*?)\)(?=\s*(?:->|<====|\(No File\)|\[File not signed\]|\(|$)))?"
        # Optional `-> args` tail (e.g. `wscript.exe ... -> "%LOCALAPPDATA%\foo.vbs"`).
        r"(?:\s*->\s*(.+?))?"
        r"\s*(?:\[File not signed\])?\s*(?:<====.*)?\s*$"
    )
    group_map = {"clsid": 1, "name": 2, "filepath": 3, "date": 4, "company": 5, "arguments": 6}
    return extract_frst_entry(line, regexp, group_map, entry_type="scheduled_task")


def extract_frst_scheduled_task_job(line):
    # Classic Windows AT-style scheduled tasks (.job format, pre-Vista, but FRST
    # still surfaces them on modern systems for legacy installers like X-Rite or
    # EPSON Scan). Shape: `Task: <path>.job => <binary>` with no GUID. The
    # `<binary>` sometimes has raw bytes from the .job file appended directly
    # with no whitespace separator (description blob, machine name, etc.) — the
    # non-greedy capture truncates at the first executable extension so that
    # trailing noise is dropped.
    regexp = (
        r'Task:\s+(.+?\.job)\s*=>\s*'
        r'"?(.+?\.(?:' + _BINARY_PATH_ENDINGS + r'))"?'
    )
    group_map = {"name": 1, "filepath": 2}
    return extract_frst_entry(line, regexp, group_map, entry_type="scheduled_task")


def extract_frst_startup(line):
    # Trailing tokens FRST may append after the date bracket: `[File not signed]`,
    # `<==== ATTENTION`, and the `(No File)` status marker. Anchoring all of them
    # prevents `(.+?)` from swallowing them into the filepath.
    regexp = (
        r"Startup: (.+?)(?: \[([^\]]*)\])?"
        r"\s*(?:\[File not signed\])?"
        r"\s*(?:\(No File\))?"
        r"\s*(?:<====.*)?$"
    )
    group_map = {"filepath": 1, "date": 2}
    return extract_frst_entry(line, regexp, group_map, entry_type="startup")


def extract_installed_software(line):
    # The uninstall key under HKLM\...\Uninstall\ is sometimes an MSI Product
    # Code GUID and sometimes a literal name. The GUID is only reliably stable
    # across systems for well-known MSI installers; third-party / PUP installers
    # often generate per-install GUIDs. We intentionally do NOT capture it into
    # `clsid` — that would silently break cross-system rule matching for those
    # installers. The Hidden flag and name/company are sufficient to tell e.g.
    # the two Adobe AIR variants apart.
    regexp = r"(.*?)( - [\s\.\d\(\)x]*)?\(HK(LM|U)(-x32)?\\.*\((Version:.* - (.*))\)( Hidden)?"
    group_map = {"name": 1, "company": 6}
    return extract_frst_entry(line, regexp, group_map, entry_type="installed_software")


_ONEMONTH_TS = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?"


def extract_onemonth(line):
    # FRST also emits these lines prefixed with "Found path already in " when
    # reporting search results against the onemonth section — handle both forms.
    regexp = (
        r"(?:Found path already in\s+)?"
        + r"(" + _ONEMONTH_TS + r") - " + _ONEMONTH_TS +
        r" - \d+ (.{5}) (\((.*)\) )?(\w:\\.*)"
    )
    group_map = {"date": 1, "attributes": 2, "company": 4, "filepath": 5}
    return extract_frst_entry(line, regexp, group_map, entry_type="onemonth")


def extract_process(line):
    regexp = r"(\((.* )->\) )?\((.*)\) (\w:\\[^\<]*?)( \<\d+\>)?$"
    group_map = {"name": 2, "company": 3, "filepath": 4}
    return extract_frst_entry(line, regexp, group_map, entry_type="process")


def extract_browser_extension(line):
    regexp = r"(Edge|CHR|FF|BRA) (Extension): \((.*)\) - ([^\[]*)(\[(.*)\])?"
    group_map = {"name": 3, "filepath": 4, "date": 6}
    return extract_frst_entry(line, regexp, group_map, entry_type="browser_extension")


def extract_bho(line):
    regexp = r"BHO(-x32)?:(.*) -> \{(.*)\} -> (.*) \[(.*)\] \((.*)\)"
    group_map = {"name": 2, "clsid": 3, "filepath": 4, "date": 5, "company": 6}
    return extract_frst_entry(line, regexp, group_map, entry_type="bho")


def extract_custom_clsid(line):
    regexp = r"CustomCLSID: .*CLSID\\\{(.*)\}(.*) -> (.*)\((.*)\)"
    group_map = {"clsid": 1, "filepath": 3, "company": 4}
    return extract_frst_entry(line, regexp, group_map, entry_type="custom_clsid")


def extract_context_menu_handler(line):
    regexp = r"ContextMenuHandlers\d+: \[(.*)\] -> \{(.*)\} => (.*)\[(.*)\] \((.*)\)"
    group_map = {"name": 1, "clsid": 2, "filepath": 3, "date": 4, "company": 5}
    return extract_frst_entry(line, regexp, group_map, entry_type="context_menu_handler")


def extract_shelliconoverlayidentifiers(line):
    regexp = r"ShellIconOverlayIdentifiers(-x32)?:\s*\[(.*)\] -> \{(.*)\} => (.*) \[(.*)\] \((.*)\)"
    group_map = {"name": 2, "clsid": 3, "filepath": 4, "date": 5, "company": 6}
    return extract_frst_entry(line, regexp, group_map, entry_type="shell_icon_overlay_id")


def extract_package(line):
    regexp = r"(.*) -> (.*) \[(.*)\] \((.*)\)"
    group_map = {"name": 1, "filepath": 2, "date": 3, "company": 4}
    return extract_frst_entry(line, regexp, group_map, entry_type="package")


def extract_firewall_rule(line):
    if not line.startswith("FirewallRules:"):
        return None
    if line.rstrip().endswith("=> No File"):
        return None
    regexp = r'FirewallRules: \[([^\]]+)\] => \((Allow|Block)\) ([^\(\n]+?)\s*(?:\(([^)]+)\s*->\s*([^)]+)\))?$'
    group_map = {"name": 2, "filepath": 3, "company": 5}
    return extract_frst_entry(line, regexp, group_map, entry_type="firewall")


# Single source of truth for extractor order (first match wins) and membership.
# Extractors that don't yield a meaningful filepath are excluded from path extraction.
_NON_PATH_EXTRACTORS = frozenset({
    extract_installed_software,           # group_map yields name + company only
    extract_custom_appcompatflags,        # group_map yields clsid + name only
    extract_frst_scheduled_task_command,  # Command(N): tasks carry no real path
})

_ALL_EXTRACTORS = (
    extract_frst_service,
    extract_frst_runkey,
    extract_frst_activesetup,
    extract_frst_shortcut,
    extract_frst_scheduled_task_command,
    extract_frst_scheduled_task,
    extract_frst_scheduled_task_job,
    extract_frst_startup,
    extract_firewall_rule,
    extract_onemonth,
    extract_process,
    extract_installed_software,
    extract_browser_extension,
    extract_custom_clsid,
    extract_context_menu_handler,
    extract_bho,
    extract_shelliconoverlayidentifiers,
    extract_print_monitors,
    extract_custom_appcompatflags,
    extract_custom_appcompatsdb,
    extract_package,
)

_PATH_EXTRACTORS = tuple(fn for fn in _ALL_EXTRACTORS if fn not in _NON_PATH_EXTRACTORS)


def get_frst_entry(line):
    for extractor in _ALL_EXTRACTORS:
        entry = extractor(line)
        if entry:
            return entry
    return None


DEFENDER_EXCLUSION_PARAMS = {
    "paths": "ExclusionPath",
    "extensions": "ExclusionExtension",
    "processes": "ExclusionProcess",
    "ipaddresses": "ExclusionIpAddress",
}
# group(1): full registry key, group(2): exclusion type, group(3): value.
_DEFENDER_EXCLUSION_RE = re.compile(
    r"(?i)^(.*\\Windows Defender\\Exclusions\\([^\\|]+))\|(.*?)\s*(?:<====.*)?$"
)


def defender_exclusion_snippet(line):
    """Return a FRST remediation directive for a Windows Defender exclusion
    registry line, or None if the line isn't one.

    The four Remove-MpPreference-backed exclusion types (Paths, Extensions,
    Processes, IpAddresses) produce a `PowerShell:` directive, e.g.
    `...\\Exclusions\\Paths|C:\\Users\\Oskar\\AppData\\Local\\Temp` ->
    `PowerShell: Remove-MpPreference -ExclusionPath "C:\\Users\\Oskar\\AppData\\Local\\Temp"`.

    TemporaryPaths has no Remove-MpPreference parameter, so it is removed with
    FRST's native `DeleteValue: key|value` directive (the exclusion path is the
    registry value name). A default value (`(Default)`, or no value at all)
    yields an empty value name: `DeleteValue: key|`.

    The value is taken literally from the line (no normalize_path) so the
    generated fixlist targets the actual machine path/value.
    """
    if not line:
        return None
    match = _DEFENDER_EXCLUSION_RE.search(line.strip())
    if not match:
        return None
    key_path = match.group(1).strip()
    exclusion_type = match.group(2).strip().lower()
    value = match.group(3).strip()
    param = DEFENDER_EXCLUSION_PARAMS.get(exclusion_type)
    if param:
        if not value:
            return None
        return f'PowerShell: Remove-MpPreference -{param} "{value}"'
    if exclusion_type == "temporarypaths":
        value_name = "" if value.lower() == "(default)" else value
        return f"DeleteValue: {key_path}|{value_name}"
    return None


def extract_any_frst_path(line):
    filepath_prefix = "FILEPATH:"
    if line.startswith(filepath_prefix):
        return line[len(filepath_prefix):].strip()

    for extractor in _PATH_EXTRACTORS:
        entry = extractor(line)
        if entry and entry.filepath and "(No File)" not in line:
            return entry.filepath
    return None
