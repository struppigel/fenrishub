import ntpath
import re
from dataclasses import dataclass

DESCRIPTION_SEP = "|||Description:"


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

    def __eq__(self, other):
        if not isinstance(other, FrstEntry):
            return NotImplemented
        return (
            self.clsid.lower() == other.clsid.lower()
            and self.name == other.name
            and self.filepath.lower() == other.filepath.lower()
            and self.filename.lower() == other.filename.lower()
            and self.file_not_signed == other.file_not_signed
            and self.company == other.company
            and self.entry_type == other.entry_type
            and self.arguments == other.arguments
        )

    def __hash__(self):
        return hash(
            (
                self.clsid.lower(),
                self.name,
                self.filepath.lower(),
                self.filename.lower(),
                self.company,
                self.file_not_signed,
                self.entry_type,
                self.arguments,
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
    return re.sub(r"(?i)(C:\\Users\\)[^\\]+", r"\1" + default_username, path)


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

    clsid = get_value("clsid")
    name = get_value("name")
    filepath = normalize_path(get_value("filepath"))
    filename = (ntpath.basename(filepath) or "").strip()
    date = get_value("date")
    company = get_value("company")
    arguments = get_value("arguments")
    file_not_signed = "[File not signed]" in line
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
    )


def extract_frst_service(line):
    regexp = r"[RSU][0-5] ([^;]+); ([^[\n]+)(\[([^]]*)\] \(([^\)]*)\))?"
    group_map = {"name": 1, "filepath": 2, "date": 4, "company": 5}
    return extract_frst_entry(line, regexp, group_map, entry_type="service")


def extract_frst_runkey(line):
    regexp = r"HK(LM)?(U\\S[0-9-]+)?(-x32)?\\\.\.\.\\Run(Once)?: \[([^]]*)\] => ([^[\n]+)(\[([^]]*)\] \(([^\)]*)\))?"
    group_map = {"name": 5, "filepath": 6, "company": 8, "date": 9}
    return extract_frst_entry(line, regexp, group_map, entry_type="runkey")


def extract_frst_activesetup(line):
    regexp = r"HKLM\\[\w \\]+\\Installed Components: \[\{([^]{}]*)\}\] -> ([^[\n]+)(\[([^]]*)\] \(([^\)]*)\))?"
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


def extract_frst_scheduled_task(line):
    regexp = r"Task:\s*?\{(.*?)\}(.*?)\=>([^\[]*)[^\[]*(\[(.*?)\])?.*\((.+)\)"
    group_map = {"clsid": 1, "filepath": 3, "date": 5, "company": 6}
    return extract_frst_entry(line, regexp, group_map, entry_type="scheduled_task")


def extract_installed_software(line):
    regexp = r"(.*?)( - [\s\.\d\(\)x]*)?\(HK(LM|U)(-x32)?\\.*\((Version:.* - (.*))\)( Hidden)?"
    group_map = {"name": 1, "company": 6}
    return extract_frst_entry(line, regexp, group_map, entry_type="installed_software")


def extract_onemonth(line):
    regexp = r".* - .* - \d* .{5} (\((.*)\) )?(\w:\\.*)"
    group_map = {"company": 2, "filepath": 3}
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


_FIREWALL_CLSID_RE = re.compile(r'\{([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}')


def extract_firewall_rule(line):
    if not line.startswith("FirewallRules:"):
        return None
    if line.rstrip().endswith("=> No File"):
        return None
    regexp = r'FirewallRules: \[([^\]]+)\] => \((Allow|Block)\) ([^\(\n]+?)\s*(?:\(([^)]+)\s*->\s*([^)]+)\))?$'
    group_map = {"name": 2, "filepath": 3, "company": 5}
    entry = extract_frst_entry(line, regexp, group_map, entry_type="firewall")
    if entry:
        bracket_content = re.match(r'FirewallRules: \[([^\]]+)\]', line)
        if bracket_content:
            clsid_match = _FIREWALL_CLSID_RE.search(bracket_content.group(1))
            if clsid_match:
                entry.clsid = clsid_match.group(1)
    return entry


def get_frst_entry(line):
    extractors = [
        extract_frst_service,
        extract_frst_runkey,
        extract_frst_activesetup,
        extract_frst_shortcut,
        extract_frst_scheduled_task,
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
    ]
    for extractor in extractors:
        entry = extractor(line)
        if entry:
            return entry
    return None


def extract_any_frst_path(line):
    filepath_prefix = "FILEPATH:"
    if line.startswith(filepath_prefix):
        return line[len(filepath_prefix):].strip()

    extractors = [
        extract_frst_service,
        extract_frst_runkey,
        extract_frst_activesetup,
        extract_frst_shortcut,
        extract_frst_scheduled_task,
        extract_firewall_rule,
        extract_onemonth,
        extract_process,
        extract_browser_extension,
        extract_custom_clsid,
        extract_context_menu_handler,
        extract_bho,
        extract_shelliconoverlayidentifiers,
        extract_print_monitors,
        extract_custom_appcompatsdb,
        extract_package,
    ]
    for extractor in extractors:
        entry = extractor(line)
        if entry and entry.filepath:
            return entry.filepath
    return None
