import re
from typing import Iterable

from . import frst_extractors as ex
from .models import ClassificationRule

STATUS_PRECEDENCE = "BPC!GSIJ?"
VALID_STATUSES = set(STATUS_PRECEDENCE)

STATUS_LABELS = {
    "B": "malware",
    "P": "potentially unwanted",
    "C": "clean",
    "!": "warning",
    "G": "grayware",
    "S": "security",
    "I": "informational",
    "J": "junk",
    "?": "unknown",
}

STATUS_CSS_CLASS = {
    "B": "status-b",
    "P": "status-p",
    "C": "status-c",
    "!": "status-w",
    "G": "status-g",
    "S": "status-s",
    "I": "status-i",
    "J": "status-j",
    "?": "status-unknown",
}

PARSER_ORDER = [
    ex.extract_frst_runkey,
    ex.extract_print_monitors,
    ex.extract_custom_appcompatflags,
    ex.extract_custom_appcompatsdb,
    ex.extract_frst_activesetup,
    ex.extract_frst_service,
    ex.extract_frst_shortcut,
    ex.extract_frst_scheduled_task,
    ex.extract_process,
    ex.extract_installed_software,
    ex.extract_bho,
    ex.extract_browser_extension,
    ex.extract_custom_clsid,
    ex.extract_shelliconoverlayidentifiers,
    ex.extract_package,
    ex.extract_context_menu_handler,
]


def _ordered_status_codes(statuses: Iterable[str]) -> str:
    available = {s for s in statuses if s in VALID_STATUSES and s != "?"}
    if not available:
        return "?"
    return "".join(s for s in STATUS_PRECEDENCE if s in available)


def _dominant_status(status_codes: str) -> str:
    if not status_codes:
        return "?"
    for status in STATUS_PRECEDENCE:
        if status in status_codes:
            return status
    return "?"


def _dedupe(items: Iterable[str]) -> list[str]:
    seen = set()
    deduped = []
    for item in items:
        if item and item not in seen:
            deduped.append(item)
            seen.add(item)
    return deduped


def _line_core_and_description(raw_line: str) -> tuple[str, str]:
    core = ex.strip_description(raw_line)
    description = ex.get_description(raw_line)
    return core, description


def parse_rule_line(raw_line: str, status: str, source_name: str = "") -> dict | None:
    line = (raw_line or "").strip()
    if not line:
        return None

    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {status}")

    core, description = _line_core_and_description(line)
    if not core:
        return None

    match_type = ClassificationRule.MATCH_EXACT
    source_text = core

    rule_data = {
        "status": status,
        "match_type": match_type,
        "source_text": source_text,
        "description": description,
        "source_name": source_name,
        "entry_type": "",
        "clsid": "",
        "name": "",
        "filepath": "",
        "normalized_filepath": "",
        "filename": "",
        "company": "",
        "arguments": "",
        "file_not_signed": False,
    }

    if core.startswith("EXACT:"):
        rule_data["match_type"] = ClassificationRule.MATCH_EXACT
        rule_data["source_text"] = core[len("EXACT:") :].strip()
        return rule_data

    if core.startswith("SUBSTRING:"):
        rule_data["match_type"] = ClassificationRule.MATCH_SUBSTRING
        rule_data["source_text"] = core[len("SUBSTRING:") :].strip()
        return rule_data

    if core.startswith("REGEX:"):
        rule_data["match_type"] = ClassificationRule.MATCH_REGEX
        rule_data["source_text"] = core[len("REGEX:") :].strip()
        return rule_data

    if core.startswith("FILEPATH:"):
        path = core[len("FILEPATH:") :].strip()
        rule_data["match_type"] = ClassificationRule.MATCH_FILEPATH
        rule_data["source_text"] = path
        rule_data["filepath"] = path
        rule_data["normalized_filepath"] = ex.normalize_path(path).lower().strip() if path else ""
        return rule_data

    parsed_entry = ex.get_frst_entry(core)
    if parsed_entry:
        rule_data["match_type"] = ClassificationRule.MATCH_PARSED_ENTRY
        rule_data["source_text"] = core
        rule_data["entry_type"] = parsed_entry.entry_type
        rule_data["clsid"] = parsed_entry.clsid
        rule_data["name"] = parsed_entry.name
        rule_data["filepath"] = parsed_entry.filepath
        rule_data["normalized_filepath"] = (
            ex.normalize_path(parsed_entry.filepath).lower().strip() if parsed_entry.filepath else ""
        )
        rule_data["filename"] = parsed_entry.filename
        rule_data["company"] = parsed_entry.company
        rule_data["arguments"] = parsed_entry.arguments
        rule_data["file_not_signed"] = parsed_entry.file_not_signed
        if not rule_data["description"]:
            rule_data["description"] = parsed_entry.description

    return rule_data


def import_rules_from_lines(lines: Iterable[str], status: str, source_name: str = "") -> dict:
    created = 0
    updated = 0
    skipped = 0
    invalid = 0
    errors = []

    for raw_line in lines:
        try:
            parsed = parse_rule_line(raw_line, status=status, source_name=source_name)
            if not parsed:
                skipped += 1
                continue

            lookup = {
                "status": parsed["status"],
                "match_type": parsed["match_type"],
                "source_text": parsed["source_text"],
            }
            defaults = {
                "description": parsed["description"],
                "source_name": parsed["source_name"],
                "entry_type": parsed["entry_type"],
                "clsid": parsed["clsid"],
                "name": parsed["name"],
                "filepath": parsed["filepath"],
                "normalized_filepath": parsed["normalized_filepath"],
                "filename": parsed["filename"],
                "company": parsed["company"],
                "arguments": parsed["arguments"],
                "file_not_signed": parsed["file_not_signed"],
                "is_enabled": True,
            }
            _, is_created = ClassificationRule.objects.update_or_create(**lookup, defaults=defaults)
            if is_created:
                created += 1
            else:
                updated += 1
        except Exception as exc:  # pragma: no cover - defensive for admin uploads
            invalid += 1
            errors.append(f"{raw_line}: {exc}")

    return {
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "invalid": invalid,
        "errors": errors,
        "total": created + updated + skipped + invalid,
    }


def _load_rule_buckets():
    rules = ClassificationRule.objects.filter(is_enabled=True)
    buckets = {
        ClassificationRule.MATCH_EXACT: [],
        ClassificationRule.MATCH_SUBSTRING: [],
        ClassificationRule.MATCH_REGEX: [],
        ClassificationRule.MATCH_FILEPATH: [],
        ClassificationRule.MATCH_PARSED_ENTRY: [],
    }

    for rule in rules:
        if rule.status not in VALID_STATUSES:
            continue

        if rule.match_type == ClassificationRule.MATCH_REGEX:
            try:
                compiled = re.compile(rule.source_text)
            except re.error:
                continue
            buckets[ClassificationRule.MATCH_REGEX].append((rule, compiled))
            continue

        if rule.match_type == ClassificationRule.MATCH_PARSED_ENTRY:
            parsed_entry = ex.FrstEntry(
                clsid=rule.clsid,
                name=rule.name,
                filepath=rule.filepath,
                filename=rule.filename,
                company=rule.company,
                arguments=rule.arguments,
                file_not_signed=rule.file_not_signed,
                entry_type=rule.entry_type,
            )
            buckets[ClassificationRule.MATCH_PARSED_ENTRY].append((rule, parsed_entry))
            continue

        buckets[rule.match_type].append(rule)

    return buckets


def _status_and_reason_from_matches(matches):
    statuses = []
    reasons = []
    for rule, reason in matches:
        statuses.append(rule.status)
        if rule.description:
            reasons.append(f"{rule.status}: {rule.description}")
        if reason:
            reasons.append(f"{rule.status}: {reason}")
    return _ordered_status_codes(statuses), _dedupe(reasons)


def _build_line_result(line: str, status_codes: str, entry_type: str, reasons: list[str], matcher: str):
    dominant_status = _dominant_status(status_codes)
    return {
        "line": line,
        "status_codes": status_codes,
        "dominant_status": dominant_status,
        "status_label": STATUS_LABELS.get(dominant_status, "unknown"),
        "css_class": STATUS_CSS_CLASS.get(dominant_status, "status-unknown"),
        "entry_type": entry_type,
        "reasons": reasons,
        "matcher": matcher,
        "matched": dominant_status != "?",
    }


def _analyze_single_line(line: str, buckets):
    exact_matches = []
    for rule in buckets[ClassificationRule.MATCH_EXACT]:
        if rule.source_text.strip() == line.strip():
            exact_matches.append((rule, "found exact match"))
    if exact_matches:
        status_codes, reasons = _status_and_reason_from_matches(exact_matches)
        return _build_line_result(line, status_codes, "exactmatch", reasons, "exact")

    for extractor in PARSER_ORDER:
        entry = extractor(line)
        if not entry:
            continue

        parsed_matches = []
        for rule, parsed_rule_entry in buckets[ClassificationRule.MATCH_PARSED_ENTRY]:
            if entry == parsed_rule_entry:
                parsed_matches.append((rule, f"matched {entry.entry_type or 'parsed'} entry"))

        if parsed_matches:
            status_codes, reasons = _status_and_reason_from_matches(parsed_matches)
            return _build_line_result(line, status_codes, entry.entry_type, reasons, "parsed_entry")

    filepath = ex.extract_any_frst_path(line)
    if filepath:
        normalized = ex.normalize_path(filepath).lower().strip()
        path_matches = []
        for rule in buckets[ClassificationRule.MATCH_FILEPATH]:
            rule_path = rule.normalized_filepath or ex.normalize_path(rule.source_text).lower().strip()
            if not rule_path:
                continue
            if r":\windows\system32\cmd.exe" in rule_path:
                continue
            if normalized == rule_path:
                path_matches.append((rule, "found matching normalized path"))

        if path_matches:
            status_codes, reasons = _status_and_reason_from_matches(path_matches)
            return _build_line_result(line, status_codes, "filepath", reasons, "filepath")

    substring_matches = []
    for rule in buckets[ClassificationRule.MATCH_SUBSTRING]:
        if rule.source_text and rule.source_text in line:
            substring_matches.append((rule, f'found substring "{rule.source_text}"'))

    if substring_matches:
        status_codes, reasons = _status_and_reason_from_matches(substring_matches)
        return _build_line_result(line, status_codes, "substrings", reasons, "substring")

    regex_matches = []
    for rule, compiled_regex in buckets[ClassificationRule.MATCH_REGEX]:
        if compiled_regex.search(line):
            regex_matches.append((rule, f'found regex match for "{rule.source_text}"'))

    if regex_matches:
        status_codes, reasons = _status_and_reason_from_matches(regex_matches)
        return _build_line_result(line, status_codes, "regex", reasons, "regex")

    unknown_entry = ex.get_frst_entry(line)
    unknown_entry_type = unknown_entry.entry_type if unknown_entry else ""
    return _build_line_result(line, "?", unknown_entry_type, [], "unknown")


def analyze_log_text(raw_log_text: str) -> dict:
    buckets = _load_rule_buckets()
    analyzed_lines = []

    for raw_line in (raw_log_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        analyzed_lines.append(_analyze_single_line(line, buckets))

    status_counts = {status: 0 for status in STATUS_PRECEDENCE}
    for entry in analyzed_lines:
        status_counts[entry["dominant_status"]] += 1

    summary = {
        "total_lines": len(analyzed_lines),
        "matched_lines": len([line for line in analyzed_lines if line["matched"]]),
        "unknown_lines": status_counts["?"],
        "status_counts": status_counts,
    }

    return {
        "lines": analyzed_lines,
        "summary": summary,
    }
