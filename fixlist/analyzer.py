import re
from typing import Iterable

from . import frst_extractors as ex
from .models import ClassificationRule, ParsedFilepathExclusion, get_default_rule_owner_id

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

FRST_END_OF_ADDITION = "==================== End of Addition.txt ======================="
FRST_END_OF_LOG = "==================== End of FRST.txt ========================"
FRST_CONTEXT_MARKERS = (
    "Farbar Recovery Scan Tool",
    "Addition.txt",
    "FRST.txt",
    "Loaded Profiles:",
)

PARSER_ORDER = [
    ex.extract_frst_runkey,
    ex.extract_print_monitors,
    ex.extract_custom_appcompatflags,
    ex.extract_custom_appcompatsdb,
    ex.extract_frst_activesetup,
    ex.extract_frst_service,
    ex.extract_frst_shortcut,
    ex.extract_frst_scheduled_task,
    ex.extract_firewall_rule,
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


def _build_warning(code: str, title: str, message: str, details: Iterable[str] | None = None) -> dict:
    detail_list = [detail for detail in (details or []) if detail]
    return {
        "code": code,
        "severity": "warning",
        "title": title,
        "message": message,
        "details": detail_list,
    }


def _detect_incomplete_log_warning(raw_log_text: str) -> dict | None:
    has_frst_context = any(marker in raw_log_text for marker in FRST_CONTEXT_MARKERS)
    if not has_frst_context:
        return None

    end_of_addition_found = FRST_END_OF_ADDITION in raw_log_text
    end_of_frst_found = FRST_END_OF_LOG in raw_log_text
    if end_of_addition_found and end_of_frst_found:
        return None

    details = [
        f"Addition end found: {'yes' if end_of_addition_found else 'no'}",
        f"FRST end found: {'yes' if end_of_frst_found else 'no'}",
    ]
    return _build_warning(
        "incomplete_logs",
        "Incomplete logs detected",
        "One or more FRST logs appear incomplete. Check that the pasted content includes the full FRST.txt and Addition.txt output.",
        details,
    )


def _detect_low_memory_warning(raw_log_text: str) -> dict | None:
    usage_percent = None
    total_mb = None
    free_gb = None
    drive_free_space_by_letter = {}
    windows_drive_letter = None
    saw_memory_context = False

    for raw_line in raw_log_text.splitlines():
        line = raw_line.strip()
        if "Percentage of memory in use:" in line:
            saw_memory_context = True
            match = re.search(r"(\d+)", line)
            if match:
                usage_percent = int(match.group(1))
        elif "Total physical RAM:" in line:
            saw_memory_context = True
            match = re.search(r"([\d.]+)", line)
            if match:
                total_mb = float(match.group(1))
        elif line.startswith("Drive"):
            saw_memory_context = True
            drive_match = re.search(r"Drive\s+([a-zA-Z]):", line, re.IGNORECASE)
            free_match = re.search(r"\(Free:\s*(\d+(?:\.\d+)?)\s*GB\)", line, re.IGNORECASE)
            if drive_match and free_match:
                drive_letter = drive_match.group(1).upper()
                drive_free_space_by_letter[drive_letter] = float(free_match.group(1))
                if re.search(r"\bWindows\b", line, re.IGNORECASE):
                    windows_drive_letter = drive_letter

    if windows_drive_letter and windows_drive_letter in drive_free_space_by_letter:
        free_gb = drive_free_space_by_letter[windows_drive_letter]
    elif "C" in drive_free_space_by_letter:
        free_gb = drive_free_space_by_letter["C"]

    if not saw_memory_context:
        return None

    threshold_usage_percent = 80
    threshold_total_ram_gb = 4
    threshold_free_space_gb = 100
    total_gb = total_mb / 1024 if total_mb is not None else None
    reasons = []
    details = []
    low_memory = False

    if total_gb is not None:
        details.append(f"Total RAM: {total_gb:.2f} GB")
        if total_gb < threshold_total_ram_gb:
            low_memory = True
            reasons.append(f"Total physical RAM below {threshold_total_ram_gb} GB")

    if usage_percent is not None:
        details.append(f"RAM usage: {usage_percent}%")
        if usage_percent > threshold_usage_percent:
            low_memory = True
            reasons.append(f"RAM usage above {threshold_usage_percent}%")

    if free_gb is not None:
        details.append(f"System drive free space: {free_gb:.2f} GB")
        if free_gb < threshold_free_space_gb:
            low_memory = True
            reasons.append(f"Free space on Windows partition below {threshold_free_space_gb} GB")

    if total_mb is None or usage_percent is None or free_gb is None:
        reasons.append("Memory information incomplete")

    if not reasons:
        return None

    title = "Low memory conditions detected" if low_memory else "Memory information incomplete"
    return _build_warning("low_memory", title, "; ".join(reasons), details)


def _detect_multiple_enabled_av_warning(raw_log_text: str) -> dict | None:
    enabled_av_lines = []

    for raw_line in (raw_log_text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("AV:"):
            continue
        if "(Enabled" not in line:
            continue
        enabled_av_lines.append(line)

    if len(enabled_av_lines) < 2:
        return None

    # Extract unique AV product names (text between "AV: " and the first "(")
    unique_products = {line.split("(")[0].strip() for line in enabled_av_lines}
    if len(unique_products) < 2:
        return None

    return _build_warning(
        "multiple_enabled_av",
        "Multiple enabled antivirus products detected",
        "Multiple AV products are enabled at the same time. Running multiple real-time AV engines can cause conflicts and performance issues.",
        [f"Detected enabled AV entries: {len(enabled_av_lines)}", *enabled_av_lines[:5]],
    )


def _build_log_warnings(raw_log_text: str) -> list[dict]:
    warnings = []
    for warning in (
        _detect_incomplete_log_warning(raw_log_text),
        _detect_low_memory_warning(raw_log_text),
        _detect_multiple_enabled_av_warning(raw_log_text),
    ):
        if warning:
            warnings.append(warning)
    return warnings


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

    fallback_path = ex.extract_any_frst_path(core)
    if fallback_path:
        rule_data["match_type"] = ClassificationRule.MATCH_FILEPATH
        rule_data["source_text"] = fallback_path
        rule_data["filepath"] = fallback_path
        rule_data["normalized_filepath"] = ex.normalize_path(fallback_path).lower().strip()

    return rule_data


def import_rules_from_lines(lines: Iterable[str], status: str, source_name: str = "", owner=None) -> dict:
    created = 0
    updated = 0
    skipped = 0
    invalid = 0
    errors = []
    owner_id = owner.id if owner is not None else get_default_rule_owner_id()

    for raw_line in lines:
        try:
            parsed = parse_rule_line(raw_line, status=status, source_name=source_name)
            if not parsed:
                skipped += 1
                continue

            lookup = {
                "owner_id": owner_id,
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
    rules = ClassificationRule.objects.filter(is_enabled=True).select_related('owner')
    parsed_filepath_exclusions = {
        (path or "").strip().lower()
        for path in ParsedFilepathExclusion.objects.filter(is_enabled=True).values_list(
            "normalized_filepath",
            flat=True,
        )
        if path
    }
    buckets = {
        ClassificationRule.MATCH_EXACT: [],
        ClassificationRule.MATCH_SUBSTRING: [],
        ClassificationRule.MATCH_REGEX: [],
        ClassificationRule.MATCH_FILEPATH: [],
        ClassificationRule.MATCH_PARSED_ENTRY: [],
        "__filepath_any": [],
        "__parsed_filepath_exclusions": parsed_filepath_exclusions,
    }

    for rule in rules:
        if rule.status not in VALID_STATUSES:
            continue

        rule_path = (rule.normalized_filepath or "").strip().lower()
        if not rule_path and rule.filepath:
            rule_path = ex.normalize_path(rule.filepath).lower().strip()
        if not rule_path and rule.source_text:
            source_path = ex.extract_any_frst_path(rule.source_text)
            if source_path:
                rule_path = ex.normalize_path(source_path).lower().strip()
        if rule_path:
            buckets["__filepath_any"].append(
                (rule, rule_path, rule.match_type == ClassificationRule.MATCH_PARSED_ENTRY)
            )

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
        for rule, rule_path, parsed_fallback in buckets["__filepath_any"]:
            if parsed_fallback and rule_path in buckets["__parsed_filepath_exclusions"]:
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


def _collect_match_groups_for_line(line: str, buckets) -> dict[str, list[tuple]]:
    groups = {
        "exact": [],
        "parsed_entry": [],
        "filepath": [],
        "substring": [],
        "regex": [],
    }

    for rule in buckets[ClassificationRule.MATCH_EXACT]:
        if rule.source_text.strip() == line.strip():
            groups["exact"].append((rule, "found exact match", "exact"))

    parsed_entries = []
    for extractor in PARSER_ORDER:
        entry = extractor(line)
        if entry:
            parsed_entries.append(entry)

    if parsed_entries:
        seen_rule_ids = set()
        for entry in parsed_entries:
            for rule, parsed_rule_entry in buckets[ClassificationRule.MATCH_PARSED_ENTRY]:
                if entry == parsed_rule_entry and rule.id not in seen_rule_ids:
                    seen_rule_ids.add(rule.id)
                    groups["parsed_entry"].append(
                        (rule, f"matched {entry.entry_type or 'parsed'} entry", "parsed_entry")
                    )

    filepath = ex.extract_any_frst_path(line)
    if filepath:
        normalized = ex.normalize_path(filepath).lower().strip()
        for rule, rule_path, parsed_fallback in buckets["__filepath_any"]:
            if parsed_fallback and rule_path in buckets["__parsed_filepath_exclusions"]:
                continue
            if normalized == rule_path:
                groups["filepath"].append((rule, "found matching normalized path", "filepath"))

    for rule in buckets[ClassificationRule.MATCH_SUBSTRING]:
        if rule.source_text and rule.source_text in line:
            groups["substring"].append((rule, f'found substring "{rule.source_text}"', "substring"))

    for rule, compiled_regex in buckets[ClassificationRule.MATCH_REGEX]:
        if compiled_regex.search(line):
            groups["regex"].append((rule, f'found regex match for "{rule.source_text}"', "regex"))

    return groups


def _collect_effective_and_shadowed_matches_for_line(line: str, buckets):
    groups = _collect_match_groups_for_line(line, buckets)
    matcher_order = ["exact", "parsed_entry", "filepath", "substring", "regex"]

    effective_matcher = "unknown"
    effective_matches = []
    shadowed_matches = []

    for index, matcher in enumerate(matcher_order):
        matches = groups.get(matcher, [])
        if matches:
            effective_matcher = matcher
            effective_matches = matches
            for later_matcher in matcher_order[index + 1 :]:
                shadowed_matches.extend(groups.get(later_matcher, []))
            break

    return effective_matches, shadowed_matches, effective_matcher


def _serialize_rule_matches(matches: list[tuple]) -> tuple[list[dict], list[str]]:
    reasons = []
    serialized_matches = []

    for rule, reason, matcher in matches:
        reason_value = reason or ""
        if reason_value:
            reasons.append(f"{rule.status}: {reason_value}")
        if rule.description:
            reasons.append(f"{rule.status}: {rule.description}")

        serialized_matches.append(
            {
                "id": rule.id,
                "status": rule.status,
                "match_type": rule.match_type,
                "source_text": rule.source_text,
                "description": rule.description,
                "source_name": rule.source_name,
                "is_enabled": rule.is_enabled,
                "entry_type": rule.entry_type,
                "clsid": rule.clsid,
                "name": rule.name,
                "filepath": rule.filepath,
                "normalized_filepath": rule.normalized_filepath,
                "filename": rule.filename,
                "company": rule.company,
                "arguments": rule.arguments,
                "file_not_signed": rule.file_not_signed,
                "matcher": matcher,
                "reason": reason_value,
                "owner_username": rule.owner.username if rule.owner_id else "",
            }
        )

    return serialized_matches, reasons


def inspect_line_matches(line: str, buckets=None) -> dict:
    line_value = (line or "").strip()
    if not line_value:
        return {
            "line": "",
            "status_codes": "?",
            "dominant_status": "?",
            "reasons": [],
            "matches": [],
        }

    active_buckets = buckets or _load_rule_buckets()
    effective_matches, shadowed_matches, effective_matcher = _collect_effective_and_shadowed_matches_for_line(
        line_value,
        active_buckets,
    )

    statuses = [rule.status for rule, _, _ in effective_matches]
    status_codes = _ordered_status_codes(statuses)
    dominant_status = _dominant_status(status_codes)
    serialized_matches, reasons = _serialize_rule_matches(effective_matches)
    serialized_shadowed_matches, _ = _serialize_rule_matches(shadowed_matches)

    return {
        "line": line_value,
        "status_codes": status_codes,
        "dominant_status": dominant_status,
        "effective_matcher": effective_matcher,
        "reasons": _dedupe(reasons),
        "matches": serialized_matches,
        "shadowed_matches": serialized_shadowed_matches,
    }


def analyze_log_text(raw_log_text: str) -> dict:
    buckets = _load_rule_buckets()
    analyzed_lines = []
    warnings = _build_log_warnings(raw_log_text or "")

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
        "warning_count": len(warnings),
    }

    return {
        "lines": analyzed_lines,
        "summary": summary,
        "warnings": warnings,
    }
