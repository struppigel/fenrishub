import re
import time
from datetime import datetime
from typing import Iterable

from . import frst_extractors as ex
from .models import ClassificationRule, ParsedFilepathExclusion, get_default_rule_owner_id, detect_log_type

STATUS_PRECEDENCE = "BPCA!GSIJ?"
VALID_STATUSES = set(STATUS_PRECEDENCE)

STATUS_LABELS = {
    "B": "malware",
    "P": "potentially unwanted",
    "C": "clean",
    "!": "warning",
    "A": "alert",
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
    "A": "status-a",
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


def _build_alert_rule_warnings(analyzed_lines: list[dict]) -> list[dict]:
    seen_descriptions = set()
    ordered_descriptions = []

    for entry in analyzed_lines:
        for description in entry.get("_alert_descriptions", []):
            value = (description or "").strip()
            if not value or value in seen_descriptions:
                continue
            seen_descriptions.add(value)
            ordered_descriptions.append(value)

    warnings = []
    for index, description in enumerate(ordered_descriptions, start=1):
        warnings.append(
            _build_warning(
                code=f"alert_rule_{index}",
                title="Alert rule matched",
                message=description,
            )
        )
    return warnings


def _detect_incomplete_log_warning(raw_log_text: str) -> dict | None:
    detected_type = detect_log_type(raw_log_text or "")
    if detected_type not in {"FRST", "Addition", "FRST&Addition"}:
        return None

    end_of_addition_found = FRST_END_OF_ADDITION in raw_log_text
    end_of_frst_found = FRST_END_OF_LOG in raw_log_text

    if detected_type == "FRST":
        is_complete = end_of_frst_found
        expected_endings = ["FRST end marker"]
    elif detected_type == "Addition":
        is_complete = end_of_addition_found
        expected_endings = ["Addition end marker"]
    else:
        is_complete = end_of_frst_found and end_of_addition_found
        expected_endings = ["FRST end marker", "Addition end marker"]

    if is_complete:
        return None

    details = [
        f"Detected log type: {detected_type}",
        f"Expected endings: {', '.join(expected_endings)}",
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
    threshold_free_space_gb = 50
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


def _detect_recent_restore_operation_warning(raw_log_text: str) -> dict | None:
    """Detect if a system restore operation occurred in the last 7 days."""
    restore_operations = []
    
    for raw_line in (raw_log_text or "").splitlines():
        line = raw_line.strip()
        # Look for lines containing "Restore Operation"
        if "Restore Operation" not in line:
            continue
        
        # Try to parse datetime from the beginning of the line
        # Expected format: DD-MM-YYYY HH:MM:SS Restore Operation
        match = re.match(r"(\d{2})-(\d{2})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\s+.*Restore Operation", line)
        if not match:
            continue
        
        try:
            day, month, year, hour, minute, second = map(int, match.groups())
            restore_dt = datetime(year, month, day, hour, minute, second)
            restore_operations.append(restore_dt)
        except (ValueError, TypeError):
            # Invalid date values, skip
            continue
    
    if not restore_operations:
        return None
    
    # Get the most recent restore operation
    latest_restore = max(restore_operations)
    now = datetime.now()
    time_diff = now - latest_restore
    days_ago = time_diff.days
    
    # Show warning if within the last 7 days
    if days_ago > 7:
        return None
    
    # Calculate fractional days for more precise messaging
    total_hours = time_diff.total_seconds() / 3600
    formatted_time = latest_restore.strftime("%Y-%m-%d %H:%M:%S")
    
    # Build warning message
    if days_ago == 0:
        time_str = f"today at {latest_restore.strftime('%H:%M:%S')}"
    elif days_ago == 1:
        time_str = f"yesterday at {latest_restore.strftime('%H:%M:%S')}"
    else:
        time_str = f"{days_ago} days ago on {formatted_time}"
    
    message = f"System restore operation detected {time_str}. This could indicate malware removal attempts."
    details = [
        f"Restore date/time: {formatted_time}",
        f"Days ago: {days_ago}",
        f"Total restore operations detected: {len(restore_operations)}",
    ]
    
    return _build_warning(
        "recent_restore_operation",
        "Recent system restore operation detected",
        message,
        details,
    )


def _build_log_warnings(raw_log_text: str) -> list[dict]:
    warnings = []
    for warning in (
        _detect_incomplete_log_warning(raw_log_text),
        _detect_low_memory_warning(raw_log_text),
        _detect_multiple_enabled_av_warning(raw_log_text),
        _detect_recent_restore_operation_warning(raw_log_text),
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


_rule_buckets_cache = None
_rule_buckets_cache_time = None
_RULE_BUCKETS_CACHE_TTL = 60


def invalidate_rule_buckets_cache():
    global _rule_buckets_cache, _rule_buckets_cache_time
    _rule_buckets_cache = None
    _rule_buckets_cache_time = None


def _get_cached_rule_buckets():
    global _rule_buckets_cache, _rule_buckets_cache_time
    now = time.monotonic()
    if _rule_buckets_cache is not None and (now - _rule_buckets_cache_time) < _RULE_BUCKETS_CACHE_TTL:
        return _rule_buckets_cache
    _rule_buckets_cache = _load_rule_buckets()
    _rule_buckets_cache_time = now
    return _rule_buckets_cache


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
    alert_descriptions = []
    for rule, reason in matches:
        statuses.append(rule.status)
        if rule.description:
            reasons.append(f"{rule.status}: {rule.description}")
            if rule.status == ClassificationRule.STATUS_ALERT:
                alert_descriptions.append(rule.description)
        if reason:
            reasons.append(f"{rule.status}: {reason}")
    return _ordered_status_codes(statuses), _dedupe(reasons), _dedupe(alert_descriptions)


def _build_line_result(
    line: str,
    status_codes: str,
    entry_type: str,
    reasons: list[str],
    matcher: str,
    alert_descriptions: list[str] | None = None,
):
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
        "_alert_descriptions": alert_descriptions or [],
    }


def _analyze_single_line(line: str, buckets):
    exact_matches = []
    for rule in buckets[ClassificationRule.MATCH_EXACT]:
        if rule.source_text.strip() == line.strip():
            exact_matches.append((rule, "found exact match"))
    if exact_matches:
        status_codes, reasons, alert_descriptions = _status_and_reason_from_matches(exact_matches)
        return _build_line_result(
            line,
            status_codes,
            "exactmatch",
            reasons,
            "exact",
            alert_descriptions,
        )

    for extractor in PARSER_ORDER:
        entry = extractor(line)
        if not entry:
            continue

        parsed_matches = []
        for rule, parsed_rule_entry in buckets[ClassificationRule.MATCH_PARSED_ENTRY]:
            if entry == parsed_rule_entry:
                parsed_matches.append((rule, f"matched {entry.entry_type or 'parsed'} entry"))

        if parsed_matches:
            status_codes, reasons, alert_descriptions = _status_and_reason_from_matches(parsed_matches)
            return _build_line_result(
                line,
                status_codes,
                entry.entry_type,
                reasons,
                "parsed_entry",
                alert_descriptions,
            )

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
            status_codes, reasons, alert_descriptions = _status_and_reason_from_matches(path_matches)
            return _build_line_result(
                line,
                status_codes,
                "filepath",
                reasons,
                "filepath",
                alert_descriptions,
            )

    substring_matches = []
    for rule in buckets[ClassificationRule.MATCH_SUBSTRING]:
        if rule.source_text and rule.source_text in line:
            substring_matches.append((rule, f'found substring "{rule.source_text}"'))

    if substring_matches:
        status_codes, reasons, alert_descriptions = _status_and_reason_from_matches(substring_matches)
        return _build_line_result(
            line,
            status_codes,
            "substrings",
            reasons,
            "substring",
            alert_descriptions,
        )

    regex_matches = []
    for rule, compiled_regex in buckets[ClassificationRule.MATCH_REGEX]:
        if compiled_regex.search(line):
            regex_matches.append((rule, f'found regex match for "{rule.source_text}"'))

    if regex_matches:
        status_codes, reasons, alert_descriptions = _status_and_reason_from_matches(regex_matches)
        return _build_line_result(
            line,
            status_codes,
            "regex",
            reasons,
            "regex",
            alert_descriptions,
        )

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

    active_buckets = buckets or _get_cached_rule_buckets()
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
    buckets = _get_cached_rule_buckets()
    analyzed_lines = []
    warnings = _build_log_warnings(raw_log_text or "")

    for raw_line in (raw_log_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        analyzed_lines.append(_analyze_single_line(line, buckets))

    warnings.extend(_build_alert_rule_warnings(analyzed_lines))
    for entry in analyzed_lines:
        entry.pop("_alert_descriptions", None)

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
