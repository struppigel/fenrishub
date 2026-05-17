import re
import time
from datetime import datetime
from typing import Iterable

try:
    import re2 as _re2
except ImportError:
    _re2 = None

from . import frst_extractors as ex
from .models import ClassificationRule, ParsedFilepathExclusion, get_default_rule_owner_id, detect_log_type
from .status_types import (
    STATUS_PRECEDENCE,
    VALID_STATUSES,
    STATUS_LABELS,
    STATUS_CSS_CLASS,
)

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
    ex.extract_frst_scheduled_task_command,
    ex.extract_frst_scheduled_task,
    ex.extract_frst_startup,
    ex.extract_firewall_rule,
    ex.extract_onemonth,
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


_OS_INSTALL_DATE_RE = re.compile(
    r"^Microsoft\s+Windows\b.*?\((?:X64|X86|ARM64)\)\s+"
    r"\((\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\)\s*$",
    re.IGNORECASE,
)

_OS_INSTALL_CORROBORATING_SIGNS = (
    (r"C:\Windows.old", "C:\\Windows.old present (in-place upgrade leftover, normally removed after ~10 days)"),
    (r"C:\Windows\Panther", "C:\\Windows\\Panther present (Windows setup artifacts directory)"),
    (r"C:\$WINDOWS.~BT", "C:\\$WINDOWS.~BT present (install staging directory)"),
    (r"C:\$WINDOWS.~WS", "C:\\$WINDOWS.~WS present (install staging directory)"),
)

# Top-level user profile folder creation in FRST "One month (created)" entries:
#   2026-05-16 17:47 - 2026-05-16 19:17 - 000000000 ____D C:\Users\caber
_USER_PROFILE_CREATE_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2})\s+-\s+"
    r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+-\s+"
    r"\d+\s+[A-Z_]*D[A-Z_]*\s+"
    r"C:\\Users\\([^\\\s]+)\s*$",
    re.IGNORECASE,
)
_SYSTEM_USER_PROFILES = frozenset({
    "public", "default", "default user", "all users",
    "defaultaccount", "wdagutilityaccount",
})

_ONE_MONTH_CREATED_HEADER = "One month (created)"
_ONE_MONTH_ENTRY_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2})\s+-\s+"
)


def _find_user_profile_created_near_install(raw_log_text: str, install_dt: datetime) -> str | None:
    """Return a non-system username whose profile folder was created within 24h of install."""
    for raw_line in (raw_log_text or "").splitlines():
        match = _USER_PROFILE_CREATE_RE.match(raw_line.strip())
        if not match:
            continue
        try:
            created = datetime(
                int(match.group(1)), int(match.group(2)), int(match.group(3)),
                int(match.group(4)), int(match.group(5)),
            )
        except (ValueError, TypeError):
            continue
        username = match.group(6)
        if username.lower() in _SYSTEM_USER_PROFILES:
            continue
        if abs((created - install_dt).total_seconds()) <= 24 * 3600:
            return username
    return None


def _find_oldest_one_month_created(raw_log_text: str) -> datetime | None:
    """Return the earliest creation date in FRST's 'One month (created)' section."""
    in_section = False
    earliest = None
    for raw_line in (raw_log_text or "").splitlines():
        line = raw_line.strip()
        if "====" in line:
            if _ONE_MONTH_CREATED_HEADER in line:
                in_section = True
                continue
            if in_section:
                # A subsequent section delimiter ends the "One month (created)" block.
                break
            continue
        if not in_section:
            continue
        match = _ONE_MONTH_ENTRY_RE.match(line)
        if not match:
            continue
        try:
            candidate = datetime(
                int(match.group(1)), int(match.group(2)), int(match.group(3)),
                int(match.group(4)), int(match.group(5)),
            )
        except (ValueError, TypeError):
            continue
        if earliest is None or candidate < earliest:
            earliest = candidate
    return earliest


def _detect_recent_os_install_warning(raw_log_text: str) -> dict | None:
    """Detect if Windows was installed or feature-updated within the last 7 days."""
    install_dt = None
    for raw_line in (raw_log_text or "").splitlines():
        match = _OS_INSTALL_DATE_RE.match(raw_line.strip())
        if not match:
            continue
        try:
            year, month, day, hour, minute, second = map(int, match.groups())
            candidate = datetime(year, month, day, hour, minute, second)
        except (ValueError, TypeError):
            continue
        if install_dt is None:
            install_dt = candidate

    if install_dt is None:
        return None

    now = datetime.now()
    time_diff = now - install_dt
    if time_diff.total_seconds() < 0:
        return None
    days_ago = time_diff.days
    if days_ago > 7:
        return None

    formatted_time = install_dt.strftime("%Y-%m-%d %H:%M:%S")
    if days_ago == 0:
        time_str = f"today at {install_dt.strftime('%H:%M:%S')}"
    elif days_ago == 1:
        time_str = f"yesterday at {install_dt.strftime('%H:%M:%S')}"
    else:
        time_str = f"{days_ago} days ago on {formatted_time}"

    haystack = (raw_log_text or "").lower()
    corroborating = [
        description
        for needle, description in _OS_INSTALL_CORROBORATING_SIGNS
        if needle.lower() in haystack
    ]

    profile_username = _find_user_profile_created_near_install(raw_log_text, install_dt)
    if profile_username:
        corroborating.append(
            f"User profile C:\\Users\\{profile_username} created near install date"
        )

    oldest_created = _find_oldest_one_month_created(raw_log_text)
    if oldest_created is not None and oldest_created.date() == install_dt.date():
        corroborating.append(
            "Oldest file in 'One month (created)' section dates to install day"
        )

    message = (
        f"Windows install or feature-update date is {time_str}. "
    )
    details = []
    if corroborating:
        details.append("Corroborating signs:")
        details.extend(f"  - {sign}" for sign in corroborating)

    return _build_warning(
        "recent_os_install",
        "Recent Windows install or feature update detected",
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
        _detect_recent_os_install_warning(raw_log_text),
    ):
        if warning:
            warnings.append(warning)
    return warnings


_BARE_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/])")


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
        "attributes": "",
        "is_hidden": False,
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
        rule_data["attributes"] = parsed_entry.attributes
        rule_data["is_hidden"] = parsed_entry.is_hidden
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

    # Bare path (no FRST line shape): `C:\foo\bar` or `\\server\share\foo` — treat
    # as a filepath rule so the import flow and the re-parse don't silently
    # downgrade these to exact.
    if _BARE_PATH_RE.match(core):
        rule_data["match_type"] = ClassificationRule.MATCH_FILEPATH
        rule_data["source_text"] = core
        rule_data["filepath"] = core
        rule_data["normalized_filepath"] = ex.normalize_path(core).lower().strip()

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
                "attributes": parsed["attributes"],
                "is_hidden": parsed["is_hidden"],
                "is_enabled": True,
            }
            rule, is_created = ClassificationRule.objects.update_or_create(**lookup, defaults=defaults)
            if is_created:
                created += 1
                default_priority = ClassificationRule.default_priority_for(parsed["match_type"])
                if rule.priority != default_priority:
                    rule.priority = default_priority
                    rule.save(update_fields=["priority", "updated_at"])
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


REPARSE_FIELDS = (
    "entry_type",
    "clsid",
    "name",
    "filepath",
    "normalized_filepath",
    "filename",
    "company",
    "arguments",
    "file_not_signed",
    "attributes",
    "is_hidden",
)


def reparse_rules(queryset, *, apply: bool = False):
    """Re-parse each rule's `source_text` and report (or write) field diffs.

    Never changes `match_type` — `parse_rule_line` defaults to EXACT when it
    can't recognize a line, and silently flipping `parsed_entry` → `exact` would
    destroy the rule's matching semantics. Rules whose re-parse yields a
    different `match_type` are left untouched and counted under `match_type_skip`.

    Returns a dict with counts and a list of per-rule diffs. Used by both the
    `reparse_rules` management command and the admin action.
    """
    diffs = []
    unchanged = 0
    unparseable = 0
    match_type_skip = 0

    for rule in queryset.iterator():
        parsed = parse_rule_line(rule.source_text, rule.status, rule.source_name)
        if parsed is None:
            unparseable += 1
            continue

        if parsed.get("match_type") != rule.match_type:
            match_type_skip += 1
            continue

        per_field = {}
        for field in REPARSE_FIELDS:
            old_value = getattr(rule, field)
            new_value = parsed.get(field)
            if old_value != new_value:
                per_field[field] = (old_value, new_value)

        if not per_field:
            unchanged += 1
            continue

        diffs.append({"rule": rule, "fields": per_field})

        if apply:
            from django.db import transaction as _txn

            with _txn.atomic():
                for field in REPARSE_FIELDS:
                    setattr(rule, field, parsed.get(field))
                rule.save(update_fields=[*REPARSE_FIELDS, "updated_at"])

    if apply and diffs:
        invalidate_rule_buckets_cache()

    return {
        "changed": len(diffs),
        "unchanged": unchanged,
        "unparseable": unparseable,
        "match_type_skip": match_type_skip,
        "diffs": diffs,
    }


def find_rule_duplicates(queryset):
    """Group rules whose comparison-relevant fields AND status are identical.

    Returns a list of groups; each group is a list of >=2 ClassificationRule
    objects sharing the same matching identity. Used by both the admin
    "Find duplicates" view and the `find_duplicates` management command.

    Parsed-entry rules group on the FrstEntry.__eq__ field set (with CLSID
    omitted from the key for SYSTEM_SPECIFIC_CLSID_TYPES). Filepath rules
    group on normalized_filepath alone. The two never collide because the
    group key starts with match_type.
    """
    from collections import defaultdict

    groups = defaultdict(list)
    for rule in queryset.iterator():
        if rule.match_type == ClassificationRule.MATCH_PARSED_ENTRY:
            clsid = (
                "" if rule.entry_type in ex.SYSTEM_SPECIFIC_CLSID_TYPES
                else (rule.clsid or "").lower()
            )
            key = (
                rule.match_type,
                rule.status,
                rule.entry_type or "",
                clsid,
                rule.name or "",
                (rule.filepath or "").lower(),
                (rule.filename or "").lower(),
                bool(rule.file_not_signed),
                bool(rule.is_hidden),
                rule.company or "",
                rule.arguments or "",
                rule.attributes or "",
            )
        elif rule.match_type == ClassificationRule.MATCH_FILEPATH:
            normalized = (rule.normalized_filepath or "").strip().lower()
            if not normalized:
                continue
            key = (rule.match_type, rule.status, normalized)
        else:
            continue
        groups[key].append(rule)

    return [
        sorted(rules, key=lambda r: r.id)
        for rules in groups.values()
        if len(rules) >= 2
    ]


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
        "__regex_set": None,
        "__regex_set_rules": [],
    }

    pending_regex_rules = []

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
            pending_regex_rules.append(rule)
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
                attributes=rule.attributes,
                is_hidden=rule.is_hidden,
            )
            buckets[ClassificationRule.MATCH_PARSED_ENTRY].append((rule, parsed_entry))
            continue

        buckets[rule.match_type].append(rule)

    _build_regex_matchers(buckets, pending_regex_rules)
    return buckets


def _build_regex_matchers(buckets, regex_rules):
    """Compile regex rules into a re2.Set for one-pass multi-pattern matching.

    Patterns rejected by re2 (backreferences, lookaround, syntax it doesn't support)
    fall back to stdlib re. If re2 is unavailable, all rules use stdlib re.
    """
    if not regex_rules:
        return

    fallback_bucket = buckets[ClassificationRule.MATCH_REGEX]

    def _add_to_fallback(rule):
        try:
            compiled = re.compile(rule.source_text)
        except re.error:
            return
        fallback_bucket.append((rule, compiled))

    if _re2 is None:
        for rule in regex_rules:
            _add_to_fallback(rule)
        return

    try:
        options = _re2.Options()
        options.max_mem = 64 * 1024 * 1024
        regex_set = _re2.Set(options, _re2.Anchor.UNANCHORED)
    except Exception:
        for rule in regex_rules:
            _add_to_fallback(rule)
        return

    set_rules = []
    for rule in regex_rules:
        try:
            regex_set.add(rule.source_text)
        except Exception:
            _add_to_fallback(rule)
            continue
        set_rules.append(rule)

    if not set_rules:
        return

    try:
        regex_set.compile()
    except Exception:
        for rule in set_rules:
            _add_to_fallback(rule)
        return

    buckets["__regex_set"] = regex_set
    buckets["__regex_set_rules"] = set_rules


def _owner_suffix(rule) -> str:
    if rule.owner_id and getattr(rule.owner, "username", ""):
        return f" (by {rule.owner.username})"
    return ""


def _status_and_reason_from_matches(matches):
    statuses = []
    reasons = []
    alert_descriptions = []
    for rule, reason in matches:
        statuses.append(rule.status)
        owner_suffix = _owner_suffix(rule)
        if rule.description:
            reasons.append(f"{rule.status}: {rule.description}{owner_suffix}")
            if rule.status == ClassificationRule.STATUS_ALERT:
                alert_descriptions.append(rule.description)
        if reason:
            reasons.append(f"{rule.status}: {reason}{owner_suffix}")
    return _ordered_status_codes(statuses), _dedupe(reasons), _dedupe(alert_descriptions)


_ONEMONTH_DATES_RE = re.compile(
    r"^(?:Found path already in\s+)?"
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?) - "
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?) - "
)
# Captures "YYYY-MM-DD" or "YYYY-MM-DD HH:MM(:SS)?" anywhere within a string.
# Used to strip the leading file size out of FRST's "[size date]" bracket format.
_DATE_NORMALIZE_RE = re.compile(r"(\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}(?::\d{2})?)?)")


def _extract_dates(line: str, parsed_entry) -> list[str]:
    if parsed_entry is None:
        return []
    if parsed_entry.entry_type == "onemonth":
        match = _ONEMONTH_DATES_RE.match(line)
        if match:
            t1, t2 = match.group(1), match.group(2)
            return [t1, t2] if t1 != t2 else [t1]
    if parsed_entry.date:
        match = _DATE_NORMALIZE_RE.search(parsed_entry.date)
        if match:
            return [match.group(1)]
    return []


def _build_line_result(
    line: str,
    status_codes: str,
    entry_type: str,
    reasons: list[str],
    matcher: str,
    alert_descriptions: list[str] | None = None,
    dates: list[str] | None = None,
    parsed_entry=None,
    filepath_highlight: dict | None = None,
):
    dominant_status = _dominant_status(status_codes)
    components = {}
    if parsed_entry is not None:
        for key in ("clsid", "name", "company"):
            value = getattr(parsed_entry, key, "") or ""
            if value:
                components[key] = value
        for key in ("filepath", "filename"):
            normalized = getattr(parsed_entry, key, "") or ""
            if not normalized:
                continue
            pos = ex.find_value_position(normalized, line, key)
            if pos:
                components[key] = line[pos[0]:pos[1]]
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
        "dates": dates or [],
        "components": components,
        "filepath_highlight": filepath_highlight,
        "_alert_descriptions": alert_descriptions or [],
    }


def _build_filepath_highlight_payload(line: str, status_codes: str) -> dict:
    dominant_status = _dominant_status(status_codes)
    payload = {
        "status": dominant_status,
        "css_class": STATUS_CSS_CLASS.get(dominant_status, "status-unknown"),
    }
    filepath_value = ex.extract_any_frst_path(line)
    if not filepath_value:
        return payload
    pos = ex.find_value_position(filepath_value, line, "filepath")
    if pos:
        payload["start"] = pos[0]
        payload["end"] = pos[1]
    return payload


def _all_matches_are_parsed_entry_filepath_fallback(matches) -> bool:
    """A parsed-entry fallback is a match where the rule's own type is
    `parsed_entry` but the line only matched via the rule's stored filepath.
    Those matches should colour just the filepath rather than flip the verdict —
    the rule's parsed entry didn't actually match the line shape."""
    if not matches:
        return False
    return all(
        matcher == "filepath"
        and rule.match_type != ClassificationRule.MATCH_FILEPATH
        for rule, _reason, matcher in matches
    )


_MATCHER_ENTRY_TYPE_LABELS = {
    "exact": "exactmatch",
    "filepath": "filepath",
    "substring": "substrings",
    "regex": "regex",
}
_MATCHER_PREFERENCE = ("parsed_entry", "exact", "filepath", "substring", "regex")


def _entry_type_for_winning_group(top_matches, parsed_entry):
    matchers = {m[2] for m in top_matches}
    if "parsed_entry" in matchers:
        for rule, _reason, matcher in top_matches:
            if matcher == "parsed_entry" and rule.entry_type:
                return rule.entry_type
        return "parsed"
    for matcher in _MATCHER_PREFERENCE:
        if matcher in matchers and matcher in _MATCHER_ENTRY_TYPE_LABELS:
            return _MATCHER_ENTRY_TYPE_LABELS[matcher]
    return parsed_entry.entry_type if parsed_entry else ""


def _analyze_single_line(line: str, buckets):
    parsed_entry = ex.get_frst_entry(line)
    dates = _extract_dates(line, parsed_entry)

    effective_matches, _shadowed, matcher_label, _top_priority = (
        _collect_effective_and_shadowed_matches_for_line(line, buckets)
    )

    if not effective_matches:
        unknown_entry_type = parsed_entry.entry_type if parsed_entry else ""
        return _build_line_result(
            line, "?", unknown_entry_type, [], "unknown",
            dates=dates, parsed_entry=parsed_entry,
        )

    status_codes, reasons, alert_descriptions = _status_and_reason_from_matches(
        [(rule, reason) for rule, reason, _matcher in effective_matches]
    )

    if _all_matches_are_parsed_entry_filepath_fallback(effective_matches):
        fallback_entry_type = parsed_entry.entry_type if parsed_entry else ""
        result = _build_line_result(
            line,
            status_codes,
            fallback_entry_type,
            reasons,
            "filepath",
            alert_descriptions,
            dates=dates,
            parsed_entry=parsed_entry,
            filepath_highlight=_build_filepath_highlight_payload(line, status_codes),
        )
        # Verdict is set (badge shows the rule's status), but the surrounding
        # line text should not take the verdict colour — only the filepath
        # substring does, via filepath_highlight.
        result["css_class"] = STATUS_CSS_CLASS.get("?", "status-unknown")
        return result

    entry_type = _entry_type_for_winning_group(effective_matches, parsed_entry)
    return _build_line_result(
        line,
        status_codes,
        entry_type,
        reasons,
        matcher_label,
        alert_descriptions,
        dates=dates,
        parsed_entry=parsed_entry,
    )


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

    regex_set = buckets.get("__regex_set")
    if regex_set is not None:
        set_rules = buckets["__regex_set_rules"]
        try:
            matched_indices = regex_set.match(line)
        except Exception:
            matched_indices = ()
        for idx in matched_indices:
            rule = set_rules[idx]
            groups["regex"].append((rule, f'found regex match for "{rule.source_text}"', "regex"))

    for rule, compiled_regex in buckets[ClassificationRule.MATCH_REGEX]:
        if compiled_regex.search(line):
            groups["regex"].append((rule, f'found regex match for "{rule.source_text}"', "regex"))

    return groups


_MATCH_TYPE_TO_PRIMARY_MATCHER = {
    ClassificationRule.MATCH_EXACT: "exact",
    ClassificationRule.MATCH_PARSED_ENTRY: "parsed_entry",
    ClassificationRule.MATCH_FILEPATH: "filepath",
    ClassificationRule.MATCH_SUBSTRING: "substring",
    ClassificationRule.MATCH_REGEX: "regex",
}

_FILEPATH_FALLBACK_EFFECTIVE_PRIORITY = 1


def _matcher_preference(rule, matcher: str) -> int:
    """Lower is preferred. Parsed entry beats everything; otherwise the rule's own match_type wins."""
    if matcher == "parsed_entry":
        return 0
    if matcher == _MATCH_TYPE_TO_PRIMARY_MATCHER.get(rule.match_type):
        return 1
    return 2


def _effective_match_priority(rule, matcher: str) -> int:
    """Effective priority for a specific match instance.

    Filepath fallback matches for non-filepath rules are intentionally weak so
    they cannot dominate true primary matches from other rules.
    """
    if matcher == "filepath" and rule.match_type != ClassificationRule.MATCH_FILEPATH:
        return _FILEPATH_FALLBACK_EFFECTIVE_PRIORITY
    return rule.priority


def _dedupe_matches_by_rule(matches):
    by_rule_id = {}
    for entry in matches:
        rule, _reason, matcher = entry
        existing = by_rule_id.get(rule.id)
        if existing is None or _matcher_preference(rule, matcher) < _matcher_preference(rule, existing[2]):
            by_rule_id[rule.id] = entry
    return list(by_rule_id.values())


def _collect_effective_and_shadowed_matches_for_line(line: str, buckets):
    groups = _collect_match_groups_for_line(line, buckets)
    flat = _dedupe_matches_by_rule(m for matches in groups.values() for m in matches)

    if not flat:
        return [], [], "unknown", None

    top_priority = max(_effective_match_priority(rule, matcher) for rule, _reason, matcher in flat)
    effective_matches = [
        m for m in flat if _effective_match_priority(m[0], m[2]) == top_priority
    ]
    shadowed_matches = [
        m for m in flat if _effective_match_priority(m[0], m[2]) < top_priority
    ]

    matchers = sorted({m[2] for m in effective_matches})
    effective_matcher = matchers[0] if len(matchers) == 1 else f"priority:{top_priority}"

    return effective_matches, shadowed_matches, effective_matcher, top_priority


def _serialize_rule_matches(matches: list[tuple]) -> tuple[list[dict], list[str]]:
    reasons = []
    serialized_matches = []

    for rule, reason, matcher in matches:
        reason_value = reason or ""
        owner_suffix = _owner_suffix(rule)
        if reason_value:
            reasons.append(f"{rule.status}: {reason_value}{owner_suffix}")
        if rule.description:
            reasons.append(f"{rule.status}: {rule.description}{owner_suffix}")

        serialized_matches.append(
            {
                "id": rule.id,
                "status": rule.status,
                "match_type": rule.match_type,
                "priority": rule.priority,
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
    (
        effective_matches,
        shadowed_matches,
        effective_matcher,
        effective_priority,
    ) = _collect_effective_and_shadowed_matches_for_line(line_value, active_buckets)

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
        "effective_priority": effective_priority,
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
