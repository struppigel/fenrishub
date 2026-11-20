"""Correlations between the logs of an infection case: the fixlist/correlations
package. This module keeps the names its callers import from here.

Package layout (each module says more):
- scope: which logs a log is correlated with, and whether they come from the same machine;
- entries: the entry shapes, matches, statuses and notes; folders: folders too broad to count;
- collector: the entries of one line; defender: Defender events in Fixlogs and Addition logs;
- sources / spor_source: the index of what the related logs say, per log type;
- related: detected siblings, copies, files of the same name, files inside a folder;
- timing: lines and Spor events at the same time;
- forward: the correlations of an FRST / Addition log (computed, cached);
- reverse: the FRST / Addition lines pointing at another log's lines;
- spor_self: links between the lines of one Spor log.
"""

# flake8: noqa: F401 (re-exports)
from .correlations.scope import (
    compare, compare_with_reason, extract_signals, KIND_COMPUTER, KIND_DISK, KIND_HW, KIND_PROFILE, KIND_SID,
    log_signals, related_upload_ids, SAME_MACHINE_LABELS, same_machine_logs, same_system, SCOPE_CASE,
    SCOPE_USER, stored_signals, STRONG_KINDS, SYSTEM_DIFFERENT, SYSTEM_LIKELY, SYSTEM_SAME, SYSTEM_SIGNAL_CHARS,
    system_signals, SYSTEM_UNKNOWN, _system_verdicts, system_verdicts,
)
from .correlations.entries import (
    _add_defender_entries, _add_folder_entry, _add_path_entry, add_stored_results, _centralbox_result,
    correlation_status, defender_severity, entry_status, evidence_severity, evidence_text, _file_info_entry,
    file_name, finding_status, _first_line_numbers, FLAGGED_STATUSES, INFO_MATCHES, KIND_RANK, MALWARE_STATUSES,
    MATCH_INSIDE, MATCH_NAME, MATCH_NOTES, MATCH_SAME_HASH, MATCH_SIBLING, _MATCH_STATUSES, MATCH_TIMING,
    _mention_entry, mention_text, _NOTE_FILE_MATCHES, original_name_differs, _plain_mention, ROLE_FILES_INSIDE,
    _SEVERITY_STATUS, summary_note, _VERDICT_STATUS,
)
from .correlations.folders import (
    _BROAD_FOLDER_RE, _BROAD_PARENT_RE, is_broad_folder, is_broad_parent,
)
from .correlations.collector import (
    LineEntries, MATCH_STRENGTH, match_strength, MAX_ENTRIES_PER_LINE, MAX_INSIDE_ENTRIES, MAX_RELATED_PER_LINE,
    _rank, slot_of,
)
from .correlations.defender import (
    _addition_defender_events, _ADDITION_DEFENDER_FIELDS, _ADDITION_DEFENDER_HEADER, _ADDITION_FIELD_RE,
    _ADDITION_SECTION_END_RE, _cmdline_target, _DEFENDER_CMDLINE_RE, _defender_events, _DEFENDER_FIELD_RE,
    _DEFENDER_FILE_ENTRY_RE, _defender_real_action, _DEFENDER_VALUE_COLUMN, iter_addition_defender_detections,
    iter_defender_detections,
)
from .correlations.sources import (
    _addition_entries, _detection_entries, _fixlog_app_entries, _fixlog_entries, _frst_search_entries,
    _hash_entries, _mau_entries, _mau_mention, _shortcut_entries,
)
from .correlations.spor_source import (
    _FILES_FACT_KEYS, _software_entries, SOFTWARE_ROLES, _spor_entries, _spor_file_infos, spor_log_entries,
)
from .correlations.related import (
    _add_inside, _add_related, _both_installed, _EMPTY_SHA256, _INSIDE_WHAT, _inside_what, _INSTALLED_PREFIXES,
    _RelatedIndex,
)
from .correlations.timing import (
    _add_timing, _created_line, CreatedLine, ROLE_SAME_TIME, _spor_timeline_events, _timed_lines, TimelineEvent,
    _TIMING_CROWDED_MINUTE, _TIMING_KEEP_PREFIXES, _TIMING_RULE_ANCHORS, _TIMING_SKIP_PREFIXES,
    _TIMING_TIME_FORMAT, TIMING_WINDOW,
)
from .correlations.forward import (
    cached_correlations, _compute, correlated_sha256s, CORRELATION_VERSION, correlations_for_upload, _empty,
    _fresh_payload, _lookup, _own_defender_detections, _signature, _store,
)
from .correlations.reverse import (
    _frst_line_facts, reverse_correlations, REVERSE_MARKER_STATUSES, reverse_note, _reverse_rates,
    reverse_entry_status, reverse_status, _REVERSE_WHAT, _reverse_what,
)
