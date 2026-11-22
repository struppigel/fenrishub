"""Names of the built-in log types and the groups they fall into.

A leaf module (no app imports) so models, the analyzer, the highlighters and
the views can all share these without import cycles. Log types beyond these
come from LogTypeDetectionRule rows.
"""

LOG_TYPE_UNKNOWN = 'Unknown'
LOG_TYPE_FRST = 'FRST'
LOG_TYPE_ADDITION = 'Addition'
LOG_TYPE_FRST_AND_ADDITION = 'FRST&Addition'
# Forensic triage log (spor_log); detected through a LogTypeDetectionRule.
LOG_TYPE_SPOR = 'Spor'
# FRST's "Search Files" / "SearchAll" output and the Users shortcut scan (tool_log_facts).
LOG_TYPE_FRST_SEARCH = 'FRST Search'
LOG_TYPE_SHORTCUT = 'Shortcut'
# FRST's fix results; counted by its own ops / ok / n/f stats, never by rules.
LOG_TYPE_FIXLOG = 'Fixlog'

# The FRST logs: the analyzer's original log types, which the FRST-specific
# features (correlations, incomplete-log check, statistics) still cover alone.
ANALYZED_LOG_TYPES = (LOG_TYPE_FRST, LOG_TYPE_ADDITION, LOG_TYPE_FRST_AND_ADDITION)


# Uploads of these types are never classified by rules: text of no known type,
# and Fixlogs, whose result lines name the files just removed (a file path rule
# would count them as malware).
NOT_ANALYZED_LOG_TYPES = (LOG_TYPE_UNKNOWN, LOG_TYPE_FIXLOG)


def is_analyzed_log_type(log_type) -> bool:
    """Whether uploads of this type are classified line by line (with the rules
    scoped to the type) and keep cached analyses: every detected type except
    NOT_ANALYZED_LOG_TYPES."""
    value = (log_type or '').strip()
    return bool(value) and value not in NOT_ANALYZED_LOG_TYPES
# Logs that carry an Addition.txt part.
ADDITION_LOG_TYPES = (LOG_TYPE_ADDITION, LOG_TYPE_FRST_AND_ADDITION)
# Scanner logs that list detections.
DETECTION_LOG_TYPES = ('ESET', 'Emsisoft', 'AdwCleaner', 'Malwarebytes', 'HitmanPro', 'Trojan Killer')


# ---------------------------------------------------------------------------
# Rule log-type scope
#
# A ClassificationRule applies either to every log type (`all_log_types`, which
# also covers types added later) or to the log types named in `log_types`.
# Names match exactly: a FRST&Addition log does not pick up a FRST-only rule.
# ---------------------------------------------------------------------------

import re as _re

# A log type name, as LogTypeBadge / LogTypeDetectionRule store it.
LOG_TYPE_NAME_RE = _re.compile(r'^[A-Za-z0-9][A-Za-z0-9 &._-]{0,31}$')

# The scope of a rule that does not name one: the log types the analyzer has
# always classified, so existing behaviour is unchanged.
DEFAULT_RULE_LOG_TYPES = (LOG_TYPE_FRST_AND_ADDITION, LOG_TYPE_FRST, LOG_TYPE_ADDITION)

# The wire value for "every log type" in forms and JSON payloads.
ALL_LOG_TYPES = 'all'

# Match types whose rules default to every log type: a path means the same file
# in any log, so the rule applies wherever a parser extracts paths.
_ALL_LOG_TYPES_MATCH_TYPES = frozenset({'filepath'})


def default_rule_log_types() -> list:
    """Model default for ClassificationRule.log_types."""
    return list(DEFAULT_RULE_LOG_TYPES)


def rule_scope_log_type(log_type):
    """The log type rule scopes are filtered by, or None for "every rule applies".

    No log context (rule test tools) and an undetected log ('Unknown', e.g. a
    pasted snippet without FRST headers) apply every rule, as before scopes existed.
    """
    value = (log_type or '').strip()
    if not value or value == LOG_TYPE_UNKNOWN:
        return None
    return value


def rule_applies_to(all_log_types: bool, log_types, log_type) -> bool:
    """Whether a rule with this scope classifies lines of a `log_type` log."""
    log_type = rule_scope_log_type(log_type)
    if log_type is None or all_log_types:
        return True
    return log_type in (log_types or ())


def default_rule_scope(match_type: str, context_log_type: str | None = None) -> tuple:
    """The `(all_log_types, log_types)` a new rule gets when none was chosen.

    File path rules apply to every log type. Otherwise a rule created while a
    log of some other type is open (e.g. Spor) applies to that type; everything
    else gets the FRST types.
    """
    if match_type in _ALL_LOG_TYPES_MATCH_TYPES:
        return True, []
    context = (context_log_type or '').strip()
    if context and context != LOG_TYPE_UNKNOWN and context not in DEFAULT_RULE_LOG_TYPES:
        return False, [context]
    return False, list(DEFAULT_RULE_LOG_TYPES)


def normalize_log_type_selection(value) -> tuple:
    """Parse a scope from a payload: `"all"` or a list of log type names.

    Returns `((all_log_types, log_types), error)`; `error` is a message or None.
    Names are stripped and de-duplicated in order.
    """
    if isinstance(value, str) and value.strip().lower() == ALL_LOG_TYPES:
        return (True, []), None
    if not isinstance(value, (list, tuple)):
        return None, 'log types must be "all" or a list of log type names'
    names = []
    for item in value:
        if not isinstance(item, str):
            return None, 'log type names must be strings'
        name = item.strip()
        if not name:
            continue
        if not LOG_TYPE_NAME_RE.match(name) or name.lower() == LOG_TYPE_UNKNOWN.lower():
            return None, f'invalid log type name: {name[:40]}'
        if name not in names:
            names.append(name)
    if not names:
        return None, 'select at least one log type, or "all"'
    return (False, names), None


def scope_payload(all_log_types: bool, log_types) -> object:
    """The JSON / wire form of a scope: `"all"` or the list of names."""
    return ALL_LOG_TYPES if all_log_types else list(log_types or [])


def scope_label(all_log_types: bool, log_types) -> str:
    """Short human label: "all logs" or the comma-joined names."""
    if all_log_types:
        return 'all logs'
    return ', '.join(log_types or []) or 'no logs'
