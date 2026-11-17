"""google-re2 when it is installed, stdlib `re` otherwise: the one place that knows.

re2 runs in linear time, so rule and tag regexes run through it wherever it
accepts them; patterns it refuses (lookarounds, backreferences) fall back to
stdlib `re`. google-re2's Set API is PascalCase (`Set(anchor, options)`, `Add`,
`Compile`, `Match`); pyre2-style lowercase calls would fail and silently send
everything to stdlib `re`, which is why nothing outside this module touches it.

A leaf module: no app imports.
"""
import re

try:
    import re2 as _re2
except ImportError:  # pragma: no cover - depends on the environment
    _re2 = None

RE2_AVAILABLE = _re2 is not None

# Memory budget of one compiled re2 Set (the analyzer's rules, the tags' regexes).
SET_MAX_MEM = 64 * 1024 * 1024


def _case(pattern: str, ignore_case: bool) -> str:
    return f'(?i){pattern}' if ignore_case else pattern


def compile(pattern: str, *, ignore_case: bool = False, fallback: bool = True):  # noqa: A001 - mirrors re.compile
    """The compiled pattern, preferring re2; None when it cannot be compiled.

    With re2 installed a pattern re2 refuses is compiled with stdlib `re` only
    when `fallback` is true. Without re2, stdlib `re` is always used.
    """
    if _re2 is not None:
        try:
            return _re2.compile(_case(pattern, ignore_case))
        except Exception:
            if not fallback:
                return None
    try:
        return re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error:
        return None


def re2_error(pattern: str):
    """None when re2 accepts `pattern`, else why not ('re2 binding unavailable' without re2)."""
    if _re2 is None:
        return 're2 binding unavailable'
    try:
        _re2.compile(pattern)
    except Exception as exc:
        return str(exc)
    return None


def build_set(patterns, *, ignore_case: bool = False):
    """``(re2 Set, positions)`` matching all `patterns` in one pass.

    `positions` maps a Set index back to the pattern's index in `patterns`;
    patterns re2 refuses are left out, for the caller to run one by one.
    ``(None, [])`` without re2, without patterns, or when the Set fails to build.
    """
    if _re2 is None or not patterns:
        return None, []
    try:
        options = _re2.Options()
        options.max_mem = SET_MAX_MEM
        regex_set = _re2.Set(_re2._Anchor.UNANCHORED, options)
        positions = []
        for index, pattern in enumerate(patterns):
            try:
                regex_set.Add(_case(pattern, ignore_case))
            except Exception:
                continue
            positions.append(index)
        if not positions:
            return None, []
        regex_set.Compile()
    except Exception:
        return None, []
    return regex_set, positions


def set_match(regex_set, text: str) -> list:
    """The Set indexes of the patterns matching `text` ([] on any error)."""
    try:
        matched = regex_set.Match(text)
    except Exception:
        return []
    # google-re2's Set.Match returns None (not []) when nothing matched.
    return list(matched or ())


def match_ranges(compiled, text: str) -> list:
    """``[[start, end], ...]`` of the non-empty matches of `compiled` in `text`."""
    try:
        return [[m.start(), m.end()] for m in compiled.finditer(text) if m.end() > m.start()]
    except Exception:
        return []
