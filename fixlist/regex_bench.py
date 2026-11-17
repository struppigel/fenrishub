"""Timing helpers for spotting regexes prone to catastrophic backtracking.

A leaf module with no app imports, so the analyzer's save-time check, the admin
"bad regex" page, the ``benchmark_regex_rules`` command and ``script_matcher``
all share one set of probes and one notion of "slow".
"""
import re
import time

# Short adversarial inputs. Catastrophic patterns blow up at small sizes, so
# keeping inputs small bounds the worst-case wall time of every caller.
ADVERSARIAL_INPUTS = (
    ('a200',     'a' * 200),
    ('a200_X',   'a' * 200 + 'X'),
    ('ab100',    'ab' * 100),
    ('ab100_X',  'ab' * 100 + 'X'),
    ('slash200', ('\\' + 'a') * 100),
    ('space200', 'a ' * 100),
    ('digit200', '1' * 200),
    ('path200',  'C:\\Users\\' + 'a' * 180 + '\\file.exe'),
    ('mixed200', 'aA1\\ ' * 50),
)

SLOW_THRESHOLD_MS = 5.0

# A single wall-clock sample can be inflated by the OS descheduling us mid-run
# (CI runs the suite with --parallel on shared CPUs), so a sample that lands
# over the threshold gets re-run and the fastest reading wins -- noise only
# ever adds time. Readings far past the threshold are genuine backtracking
# blowups rather than jitter, so those are not re-run.
RETRIES = 4
RETRY_CEILING = 10.0


def time_search(compiled, payload: str) -> float:
    """Seconds one ``compiled.search(payload)`` takes."""
    start = time.perf_counter()
    try:
        compiled.search(payload)
    except re.error:
        pass
    return time.perf_counter() - start


def worst_input(compiled, threshold_s: float, *, timer=time_search) -> tuple[float, str, float]:
    """Time ``compiled`` on every adversarial input.

    Returns ``(worst seconds, label of the worst input, total seconds)``. A
    reading between the threshold and ``RETRY_CEILING`` times it is re-timed
    up to ``RETRIES`` times and the fastest reading kept.
    """
    worst = 0.0
    worst_label = ''
    total = 0.0
    for label, payload in ADVERSARIAL_INPUTS:
        elapsed = timer(compiled, payload)
        if threshold_s <= elapsed < threshold_s * RETRY_CEILING:
            for _ in range(RETRIES):
                elapsed = min(elapsed, timer(compiled, payload))
                if elapsed < threshold_s:
                    break
        total += elapsed
        if elapsed > worst:
            worst = elapsed
            worst_label = label
    return worst, worst_label, total


def non_empty_lines(text: str) -> list[str]:
    """The stripped, non-blank lines of ``text``."""
    return [line.strip() for line in (text or '').splitlines() if line.strip()]


def replay_lines(compiled, lines) -> tuple[float, float, str]:
    """Time ``compiled`` on each line: ``(total seconds, worst line seconds, worst line)``."""
    start = time.perf_counter()
    worst = 0.0
    worst_line = ''
    for line in lines:
        elapsed = time_search(compiled, line)
        if elapsed > worst:
            worst = elapsed
            worst_line = line
    return time.perf_counter() - start, worst, worst_line
