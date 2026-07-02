"""Sandboxed execution for ``script`` classification rules.

A script rule lets a (moderator-authored) Python snippet decide whether a log
line matches. The snippet receives the line via the ``line`` variable and signals
a match by assigning ``result``:

    result = line.startswith("R2 ") and "evil" in line.lower()
    # or, explicitly:
    result = "MATCH" if some_condition else "NOMATCH"

``result`` is truthy / equal to ``"MATCH"`` (case-insensitive) -> MATCH; anything
else (falsy, ``"NOMATCH"``, or unset) -> NOMATCH.

Snippets are compiled with ``RestrictedPython.compile_restricted`` and executed in
a guarded namespace: no imports, no file/network access, no dunder/attribute
escapes. A curated set of pure builtins (``len``, ``any``, ``min`` ...) plus the
stdlib ``re`` module are exposed, so snippets can use regular expressions:

    m = re.search(r"C:\\\\Users\\\\([^\\\\]+)", line)
    result = bool(m) and m.group(1).startswith("ADMIN")

Residual risk: an in-process sandbox cannot hard-kill a CPU-bound loop, and the
exposed stdlib ``re`` can backtrack catastrophically (unlike the regex *rule type*,
which uses linear-time re2). :func:`evaluate_script` runs the snippet against
adversarial inputs under a wall-clock guard at save time and rejects slow ones, but
that guard cannot interrupt a regex that holds the GIL -- a pathological pattern
would instead hang the author's own save request (killed by Gunicorn's worker
timeout in production). Authoring is restricted to moderators, so the trust bar is
high to begin with; the same moderators can already author arbitrary regex rules.
"""

import builtins
import re
import threading

from RestrictedPython import compile_restricted, safe_builtins
from RestrictedPython.Guards import (
    guarded_iter_unpack_sequence,
    guarded_unpack_sequence,
    safer_getattr,
)
from RestrictedPython.Eval import default_guarded_getitem, default_guarded_getiter


# Augmented-assignment ops (``x += 1``) are compiled to a ``_inplacevar_`` call.
# Support the common, side-effect-free operators; reject anything exotic.
_INPLACE_OPS = {
    "+=": lambda a, b: a + b,
    "-=": lambda a, b: a - b,
    "*=": lambda a, b: a * b,
    "/=": lambda a, b: a / b,
    "//=": lambda a, b: a // b,
    "%=": lambda a, b: a % b,
    "**=": lambda a, b: a ** b,
    "&=": lambda a, b: a & b,
    "|=": lambda a, b: a | b,
    "^=": lambda a, b: a ^ b,
    ">>=": lambda a, b: a >> b,
    "<<=": lambda a, b: a << b,
}


def _inplacevar(op, var, expr):
    try:
        return _INPLACE_OPS[op](var, expr)
    except KeyError:
        raise NotImplementedError(f"Augmented assignment {op!r} is not allowed.")


# Wall-clock budget for a single snippet execution during validation. Snippets are
# simple line predicates; anything slower than this on benign input is rejected.
SCRIPT_TIMEOUT_MS = 50.0

_RESULT_VAR = "result"
_TIMEOUT_SENTINEL = object()


# Pure, side-effect-free builtins that are handy for line predicates but missing
# from RestrictedPython's default ``safe_builtins``. None of these can perform IO,
# import, or attribute escapes, so they are safe to expose directly.
_EXTRA_SAFE_BUILTINS = {
    _name: getattr(builtins, _name)
    for _name in (
        "any", "all", "min", "max", "sum", "enumerate", "reversed",
        "map", "filter", "list", "set", "dict",
    )
    if hasattr(builtins, _name)
}


def _build_builtins():
    builtins = dict(safe_builtins)
    builtins.update(_EXTRA_SAFE_BUILTINS)
    return builtins


def compile_script(source: str):
    """Compile a snippet into a restricted code object.

    Raises ``ValueError`` with a readable message on syntax or restriction errors.
    """
    if not source or not source.strip():
        raise ValueError("Script is empty.")
    try:
        return compile_restricted(source, "<script-rule>", "exec")
    except SyntaxError as exc:
        # RestrictedPython raises SyntaxError both for genuine syntax errors and
        # for disallowed constructs (imports, dunder access, etc.).
        raise ValueError(f"Invalid script: {exc}") from exc


def _make_globals(text: str, var_name: str = "line") -> dict:
    namespace = {
        "__builtins__": _build_builtins(),
        "_getattr_": safer_getattr,
        "_getitem_": default_guarded_getitem,
        "_getiter_": default_guarded_getiter,
        "_write_": lambda obj: obj,
        "_unpack_sequence_": guarded_unpack_sequence,
        "_iter_unpack_sequence_": guarded_iter_unpack_sequence,
        "_inplacevar_": _inplacevar,
        "re": re,
    }
    # Per-line rules read ``line``; whole-log rules read ``log``. The input text is
    # bound under the requested name.
    namespace[var_name] = text
    return namespace


def _interpret(result) -> bool:
    """Map a snippet's ``result`` value to a match/no-match boolean."""
    if isinstance(result, str):
        return result.strip().upper() == "MATCH"
    return bool(result)


def run_script(code, text: str, var_name: str = "line") -> tuple[bool, str | None]:
    """Execute a compiled snippet against ``text``.

    ``var_name`` is the variable the snippet reads its input from: ``"line"`` for
    per-line rules, ``"log"`` for whole-log rules.

    Returns ``(matched, error)``. Any runtime exception is swallowed into a
    NOMATCH result with the error message, so a faulty rule can never break
    analysis of a log.
    """
    namespace = _make_globals(text, var_name)
    try:
        exec(code, namespace)
    except Exception as exc:  # noqa: BLE001 - untrusted code; never propagate
        return False, f"{type(exc).__name__}: {exc}"
    return _interpret(namespace.get(_RESULT_VAR)), None


def _run_with_timeout(fn, timeout_ms: float):
    """Run ``fn`` in a daemon thread, returning its result or ``_TIMEOUT_SENTINEL``.

    A daemon thread is used so a runaway snippet can never block process or test
    suite exit. The thread is abandoned (not killed) on timeout -- acceptable
    because :func:`evaluate_script` only uses this to *reject* such snippets.
    """
    box = {}

    def _target():
        try:
            box["value"] = fn()
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    thread.join(timeout_ms / 1000.0)
    if thread.is_alive():
        return _TIMEOUT_SENTINEL
    if "error" in box:
        raise box["error"]
    return box.get("value")


# Inputs designed to surface accidental blow-ups (long lines, many tokens) when a
# snippet is validated at save time. Mirrors analyzer.REGEX_ADVERSARIAL_INPUTS but
# kept local to avoid an import cycle.
ADVERSARIAL_INPUTS = (
    "a" * 200,
    "ab" * 100,
    ("\\" + "a") * 100,
    "a " * 100,
    "1" * 200,
    "C:\\Users\\" + "a" * 180 + "\\file.exe",
    "aA1\\ " * 50,
)


def evaluate_script(source: str, sample_lines=(), timeout_ms: float = SCRIPT_TIMEOUT_MS, var_name: str = "line") -> dict:
    """Validate a snippet for safe, reasonably fast execution.

    Compiles the snippet and runs it against adversarial + caller-supplied sample
    lines under a wall-clock guard. Returns a dict describing the outcome:

        {compile_ok, compile_error, runtime_error, timed_out, is_slow}

    The caller rejects the rule when ``compile_ok`` is False, ``runtime_error`` is
    set, or ``is_slow``/``timed_out`` is True.
    """
    result = {
        "compile_ok": False,
        "compile_error": None,
        "runtime_error": None,
        "timed_out": False,
        "is_slow": False,
    }

    try:
        code = compile_script(source)
    except ValueError as exc:
        result["compile_error"] = str(exc)
        return result
    result["compile_ok"] = True

    probes = list(ADVERSARIAL_INPUTS) + [str(s) for s in sample_lines]
    for probe in probes:
        outcome = _run_with_timeout(lambda: run_script(code, probe, var_name), timeout_ms)
        if outcome is _TIMEOUT_SENTINEL:
            result["timed_out"] = True
            result["is_slow"] = True
            return result
        _matched, error = outcome
        if error is not None:
            result["runtime_error"] = error
            return result

    return result
