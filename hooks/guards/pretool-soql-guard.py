#!/usr/bin/env python3
"""
PreToolUse guard — BLOCKS a Bash/PowerShell command that contains a SOQL `IN (...)`
clause with an EMPTY element (`IN ()`, `IN ('')`, `IN ("")`, a leading or doubled comma,
or a bare-quote element).

Why: in SOQL, `field IN ('')` matches every record where `field` is NULL/blank (verified:
`IN ('')` returned the same count as `= null`). A single stray empty element silently turns
a narrow filter into "all null/blank" — and if that filter drives a DELETE it deletes far
more than intended. On 2026-07-12 a mis-parsed CSV produced `IN ('100001','N/A','')` and a
`delete [... WHERE External_Id__c IN (...)]` removed 306 records from a shared sandbox.

Two things it deliberately does NOT flag, both added 2026-07-28 after the guard blocked an
ordinary `for k in ('content',):` inside a Python heredoc:

  * A TRAILING comma before `)` is not an empty element. `('content',)` is a one-element
    Python/JS tuple, and in SOQL a trailing comma is a MALFORMED_QUERY the server rejects
    outright (verified 2026-07-28) — not the silent all-NULL match this guard exists to
    stop. A leading (`IN (,'a')`) or doubled (`IN ('a',,'b')`) comma still counts, since
    those are the shapes a bad value-list build actually produces.
  * An `IN (...)` that does not plausibly sit inside a SOQL statement. Context is decided
    per STATEMENT (see _in_soql_context): a SOQL keyword (SELECT / FROM / WHERE, which also
    catches a `--where` flag) earlier in the same statement, or a `__c`/`__r` field API name
    immediately before the `IN`. A `WHERE ...` clause wrapped onto its own `AND`/`OR` line
    is followed back to the line that opened it. So Python, jq, and shell list literals on
    their own line are left alone, while every SOQL shape stays covered.

Scope + limits: this scans the LITERAL command text, so it catches a written-out empty
element. It CANNOT see an empty string that only appears after shell expansion of a variable
(e.g. `IN ($QIN)`) — that runtime case is covered by a delete routine that pre-counts and asserts
the match count, and by never building IN lists by awk-splitting a CSV, not by this hook. Nor does it see
a SOQL fragment assigned to a variable whose statement carries no SOQL keyword and no `__c`
field (`Q="Foo IN ('','a')"`), a narrow recall gap accepted in trade for not blocking
every parenthesised list in the command.

Blocking: emits a PreToolUse `deny` decision. Fail-OPEN on any internal error (a guard bug
must never wedge every shell command); a pre-counting delete and review remain the backstop.
Runs from hooks/pretool-guards.py, or alone as a PreToolUse hook on "Bash|PowerShell".

Self-checks: test-pretool-soql-guard.py, beside this file (no org, no network).
"""

import json
import re
import sys

# `IN (` ... `)` with no nested paren; we then inspect the element list.
_IN_CLAUSE = re.compile(r"\bIN\s*\(([^)]*)\)", re.IGNORECASE)

# --- SOQL context, tested against the text PRECEDING the `IN (` -----------------------
# A SOQL keyword anywhere earlier in the statement. `\bWHERE\b` also matches the `--where`
# flag of sf-safe-delete.sh / `sf data delete record`, which is exactly the context we want.
_SOQL_KEYWORD = re.compile(r"\b(?:SELECT|FROM|WHERE)\b", re.IGNORECASE)
# A custom field/relationship API name immediately before the `IN` — on its own enough of a
# signal to cover a bare SOQL fragment (`External_Id__c IN (...)`) with no keyword.
_SOQL_FIELD = re.compile(r"__[cr]\s*\Z", re.IGNORECASE)
# A WHERE clause continued onto its own line: keep walking back to the line that opened it.
_SOQL_CONTINUATION = re.compile(r"^\s*(?:AND|OR|NOT)\b", re.IGNORECASE)
# Shell statement separators. Only the text after the LAST one on a line is that line's
# statement, so a `WHERE` in an unrelated earlier command can't lend context to this one.
_STATEMENT_SPLIT = re.compile(r"&&|\|\||[;|]")
# Bound the continuation walk; a real WHERE clause never spans anything like this many lines.
_MAX_LOOKBACK_LINES = 20


def _in_soql_context(command: str, in_start: int) -> bool:
    """True if the `IN (` at `in_start` plausibly sits inside a SOQL statement.

    Line-scoped on purpose: a Python heredoc that also builds a query elsewhere must not
    lend SOQL context to an unrelated tuple literal further down.
    """
    lines = command[:in_start].split("\n")
    for depth in range(min(len(lines), _MAX_LOOKBACK_LINES)):
        # At depth 0 this is the partial line before the `IN`; deeper, a whole earlier line.
        segment = _STATEMENT_SPLIT.split(lines[-1 - depth])[-1]
        if _SOQL_KEYWORD.search(segment):
            return True
        if depth == 0 and _SOQL_FIELD.search(segment):
            return True
        # Only a blank line or an AND/OR/NOT continuation earns another step back.
        if segment.strip() and not _SOQL_CONTINUATION.match(segment):
            return False
    return False


def _has_empty_element(content: str) -> bool:
    """True if the element list holds an empty element (`''`, `""`, or nothing at all)."""
    elements = [e.strip() for e in content.split(",")]
    # Drop ONE trailing empty: that is a trailing comma, not an element. `IN ('a',,)` keeps
    # its second empty and is still flagged.
    if elements[-1] == "":
        elements.pop()
    return any(e == "" or e in ("''", '""') for e in elements)


def empty_in_hits(command: str):
    """Return a list of offending `IN (...)` snippets that contain an empty element."""
    hits = []
    for m in _IN_CLAUSE.finditer(command):
        content = m.group(1)
        # Subquery semi-join `IN (SELECT ...)` is legitimate and never an empty element.
        if re.match(r"\s*SELECT\b", content, re.IGNORECASE):
            continue
        if not _in_soql_context(command, m.start()):
            continue
        if content.strip() == "":
            hits.append("IN ()")
        elif _has_empty_element(content):
            hits.append(m.group(0)[:80])
    return hits


def main() -> int:
    try:
        data = json.loads(sys.stdin.read() or "{}")
    except Exception:
        return 0  # fail-open: can't parse input, don't block

    try:
        if data.get("tool_name") not in ("Bash", "PowerShell"):
            return 0
        command = (data.get("tool_input") or {}).get("command") or ""
        if not isinstance(command, str) or "(" not in command:
            return 0

        hits = empty_in_hits(command)
        if not hits:
            return 0

        reason = (
            "Blocked: a SOQL IN clause has an EMPTY element "
            f"({'; '.join(hits[:3])}). In SOQL, IN ('') matches every NULL/blank record, "
            "so this can match — and (for a DELETE) destroy — far more than intended. "
            "Fix the value list (drop blank/sentinel elements; never build it by awk-splitting "
            "a CSV), and for any delete, pre-count with the exact WHERE and abort unless the "
            "match count equals the number you expect."
        )
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }))
        return 0
    except Exception:
        return 0  # fail-open


if __name__ == "__main__":
    sys.exit(main())
