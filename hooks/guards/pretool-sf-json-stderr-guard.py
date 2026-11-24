#!/usr/bin/env python3
"""
PreToolUse guard — stops a Bash/PowerShell `sf ... --json | jq` pipeline from MASKING a failed
query. It CORRECTS the unsafe shape for read-only commands, still asking before it runs, and
BLOCKS it for everything else.

Why the shape is dangerous: on failure `sf ... --json` still exits non-zero and prints its error
AS JSON to stdout (`.status`/`.name`/`.message`, no `.result`). So `sf ... --json 2>/dev/null |
jq '.result...'` turns a FAILED query into a SILENT null (jq finds no `.result`, prints `null`,
exits 0) and `2>/dev/null` hides the human-readable stderr copy too — the query looks like a
legitimate empty result. `2>&1` is the mirror trap: it folds stderr into stdout and breaks jq
parsing. That is how a malformed query once came back blank with no error.

The fix is just to NOT redirect stderr on an `sf --json` you pipe to `jq` (the stderr chatter is
only banners; `sf ... --json | jq` parses cleanly). Better, use the `sfj` wrapper
(bin/sfj in this plugin): quiet AND it surfaces failures instead of masking them. The rewrite
below depends on `sfj` being on the Bash tool's PATH, which the plugin's bin/ directory
arranges. Without it the rewritten command prints "sfj: command not found" and the pipeline
still exits 0, which is why the wrapper ships beside the guard.

AS OF 2026-08-24 IT ALSO REWRITES THE CORRECT-LOOKING SHAPE, because dropping the redirect was
never enough. `sf ... --json | jq '.result.records[]?'` still turns a failed query into silence:
sf's error envelope goes to stdout, jq finds no `.result`, and the `?` swallows the null so jq
prints nothing and exits 0. On 2026-08-24 that produced five wrong "empty result" conclusions in
one session — a MALFORMED_QUERY from aliasing non-aggregate SOQL fields. The one edit that
defends the whole class rather than that one `?` is to run it through `sfj`, so this hook makes
that the default for any `sf --json` piped to jq instead of describing it.

What this hook does with the offending shape:
  * READ-only sf command (data query / sobject describe / org list / config get / ...):
    CORRECT, THEN ASK — return `permissionDecision: ask` + `updatedInput` rewriting the stage to
    `sfj`: `sf` -> `sfj`, drop any `2>{/dev/null,&1,$null}` token, and drop `--json` (sfj appends
    it itself, so leaving it yields `--json --json`). Nothing else is touched. Read-only is
    decided from the sf SUBCOMMAND tokens (the words after `sf` up to the first flag), NOT by
    scanning the whole line — so a SOQL literal like 'Update Corp' can't be mistaken for a
    mutating verb. The decision is `ask`, never `allow`, so the corrected command still goes
    through the permission prompt: this hook never approves a command on anyone's behalf.
  * Anything else (deploy / delete / create / update / apex run / import / unknown): DENY, so the
    corrected command is re-issued through the normal permission flow rather than rewritten
    here. A side-effecting command is never changed underneath anyone.

The rewrite relies on the harness honoring PreToolUse `updatedInput`. If a build ignored it, the
prompt would offer the ORIGINAL unsafe command — so the read-only gate keeps that worst case
limited to a (re-)masked READ, never a mutating command. `updatedInput` was verified honored in
the Claude desktop app on 2026-07-22.

Scope + limits: scans LITERAL command text, matching only within a SINGLE pipeline stage
(`sf ... --json ... 2>{...} ... | jq`, no intervening pipe/`;`/`&&`/newline), so a `2>/dev/null`
on an UNRELATED command in a compound line does not trip it. Misses the capture-to-variable
variant (`A=$(sf --json 2>/dev/null); echo "$A" | jq`) by design (the `;` breaks the segment) —
a deliberate fail-open. Fail-OPEN on any internal error too (a guard bug must never wedge every
shell command).

Runs from hooks/pretool-guards.py, or alone as a PreToolUse hook on "Bash|PowerShell".

Self-checks: test-pretool-sf-json-stderr-guard.py, beside this file.
"""

import json
import re
import sys

# Offending shape: an `sf ... --json` whose stderr is redirected in the SAME pipeline stage, then
# piped to `jq`. The `[^|;&\n]` runs keep the match inside one pipeline stage.
_OFFENDING = re.compile(
    r"\bsf\b[^|;&\n]*--json[^|;&\n]*2>\s*(?:/dev/null|&1|\$null)[^|;&\n]*\|\s*jq",
    re.IGNORECASE,
)
# Any `sf ... --json ... | jq` in one stage, redirect or not. This is the shape that a bare
# `jq '.result.records[]?'` turns into a silent empty, so it is rewritten to `sfj` even when the
# stderr handling is already correct. `\bsf\b` does not match `sfj`, so a rewritten command is
# not re-matched.
#
# `&` stays excluded so a stage cannot run past `&&` or a background `&`, but `2>&1` has to be
# allowed through explicitly or this pattern is NARROWER than _OFFENDING and silently stops
# covering the merged-stderr case the guard already handled. Its own self-check caught exactly
# that regression on 2026-08-24, which is the reason the alternation is spelled out.
_STAGE = r"(?:2>\s*&1|[^|;&\n])*"
_PIPED = re.compile(r"\bsf\b" + _STAGE + r"--json" + _STAGE + r"\|\s*jq", re.IGNORECASE)
# Just the stderr-redirect token, for surgical removal.
_REDIR = re.compile(r"\s*2>\s*(?:/dev/null|&1|\$null)")
# The `--json` flag, which `sfj` supplies itself — leaving it duplicates the flag.
_JSON_FLAG = re.compile(r"\s--json\b")

# sf subcommands that only READ (safe to auto-correct + auto-run). Matched as a prefix of the
# subcommand token string (the words after `sf` up to the first flag). Keep this conservative:
# an unknown subcommand falls through to DENY, which is safe (it just gets re-issued).
_READONLY_HEADS = (
    "data query", "data get", "data export", "data tree export",
    "sobject describe", "sobject list",
    "org list", "org display",
    "config get", "config list",
    "package installed list", "package list",
    "apex list", "apex tail", "apex log get", "apex log list",
    "limits api display", "limits", "schema", "describe", "doctor", "version",
    "force:data:soql",
)


def is_offending(command: str) -> bool:
    return bool(_OFFENDING.search(command))


def _sf_head(segment: str) -> str:
    """The sf subcommand tokens in a segment: words after the first bare `sf` up to the first
    flag. e.g. 'sf data query -o prod ...' -> 'data query'; 'sf project deploy start -x' ->
    'project deploy start'. Returns '' if no bare `sf` token is present."""
    toks = segment.split()
    i = next((k for k, t in enumerate(toks) if t == "sf"), -1)
    if i < 0:
        return ""
    head = []
    for t in toks[i + 1:]:
        if t.startswith("-"):
            break
        head.append(t.lower())
    return " ".join(head)


def _head_is_readonly(segment: str) -> bool:
    head = _sf_head(segment)
    if not head:
        return False
    return any(head == p or head.startswith(p + " ") for p in _READONLY_HEADS)


def all_offending_readonly(command: str) -> bool:
    """True only if EVERY offending `sf --json ... | jq` stage is a read-only sf command."""
    segs = list(_OFFENDING.finditer(command))
    return bool(segs) and all(_head_is_readonly(m.group(0)) for m in segs)


def rewrite_to_sfj(command: str) -> str:
    """Rewrite every READ-ONLY `sf ... --json ... | jq` stage to `sfj ... | jq`.

    Three edits per stage, all inside that stage: `sf` -> `sfj`, drop the stderr redirect if any,
    and drop `--json` (sfj appends it, so leaving it yields `--json --json`). A mutating stage is
    left completely alone — sfj is a passthrough, and only read-only sfj subcommands are
    allowlisted, so rewriting one would neither help nor stay approved.

    Terminates because `\\bsf\\b` does not match the `sfj` a rewrite produces, so each pass strictly
    reduces the number of matches.
    """
    out = command
    pos = 0
    while True:
        m = _PIPED.search(out, pos)
        if not m:
            break
        seg = m.group(0)
        if not _head_is_readonly(seg) or not seg.lower().startswith("sf"):
            pos = m.end()  # leave it, and don't rescan it
            continue
        fixed = "sfj" + seg[2:]
        fixed = _REDIR.sub("", fixed, count=1)
        fixed = _JSON_FLAG.sub("", fixed, count=1)
        out = out[:m.start()] + fixed + out[m.end():]
        pos = m.start() + len(fixed)
    return out


def strip_redirects(command: str) -> str:
    """Remove the stderr redirect from every offending `sf --json ... | jq` stage. Terminates:
    removing a stage's redirect makes that stage stop matching, so the scan advances."""
    out = command
    while True:
        m = _OFFENDING.search(out)
        if not m:
            break
        seg = m.group(0)
        fixed = _REDIR.sub("", seg, count=1)
        if fixed == seg:  # nothing removed (shouldn't happen) — avoid an infinite loop
            break
        out = out[:m.start()] + fixed + out[m.end():]
    return out


_WHY = (
    "`sf ... --json 2>{/dev/null,&1,$null} | jq` masks failures: on error sf prints its error as "
    "JSON to stdout (.status/.name/.message, no .result) and exits non-zero, so `2>/dev/null | jq` "
    "yields a SILENT null and `2>&1` breaks jq. Prefer `sfj ... | jq` (bin/sfj from the "
    "command-guards plugin, on your PATH) — quiet AND it surfaces failures — or just drop the redirect: "
    "`sf ... --json | jq`."
)


def _emit(decision: str, reason: str, updated_input=None) -> None:
    out = {"hookEventName": "PreToolUse", "permissionDecision": decision,
           "permissionDecisionReason": reason}
    if updated_input is not None:
        out["updatedInput"] = updated_input
    print(json.dumps({"hookSpecificOutput": out}))


def main() -> int:
    try:
        data = json.loads(sys.stdin.read() or "{}")
    except Exception:
        return 0  # fail-open: can't parse input, don't block

    try:
        if data.get("tool_name") not in ("Bash", "PowerShell"):
            return 0
        tool_input = data.get("tool_input") or {}
        command = tool_input.get("command") or ""
        if not isinstance(command, str):
            return 0
        if "--json" not in command or not _PIPED.search(command):
            return 0

        # A stderr redirect on a MUTATING sf command is still a hard block: it is re-issued
        # through normal permissioning rather than rewritten here.
        if is_offending(command) and not all_offending_readonly(command):
            _emit("deny", "Blocked (stderr redirect on an sf --json|jq that is not a plain "
                          "read-only command). " + _WHY)
            return 0

        fixed = rewrite_to_sfj(command)
        if fixed == command:
            return 0  # nothing read-only to rewrite (e.g. every stage is a mutating command)
        if is_offending(fixed) or "--json --json" in fixed:
            _emit("deny", "Blocked (could not auto-correct the pipeline). " + _WHY)
            return 0

        _emit("ask",
              "Corrected to `sfj`, which surfaces a failed query instead of letting it "
              "return a silent empty result. Approve to run the corrected command. " + _WHY,
              {**tool_input, "command": fixed})
        return 0
    except Exception:
        return 0  # fail-open


if __name__ == "__main__":
    sys.exit(main())
