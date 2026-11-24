#!/usr/bin/env python3
"""Self-checks for pretool-sf-json-stderr-guard.py.

Run: python hooks/guards/test-pretool-sf-json-stderr-guard.py

Two halves, and the second is the one that keeps the guard alive. The MUST-REWRITE cases (a correction that still asks) are the
real shapes that masked a failure, including the five from 2026-08-24 where a MALFORMED_QUERY read
as an empty result. The MUST-NOT-TOUCH cases are false-positive guards: a guard that cries wolf gets
removed, and this one sits on every Bash call.
"""

import json
import subprocess
import sys
from pathlib import Path

GUARD = Path(__file__).with_name("pretool-sf-json-stderr-guard.py")


def run(command: str, tool_name: str = "Bash") -> dict:
    """Invoke the guard exactly as the harness does and return its parsed decision."""
    payload = json.dumps({"tool_name": tool_name, "tool_input": {"command": command}})
    proc = subprocess.run(
        [sys.executable, str(GUARD)],
        input=payload, capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        return {"decision": "ERROR", "rc": proc.returncode, "stderr": proc.stderr}
    out = (proc.stdout or "").strip()
    if not out:
        return {"decision": "pass"}          # guard stayed silent: command runs unchanged
    parsed = json.loads(out)["hookSpecificOutput"]
    return {
        "decision": parsed["permissionDecision"],
        "command": (parsed.get("updatedInput") or {}).get("command"),
    }


# (label, command, expected decision, expected rewritten command or None)
CASES = [
    # ---------- the 2026-08-24 incidents: correct stderr handling, still silent ----------
    (
        "2026-08-24: aliased SOQL, no redirect, `?` swallowed the error",
        "sf data query --target-org prod --query \"SELECT Name nm FROM Account\" --json | jq -r '.result.records[]?.nm'",
        "ask",
        "sfj data query --target-org prod --query \"SELECT Name nm FROM Account\" | jq -r '.result.records[]?.nm'",
    ),
    (
        "2026-08-24: merged stderr AND a swallowing jq program",
        "sf data query --target-org qa --query \"SELECT Id FROM Account\" --json 2>&1 | jq -r '.result.records[]?'",
        "ask",
        "sfj data query --target-org qa --query \"SELECT Id FROM Account\" | jq -r '.result.records[]?'",
    ),
    (
        "aggregate COUNT read as a real zero",
        "sf data query --query \"SELECT COUNT(Id) cnt FROM Foo__c\" --json 2>/dev/null | jq -r '.result.records[0].cnt'",
        "ask",
        "sfj data query --query \"SELECT COUNT(Id) cnt FROM Foo__c\" | jq -r '.result.records[0].cnt'",
    ),
    (
        "sobject describe piped to jq",
        "sf sobject describe --sobject Account --target-org prod --json | jq -r '.result.fields[].name'",
        "ask",
        "sfj sobject describe --sobject Account --target-org prod | jq -r '.result.fields[].name'",
    ),
    (
        "tooling-api query with a trailing flag after --json",
        "sf data query --json --use-tooling-api --query \"SELECT Id FROM Flow\" | jq -r '.result.records[].Id'",
        "ask",
        "sfj data query --use-tooling-api --query \"SELECT Id FROM Flow\" | jq -r '.result.records[].Id'",
    ),
    (
        "config get, a read-only head that is not a query",
        "sf config get target-org --json | jq -r '.result[0].value'",
        "ask",
        "sfj config get target-org | jq -r '.result[0].value'",
    ),

    # ---------- mutating commands: never silently rewritten ----------
    (
        "mutating deploy WITH a stderr redirect stays a hard block",
        "sf project deploy start --source-dir force-app --json 2>/dev/null | jq -r '.result.status'",
        "deny",
        None,
    ),
    (
        "mutating deploy WITHOUT a redirect is left completely alone",
        "sf project deploy start --source-dir force-app --json | jq -r '.result.status'",
        "pass",
        None,
    ),
    (
        "data delete is not read-only, even piped to jq",
        "sf data delete record --sobject Account --record-id 001 --json | jq -r '.result.id'",
        "pass",
        None,
    ),

    # ---------- false-positive guards ----------
    (
        "already sfj: must not be rewritten again",
        "sfj data query --query \"SELECT Id FROM Account\" | jq -r '.result.records[].Id'",
        "pass",
        None,
    ),
    (
        "sfj that still carries --json: harmless, and not ours to touch",
        "sfj data query --query \"SELECT Id FROM Account\" --json | jq -r '.result.records[].Id'",
        "pass",
        None,
    ),
    (
        "--json with no jq downstream",
        "sf data query --query \"SELECT Id FROM Account\" --json > out.json",
        "pass",
        None,
    ),
    (
        "jq with no sf --json upstream",
        "cat payload.json | jq -r '.result.records[]?'",
        "pass",
        None,
    ),
    (
        "a mutating verb inside a SOQL literal must not decide read-only-ness",
        "sf data query --query \"SELECT Id FROM Account WHERE Name = 'Update Corp'\" --json | jq -r '.result.records[].Id'",
        "ask",
        "sfj data query --query \"SELECT Id FROM Account WHERE Name = 'Update Corp'\" | jq -r '.result.records[].Id'",
    ),
    (
        "an unrelated 2>/dev/null elsewhere in a compound line",
        "mkdir -p /tmp/x 2>/dev/null; sf data query --query \"SELECT Id FROM Account\" --json | jq -r '.result.records[].Id'",
        "ask",
        "mkdir -p /tmp/x 2>/dev/null; sfj data query --query \"SELECT Id FROM Account\" | jq -r '.result.records[].Id'",
    ),
    (
        "not a shell tool at all",
        "sf data query --query \"SELECT Id FROM Account\" --json | jq -r '.result.records[]?'",
        "pass",
        None,
    ),
    (
        "no sf, no --json, nothing to do",
        "git status --porcelain | head",
        "pass",
        None,
    ),
]


def main() -> int:
    failures = []
    for i, (label, command, want_decision, want_command) in enumerate(CASES):
        tool = "Read" if label == "not a shell tool at all" else "Bash"
        got = run(command, tool_name=tool)
        if got["decision"] != want_decision:
            failures.append(f"[{i}] {label}\n     decision: want {want_decision}, got {got['decision']}")
            continue
        if want_command is not None and got.get("command") != want_command:
            failures.append(
                f"[{i}] {label}\n     want: {want_command}\n     got : {got.get('command')}"
            )

    print(f"{len(CASES) - len(failures)}/{len(CASES)} passed")
    for f in failures:
        print("FAIL " + f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
