#!/usr/bin/env python3
"""
test-pretool-soql-guard.py — self-checks for pretool-soql-guard.py.
Run:  python hooks/guards/test-pretool-soql-guard.py     (no org, no network, no deps)

Drives the guard the way the harness does — a JSON PreToolUse payload on stdin — and asserts
the decision, so what is under test is the wired contract and not just an internal function.

Two directions, and the suite is only worth anything if it holds BOTH:

  * The guard must not block ordinary code. On 2026-07-28 it blocked `for k in ('content',):`
    in a Python heredoc, reading the one-element tuple's trailing comma as an empty SOQL
    element. A guard that cries wolf over Python gets switched off, and then it is not
    guarding the thing it exists for.
  * The guard must still block a real empty element. `IN ('')` matches every NULL/blank
    record, and on 2026-07-12 that shape removed 306 records from a shared sandbox. Any
    change that quiets a false positive by loosening this half has traded the wrong way.

The `allow` cases therefore pin the exemptions narrowly (a TRAILING comma only, and only
outside SOQL context) rather than "does not block Python", which a broken guard also satisfies.
"""

import json
import pathlib
import subprocess
import sys

GUARD = pathlib.Path(__file__).resolve().parent / "pretool-soql-guard.py"

fail = 0


def check(label, expected, actual):
    global fail
    if expected == actual:
        print(f"ok: {label}")
    else:
        print(f"FAIL: {label}")
        print(f"  expected: [{expected}]")
        print(f"  actual:   [{actual}]")
        fail = 1


def run(payload: str):
    return subprocess.run(
        [sys.executable, str(GUARD)], input=payload,
        capture_output=True, text=True,
    )


def decide(command: str, tool_name: str = "Bash") -> str:
    """'deny', 'allow', or a describe-the-breakage string.

    A hook signals its decision in the JSON it prints, never by exit status — a non-zero
    exit is a crashed guard, which the harness reads as "no opinion". So a non-zero return
    is reported as its own failure rather than being folded into 'allow'.
    """
    proc = run(json.dumps({"tool_name": tool_name, "tool_input": {"command": command}}))
    if proc.returncode != 0:
        return f"exit {proc.returncode}: {proc.stderr.strip()[:120]}"
    out = proc.stdout.strip()
    if not out:
        return "allow"
    try:
        decoded = json.loads(out)
    except ValueError:
        return f"unparseable stdout: {out[:120]}"
    return decoded.get("hookSpecificOutput", {}).get("permissionDecision", "no decision")


# ---------------------------------------------------------------------------------------
# MUST ALLOW — ordinary code the guard has no business blocking.
# ---------------------------------------------------------------------------------------
ALLOW = [
    # The reported false positive, in the shape it was hit in.
    ("python one-element tuple in a heredoc", """python3 - <<'PY'
for k in ('content',):
    print(k)
PY"""),

    ("python tuple, several elements + trailing comma",
     "python3 -c \"print([k for k in ('content', 'name',)])\""),

    ("python tuple, no trailing comma",
     "python3 -c \"print('content' in ('content', 'name'))\""),

    ("python empty tuple", """python3 - <<'PY'
for x in ():
    pass
PY"""),

    # Isolates the CONTEXT gate: this element genuinely is an empty string, and it is still
    # fine, because a Python tuple is not a SOQL value list. If the gate regresses, only
    # this case and the jq one below go red.
    ("python tuple holding an empty string", """python3 - <<'PY'
for k in ('',):
    print(repr(k))
PY"""),

    ("jq IN() filter downstream of a query",
     "sfj data query -q \"SELECT Id, Name FROM Account\" "
     "| jq '[.result.records[] | select(.Name | IN(\"a\",\"\"))]'"),

    # Isolates the TRAILING-COMMA rule: full SOQL context, so the gate does not save it.
    # Verified 2026-07-28 against a sandbox — the server answers MALFORMED_QUERY "unexpected
    # token: ')'", so this is a query that cannot run, not one that silently over-matches.
    ("SOQL trailing comma is a parse error, not an empty element",
     "sfj data query -q \"SELECT Id FROM Account WHERE Name IN ('x',)\""),

    ("semi-join subquery",
     "sfj data query -q \"SELECT Id FROM Contact WHERE AccountId "
     "IN (SELECT Id FROM Account WHERE Name = 'Acme')\""),

    ("valid SOQL IN list",
     "sfj data query -q \"SELECT Id FROM Invoice__c "
     "WHERE External_Id__c IN ('100001','100002')\""),

    # Context is per statement, not per command: a query built earlier in the same heredoc
    # must not lend SOQL context to an unrelated tuple further down.
    ("tuple in a heredoc that also builds SOQL", """python3 - <<'PY'
query = "SELECT Id FROM Invoice__c WHERE Name = 'Acme'"
for k in ('content',):
    print(query, k)
PY"""),

    # Same point across a `;` rather than a newline.
    ("tuple after a query in a chained command",
     "sfj data query -q \"SELECT Id FROM Account\" > /tmp/a.json; "
     "python3 -c \"print([k for k in ('content',)])\""),
]

# ---------------------------------------------------------------------------------------
# MUST DENY — a literal empty element in something that reads as SOQL.
# ---------------------------------------------------------------------------------------
DENY = [
    ("IN ('')",
     "sfj data query -q \"SELECT Id FROM Invoice__c WHERE External_Id__c IN ('')\""),

    ("IN ('', 'x')",
     "sfj data query -q \"SELECT Id FROM Invoice__c "
     "WHERE External_Id__c IN ('', '100001')\""),

    ("IN () with nothing at all",
     "sfj data query -q \"SELECT Id FROM Invoice__c WHERE External_Id__c IN ()\""),

    # The 2026-07-12 incident: a mis-parsed CSV put a blank element on the end of the list
    # and the delete took 306 records instead of 3.
    ("the 306-record delete shape", """sf apex run <<'APEX'
delete [SELECT Id FROM Invoice__c WHERE External_Id__c IN ('100001','N/A','')];
APEX"""),

    # A quoted empty LAST is not the exempted trailing comma — the exemption is one bare
    # comma before `)`, nothing else.
    ("quoted empty in the last position",
     "sfj data query -q \"SELECT Id FROM Account WHERE Name IN ('Acme','')\""),

    ("doubled comma mid-list",
     "sfj data query -q \"SELECT Id FROM Account WHERE Name IN ('Acme',,'Globex')\""),

    ("leading comma",
     "sfj data query -q \"SELECT Id FROM Account WHERE Name IN (,'Acme')\""),

    # One trailing empty is dropped as the comma; a second one is a real element.
    ("doubled trailing comma",
     "sfj data query -q \"SELECT Id FROM Account WHERE Name IN ('Acme',,)\""),

    ("double-quoted empty (PowerShell)",
     "sf data query -q 'SELECT Id FROM Account WHERE Name IN (\"\")'"),

    # No SELECT/FROM at all — the `--where` flag is the SOQL context, and this is the exact
    # call a delete script would make.
    ("safe-delete.sh --where",
     "bash safe-delete.sh --sobject Invoice__c "
     "--where \"External_Id__c IN ('')\" --expect 3 --yes"),

    ("WHERE clause wrapped onto an AND line", """sfj data query -q "
  SELECT Id FROM Invoice__c
  WHERE Status__c = 'Draft'
  AND External_Id__c IN ('')
" """),

    # No keyword on the line at all: the `__c` field API name before the IN is the signal.
    ("bare SOQL fragment in a shell variable",
     "Q=\"External_Id__c IN ('','100001')\""),

    ("lowercase SOQL",
     "sfj data query -q \"select id from account where name in ('')\""),

    # Every IN on the line is inspected, not just the first.
    ("second IN clause on the same line",
     "sfj data query -q \"SELECT Id FROM Invoice__c WHERE Status__c IN ('Draft') "
     "AND External_Id__c IN ('')\""),
]

for label, command in ALLOW:
    check(f"allow: {label}", "allow", decide(command))

for label, command in DENY:
    check(f"deny: {label}", "deny", decide(command))

check("deny: PowerShell tool is in scope", "deny",
      decide("sf data query -q \"SELECT Id FROM Account WHERE Name IN ('')\"",
             tool_name="PowerShell"))

# ---------------------------------------------------------------------------------------
# Hook protocol. Fail-open is deliberate: a guard bug must never wedge every shell command.
# ---------------------------------------------------------------------------------------
check("allow: a tool that is not Bash/PowerShell", "allow",
      decide("sf data query -q \"SELECT Id FROM Account WHERE Name IN ('')\"", tool_name="Write"))

proc = run("this is not json {")
check("fail-open: unparseable stdin exits 0", 0, proc.returncode)
check("fail-open: unparseable stdin is silent", "", proc.stdout.strip())

proc = run("")
check("fail-open: empty stdin exits 0", 0, proc.returncode)
check("fail-open: empty stdin is silent", "", proc.stdout.strip())

proc = run(json.dumps({"tool_name": "Bash", "tool_input": {}}))
check("fail-open: no command key exits 0", 0, proc.returncode)
check("fail-open: no command key is silent", "", proc.stdout.strip())

# The deny reason has to say what to do about it, not just that it said no.
proc = run(json.dumps({
    "tool_name": "Bash",
    "tool_input": {"command": "sfj data query -q \"SELECT Id FROM Account WHERE Name IN ('')\""},
}))
reason = json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
check("deny reason names the offending clause", True, "IN ('')" in reason)
check("deny reason says to pre-count a delete", True, "pre-count with the exact WHERE" in reason)

print("---")
print("ALL PASS" if fail == 0 else "SOME FAILED")
sys.exit(fail)
