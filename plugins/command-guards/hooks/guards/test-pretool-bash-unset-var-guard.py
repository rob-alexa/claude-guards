#!/usr/bin/env python3
"""
test-pretool-bash-unset-var-guard.py — self-checks for pretool-bash-unset-var-guard.py.
Run:  python hooks/guards/test-pretool-bash-unset-var-guard.py   (no org, no network, no deps)

Drives the guard the way the harness does — a JSON PreToolUse payload on stdin — and asserts the
decision, so what is under test is the wired contract and not just an internal function.

Two directions, and the suite is only worth anything if it holds BOTH:

  * The guard must still block the real bug. A variable set in an earlier Bash tool call is EMPTY
    in this one, and bash expands it to nothing and exits 0, so the command silently runs a
    different command. `git diff $MB..$B -- CLAUDE.md` collapsed to `git diff .. -- CLAUDE.md` on
    2026-08-01 and was read as "nothing changed" when the file had changed.
  * The guard must not block ordinary shell. Every safe way of writing a variable has to pass:
    assigned in the same command, a real environment variable, a `${VAR:-default}`, a loop
    variable, a positional, single quotes, a quoted heredoc, command substitution. A guard that
    cries wolf over normal shell gets switched off, and then it guards nothing.

The allow cases pin the exemptions narrowly rather than asserting "does not block everything",
which a guard stuck on allow would also satisfy — hence the deny cases sitting beside them.
"""

import json
import pathlib
import subprocess
import sys

GUARD = pathlib.Path(__file__).resolve().parent / "pretool-bash-unset-var-guard.py"

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


def decide(command: str, tool_name: str = "Bash") -> str:
    """'deny', 'allow', or a describe-the-breakage string.

    A hook signals its decision in the JSON it prints, never by exit status — a non-zero exit is
    a crashed guard, which the harness reads as "no opinion". So a non-zero return is reported as
    its own failure rather than being folded into 'allow'.
    """
    proc = subprocess.run(
        [sys.executable, str(GUARD)],
        input=json.dumps({"tool_name": tool_name, "tool_input": {"command": command}}),
        capture_output=True, text=True,
    )
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
# MUST DENY — the cross-call bug this guard exists for.
# ---------------------------------------------------------------------------------------

# The exact 2026-08-01 failure, verbatim.
check("the real incident: git diff $MB..$B", "deny",
      decide('git diff $MB..$B -- CLAUDE.md'))

check("bare unset in a quoted string", "deny",
      decide('echo "value is $LEFTOVER_FROM_LAST_CALL"'))

check("braced unset", "deny",
      decide('git log --oneline ${SOMEBRANCH}'))

check("unset used in a path", "deny",
      decide('ls "$WT/force-app/main/default/flows"'))

# An UNquoted heredoc does expand, so an unset name inside it is the same bug.
check("unquoted heredoc expands, so an unset name still counts", "deny",
      decide('cat <<EOF\ntarget is $MISSINGVAR\nEOF'))

# Only one of several needs to be unsafe.
check("one unsafe among several safe", "deny",
      decide('A=1; B=2; echo "$A $B $CFORGOTTEN"'))


# ---------------------------------------------------------------------------------------
# MUST ALLOW — every legitimate way of writing a variable.
# ---------------------------------------------------------------------------------------

check("assigned in the SAME command (the recommended fix)", "allow",
      decide('MB=679e1be; git diff "$MB"..HEAD -- CLAUDE.md'))

check("assigned with export", "allow",
      decide('export TARGET=dev; echo "$TARGET"'))

check("a real environment variable", "allow",
      decide('echo "$HOME/.sf/sync-markers"'))

check("default value makes unset harmless", "allow",
      decide('echo "${MAYBE_UNSET:-fallback}"'))

check("empty default is the idiom for optional", "allow",
      decide('if [ -z "${OPTIONAL:-}" ]; then echo none; fi'))

check("for-loop variable", "allow",
      decide('for f in a b c; do echo "$f"; done'))

check("read into a name", "allow",
      decide('read LINE; echo "$LINE"'))

check("positional and special parameters", "allow",
      decide('echo "$1 $@ $? $$ $# $!"'))

check("command substitution is not a variable", "allow",
      decide('echo "$(date) $(git rev-parse HEAD)"'))

check("arithmetic expansion is not a variable", "allow",
      decide('echo $((2 + 3))'))

check("single quotes do not expand", "allow",
      decide("grep -n '$NOTAVARIABLE' file.txt"))

check("quoted heredoc does not expand", "allow",
      decide("cat <<'EOF'\nliteral $NOTAVARIABLE stays literal\nEOF"))

check("no dollar sign at all", "allow",
      decide('git status --short'))

check("local inside a function body", "allow",
      decide('f() { local tmp=1; echo "$tmp"; }; f'))

# PowerShell's $var is a different language with different scoping — out of scope by design.
check("PowerShell is skipped entirely", "allow",
      decide('Write-Output "$SomePowerShellVar"', tool_name="PowerShell"))

# A guard that crashes must read as "no opinion", never as a block.
check("malformed payload fails open", "allow", decide(""))


# ---------------------------------------------------------------------------------------
# QUOTE TRACKING — what a quote character means depends on the context it sits in.
# ---------------------------------------------------------------------------------------

# The 2026-09-23 block, verbatim. `$s` is a jq variable inside the single-quoted jq program, but
# the guard paired quotes with a bare '[^']*' regex, so the apostrophe in "team's" (a literal
# character inside double quotes) was paired with the program's OPENING quote, and the program
# was scanned as unquoted shell. Any Jira summary or comment with a possessive tripped it.
check("2026-09-23 incident: an apostrophe inside a double-quoted --arg value", "allow",
      decide("""jq --arg s "Administrators can see the errors the team's Apex code catches and handles" '.fields += {project:{key:"PROJ"}, issuetype:{name:"Story"}, summary:$s}' in.json > out.json"""))

check("the recommended jq --arg shape", "allow",
      decide(r"""jq --arg p '^QA\b' 'test($p)' issue.json"""))

# The mirror image: a `"` inside '...' opens no double-quoted region to swallow what follows.
check("a double quote inside single quotes opens nothing", "allow",
      decide("""grep -c '"' out.json && jq --arg v 1 '.x = $v' in.json"""))

check("the '\\'' idiom for an apostrophe inside single quotes", "allow",
      decide("""echo 'today'\\''s branch' && jq --arg v 1 -n '$v'"""))

check("an apostrophe in a comment opens nothing", "allow",
      decide("# today's check\njq --arg v 1 -n '$v'"))

check("an apostrophe in an unquoted heredoc body opens nothing", "allow",
      decide("cat <<EOF\ntoday's note: $HOME\nEOF\njq --arg v 1 -n '$v'"))

check("$'...' keeps an escaped quote inside the string", "allow",
      decide("printf '%s\\n' $'today\\'s' && jq --arg v 1 -n '$v'"))

check("single quotes inside $(...) inside double quotes still quote", "allow",
      decide('echo "$(jq -r --arg k a \'.[$k]\' in.json)"'))

check("a nested double-quoted default inside ${...} inside double quotes", "allow",
      decide('echo "${NAME:-"today\'s"} branch" \'$literal\''))

check("a $VAR in a comment is never expanded", "allow",
      decide("git status  # then compare against $BASE_FROM_LAST_CALL"))

check("a backslash-escaped dollar is literal", "allow",
      decide('echo "cost: \\$PRICE"'))

check("<<- strips leading tabs before the delimiter", "allow",
      decide("cat <<-'EOF'\n\tliteral $NOTAVARIABLE\n\tEOF\necho done"))

check("<< inside $((...)) is a shift, not a heredoc", "allow",
      decide("n=$((1 << 3))\necho \"today's total: $n\" '$literal'"))

check("the $(cat <<'EOF' ... EOF) commit-message idiom", "allow",
      decide("git commit -m \"$(cat <<'EOF'\ntoday's fix for $NOT_A_VAR\nEOF\n)\""))

# The same pairing also HID real expansions: an apostrophe paired with a later one, and the
# unset variable between them was read as single-quoted. Inside a double-quoted SOQL string,
# `'$ACCT_NAME'` collapses to `''` when unset, which is the empty-string match that makes
# a SOQL IN clause select every blank record.
check("single quotes inside double quotes do not stop an expansion", "deny",
      decide('''grep -rn "Name = '$ACCT_NAME'" force-app'''))

check("two apostrophes in double quotes hide nothing between them", "deny",
      decide('''echo "today's" $LEFTOVER_FROM_LAST_CALL "the org's"'''))

check("apostrophes in an unquoted heredoc body hide nothing", "deny",
      decide("cat <<EOF\ntoday's note: $MISSING_NOTE, and the org's\nEOF"))

check("apostrophes in comments hide nothing between them", "deny",
      decide("# today's check\necho $LEFTOVER_FROM_LAST_CALL  # and the org's"))

check("$(...) inside double quotes is still scanned", "deny",
      decide('echo "$(git log -1 --format=%h $SOMEREF)"'))

# `$(cat <<EOF ... EOF)`: bash ends the body at the `)` that closes the substitution.
check("a heredoc closed by EOF) inside $(...) still ends there", "deny",
      decide("msg=$(cat <<'EOF'\ntoday's fix\nEOF)\necho \"$msg $LEFTOVER_FROM_LAST_CALL\""))


# ---------------------------------------------------------------------------------------
# READ — every name after `read` is assigned, not only the first.
# ---------------------------------------------------------------------------------------

# Crediting only the first name went unnoticed while the quote pairing hid the usual later
# reference. Fixing the pairing exposed it: replaying past session transcripts, nine commands
# shaped like this one would have been newly blocked.
check("every name read assigns counts, not only the first", "allow",
      decide("""while read -r O R; do echo "Id = '$R'"; done < ids.txt"""))

check("an option's argument is not taken for a name", "allow",
      decide("read -r -d '' BODY < msg.txt; echo \"$BODY\""))

check("read credits only its own names", "deny",
      decide('while read -r O R; do echo "$O $R $LEFTOVER_FROM_LAST_CALL"; done < ids.txt'))

# Only a `read` bash runs assigns anything, so crediting every word must not reach into comments.
check("a read inside a comment assigns nothing", "deny",
      decide("# read MB from the log first\ngit diff $MB..HEAD -- CLAUDE.md"))

check("a comment on the same line ends read's names", "deny",
      decide('read -r A  # then set MB\necho "$A $MB"'))


print()
print("FAILURES ABOVE" if fail else "all checks passed")
sys.exit(fail)
