"""Self-checks for pretool-grep-abort-guard.py.

The guard refuses a git-bash grep that GNU grep 3.0 aborts on: -i with -F in any spelling, and -i
with two or more patterns that are all plain strings, which grep quietly hands to the same -F
matcher. The abort prints nothing and reads as "no matches", so every case in the BLOCK list is
a command that would have returned a confident empty answer.

MOST OF THIS SUITE IS FALSE-POSITIVE COVER, on purpose. grep runs in ordinary commands all day, the
option letters involved are common, and the trap gets written ABOUT in commit messages, docs, and
PR bodies. A guard that fires on `grep -i "$x"`, on `awk -F,` in the same pipeline, or on a commit
message naming the trap gets switched off within a day, and then nothing is left. So the PASS list
is longer than the BLOCK list.

It also proves two things a case list cannot: that the guard is in the dispatcher's GUARDS tuple
(a guard missing from it never runs, and nothing else would notice), and that the dispatcher
denies end to end.

Every guard run strips LANG, LC_ALL, and LC_CTYPE from the guard's environment and sets
PYTHONCOERCECLOCALE=0. The guard stands down in a UTF-8 locale, correctly, and a Linux runner ends
up in one twice over: it usually sets LANG itself, and with no locale set at all Python coerces the
C locale by writing LC_CTYPE=C.UTF-8 into its own environment. Either way every BLOCK case passes
silently on the runner, which is how the first CI run of this suite failed 52 of its 113 cases.

Drives the guard as a SUBPROCESS on stdin, the same way the hook does. No org, no network.

Run: python hooks/guards/test-pretool-grep-abort-guard.py
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "pretool-grep-abort-guard.py")
DISPATCHER = os.path.join(HERE, "..", "pretool-guards.py")
LOCALE = ("LANG", "LC_ALL", "LC_CTYPE")

checks = 0
failures = []


def clean_env(**extra):
    env = dict((k, v) for k, v in os.environ.items() if k not in LOCALE)
    # With no locale set, Python on Linux coerces the C locale at startup (PEP 538) and writes
    # LC_CTYPE=C.UTF-8 into its own environment, which the guard then reads as a UTF-8 locale and
    # stands down. That is right on Linux, whose grep does not abort, and it failed 52 cases of
    # this suite on a Linux CI runner while every one passed on Windows, which never coerces.
    env["PYTHONCOERCECLOCALE"] = "0"
    env.update(extra)
    return env


def run(script, command, tool="Bash", cwd=None, env=None):
    body = {"tool_name": tool, "tool_input": {"command": command}}
    if cwd:
        body["cwd"] = cwd
    done = subprocess.run([sys.executable, script], input=json.dumps(body),
                          capture_output=True, text=True, timeout=60,
                          env=clean_env() if env is None else env)
    out = (done.stdout or "").strip()
    if done.returncode != 0:
        return "EXIT %d: %s" % (done.returncode, (done.stderr or "")[:160]), ""
    if not out:
        return "none", ""
    try:
        hso = json.loads(out)["hookSpecificOutput"]
        return hso["permissionDecision"], hso.get("permissionDecisionReason") or ""
    except Exception:
        return "UNPARSED:" + out[:160], ""


def decision(command, **kw):
    return run(GUARD, command, **kw)[0]


def check(ok, label, detail=""):
    global checks
    checks += 1
    print(("  ok   " if ok else "  FAIL ") + label)
    if not ok:
        if detail:
            print("         " + detail)
        failures.append(label)


def load_guard():
    spec = importlib.util.spec_from_file_location("grep_abort_guard", GUARD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- must BLOCK -----------------------------------------------------------------------------
BLOCK = [
    ("jq -r '.records[].CreatedBy.Username' authors.json | tr -d '\\r' "
     "| grep -viF \"$COMPANY_DOMAIN\" | sort | uniq -c",
     "the audit-authors.sh pipeline as it shipped"),
    ('grep -n -i -e "DML" -e "owned by a profile" -e "profile-owned" docs/notes.md',
     "the 2026-09-10 search that found no DML notes in a file with a section on them"),
    ("grep -iF abc notes.txt", "-iF"),
    ("grep -Fi abc notes.txt", "-Fi"),
    ("grep -i -F abc notes.txt", "-i -F as two words"),
    ("grep -qiF abc notes.txt", "-qiF"),
    ("grep -y -F abc notes.txt", "-y, the old synonym for -i"),
    ("grep --ignore-case --fixed-strings abc notes.txt", "the long options"),
    ("grep --ign --fixed abc notes.txt", "unambiguous prefixes of the long options"),
    ("grep --fixed-regexp -i abc notes.txt", "--fixed-regexp, the older spelling"),
    ("fgrep -i abc notes.txt", "fgrep -i"),
    ("zfgrep -i abc notes.txt.gz", "zfgrep -i"),
    ("grep -X fgrep -i abc notes.txt", "-X fgrep"),
    ("grep abc notes.txt -iF", "options after the operands, which GNU getopt still reads"),
    ("grep -iF '' notes.txt", "an empty pattern aborts too"),
    ("grep -iwF abc notes.txt", "-w does not help"),
    ("grep -i -e abc -e xyz notes.txt", "two literal patterns"),
    ("grep -i --regexp=abc --regexp xyz notes.txt", "--regexp twice"),
    ("grep -i $'abc\\nxyz' notes.txt", "a newline inside one pattern"),
    ("grep -iE -e abc -e xyz notes.txt", "-E with two literal patterns"),
    ("grep -i -e abc -e 'a+c' notes.txt", "`+` is an ordinary character in a basic regex"),
    ("grep -i -e abc -e 'a\\.c' notes.txt", "an escaped dot is a literal dot"),
    ("grep -ie abc -e xyz notes.txt", "-e bundled after -i"),
    ("grep -i -f <(printf 'a\\nb\\n') notes.txt", "a -f file this guard cannot read"),
    ("x=$(grep -iF abc notes.txt)", "inside $(...)"),
    ("echo `grep -iF abc notes.txt`", "inside backticks"),
    ("echo \"found: $(grep -i -e abc -e xyz notes.txt)\"", "inside $(...) inside double quotes"),
    ("if grep -qiF abc notes.txt; then echo yes; fi", "under if, where the abort is just false"),
    ("while read -r w; do grep -qiF \"$w\" notes.txt && echo \"$w\"; done < words.txt",
     "a loop body, with the pattern in a variable"),
    ("find . -name '*.md' -exec grep -liF abc {} +", "behind find -exec"),
    ("printf 'a\\n' | xargs -I{} grep -iF {} notes.txt", "behind xargs"),
    ("command grep -iF abc notes.txt", "behind command"),
    ("timeout 5 grep -iF abc notes.txt", "behind timeout"),
    ("\\grep -iF abc notes.txt", "a backslash that skips an alias"),
    ("/usr/bin/grep -iF abc notes.txt", "a full path"),
    ("bash -c 'grep -iF abc notes.txt'", "inside bash -c"),
    ("bash <<'EOF'\ngrep -iF abc notes.txt\nEOF", "in a heredoc fed to bash"),
    ("cat <<EOF\n$(grep -iF abc notes.txt)\nEOF", "an unquoted heredoc still runs its $(...)"),
    ("LC_ALL=C.UTF-8; grep -iF abc notes.txt",
     "a bare assignment is not exported, so grep never sees it"),
    ("LC_ALL=C grep -iF abc notes.txt", "LC_ALL=C, the aborting locale, stated outright"),
    ("LANG=C.UTF-8 LC_ALL=C grep -iF abc notes.txt", "LC_ALL outranks LANG"),
    ("LANG=C.UTF-8 LC_CTYPE=C grep -iF abc notes.txt", "LC_CTYPE outranks LANG"),
    ("grep -iF abc notes.txt 2>/dev/null || echo none",
     "the `|| echo none` that turns the abort into a finding"),
]

# --- must PASS ------------------------------------------------------------------------------
PASS = [
    ("LC_ALL=C.UTF-8 grep -viF \"$COMPANY_DOMAIN\" authors.txt", "the fix: prefix THIS grep"),
    ("export LC_ALL=C.UTF-8; grep -iF abc notes.txt", "exported before the grep"),
    ("LANG=C.UTF-8 grep -iF abc notes.txt", "LANG alone is enough"),
    ("LC_CTYPE=C.UTF-8 grep -iF abc notes.txt", "LC_CTYPE alone is enough"),
    ("LC_ALL=en_US.UTF-8 grep -iF abc notes.txt", "any UTF-8 locale"),
    ("LC_ALL=C.utf8 grep -iF abc notes.txt", "the lowercase spelling"),
    ("env LC_ALL=C.UTF-8 grep -iF abc notes.txt", "env's own assignment"),
    ("LC_ALL=C.UTF-8 bash -c 'grep -iF abc notes.txt'",
     "a prefix on the shell reaches the grep inside it"),
    ("printf 'a\\n' | LC_ALL=C.UTF-8 xargs grep -iF abc", "a prefix on xargs"),
    ("grep -i abc notes.txt", "-i alone"),
    ("grep -F abc notes.txt", "-F alone"),
    ("grep -vF \"$COMPANY_DOMAIN\" authors.txt", "-F without -i"),
    ("grep -c -F -f ids.txt all.txt", "-F -f without -i"),
    ("grep -i -e abc notes.txt", "one pattern through -e"),
    ("grep -i -e 'a.c' -e xyz notes.txt", "one real regex keeps grep on its regex matcher"),
    ("grep -o -i -e 'Security Key ([^\"]\\{0,30\\}' -e 'QR code' notes.txt",
     "a bracket expression among the patterns"),
    ("grep -iE 'abc|xyz' notes.txt", "an alternation in one pattern, the easy rewrite"),
    ("grep -i 'abc\\|xyz' notes.txt", "the basic-regex alternation"),
    ("grep -iE -e abc -e 'a+c' notes.txt", "`+` is special in -E"),
    ("grep -i -e abc -e '\\bxyz' notes.txt", "a backslash anchor is a real regex"),
    ("grep -i \"$needle\" notes.txt", "a pattern held in a variable"),
    ("grep -i -e \"^$A\" -e \"$B\" notes.txt", "a variable pattern beside a real regex"),
    ("grep -i -e abc -f /dev/null notes.txt", "one pattern plus an empty pattern file"),
    ("grep -iP abc notes.txt", "-P, which grep refuses out loud in this locale"),
    ("grep -iF -E abc notes.txt", "conflicting matchers, which grep refuses out loud"),
    ("grep -i", "no pattern at all: grep prints its usage line"),
    ("grep --version", "--version"),
    ("git grep -iF abc", "git grep is git's own"),
    ("git log --grep=fix -i -F", "git log's own --grep, -i, and -F"),
    ("rg -iF abc", "ripgrep"),
    ("awk -F',' '{print $1}' notes.csv | grep -i abc", "awk -F in the same pipeline"),
    ("sed -i -e 's/a/b/' -e 's/c/d/' notes.txt", "sed -i -e -e is not grep"),
    ("echo 'grep -iF abc'", "quoted text"),
    ("git commit -m \"Stop grep -iF from aborting\"", "a commit message about the trap"),
    ("gh pr create --title \"chore: refuse grep -iF\" --body-file body.md", "a PR title"),
    ("cat > notes.md <<'EOF'\nUse grep -iF with care.\ngrep -i -e a -e b\nEOF",
     "a quoted heredoc writing about it"),
    ("python - <<'PY'\nprint('grep -iF abc')\nPY", "a Python heredoc mentioning it"),
    ("# grep -iF abc notes.txt", "a comment"),
    ("grep -rn 'grep -iF' docs/", "searching for the trap"),
    ("grep -rni 'grep -iF' docs/", "searching for it case-insensitively, as one pattern"),
    ("echo \"$(grep -i abc notes.txt)\"", "a clean grep inside $(...)"),
    ("python hooks/guards/test-pretool-grep-abort-guard.py", "running this very suite"),
]


def main():
    print("must BLOCK:")
    for cmd, label in BLOCK:
        got = decision(cmd)
        check(got == "deny", label, "got: " + got)

    print("\nmust PASS (false-positive cover):")
    for cmd, label in PASS:
        got = decision(cmd)
        check(got == "none", label, "got: " + got)

    print("\nthe environment the Bash tool inherits:")
    check(decision("grep -iF abc notes.txt", env=clean_env(LANG="C.UTF-8")) == "none",
          "a machine already on a UTF-8 locale is never blocked")
    check(decision("env -i grep -iF abc notes.txt", env=clean_env(LANG="C.UTF-8")) == "deny",
          "env -i drops that locale again")
    check(decision("grep -iF abc notes.txt", env=clean_env(LC_ALL="C")) == "deny",
          "LC_ALL=C in the environment is the aborting locale")

    print("\nfiles the command makes grep read or bash run:")
    tmp = tempfile.mkdtemp(prefix="grep-abort-")

    def put(name, text):
        with open(os.path.join(tmp, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    put("two.txt", "Smith\nJones\n")
    put("one.txt", "Smith\n")
    put("mixed.txt", "Smith\nJ.nes\n")
    check(decision("grep -i -f two.txt names.txt", cwd=tmp) == "deny",
          "a -f file holding two literal lines")
    check(decision("grep -i -f one.txt names.txt", cwd=tmp) == "none",
          "a -f file holding one line")
    check(decision("grep -i -f mixed.txt names.txt", cwd=tmp) == "none",
          "a -f file holding a real regex")
    put("probe.sh", "#!/usr/bin/env bash\nset -u\n"
                    "sf_users | tr -d '\\r' | grep -viF \"$COMPANY_DOMAIN\" | sort\n")
    put("clean.sh", "#!/usr/bin/env bash\ngrep -i abc notes.txt\n")
    put("exports.sh", "#!/usr/bin/env bash\nexport LC_ALL=C.UTF-8\ngrep -iF abc notes.txt\n")
    verdict, why = run(GUARD, "bash probe.sh", cwd=tmp)
    check(verdict == "deny", "a script run with bash is read too")
    check("probe.sh, line 3" in why, "the reason names the script and the line",
          why[:200].replace("\n", " "))
    check(decision("./probe.sh", cwd=tmp) == "deny", "a script run directly")
    check(decision("source probe.sh", cwd=tmp) == "deny", "a script sourced")
    check(decision("bash clean.sh", cwd=tmp) == "none", "a clean script passes")
    check(decision("bash exports.sh", cwd=tmp) == "none",
          "a script that exports a UTF-8 locale before its grep passes")
    check(decision("bash missing.sh", cwd=tmp) == "none",
          "a script that does not exist is nothing to read")

    print("\nother tools and shapes:")
    check(decision("grep -iF abc notes.txt", tool="PowerShell") == "none",
          "PowerShell is not covered")
    check(decision("grep -iF abc notes.txt", tool="Write") == "none",
          "Write is not this guard's tool")
    check(decision("") == "none", "empty command")

    print("\nthe reason carries the fix:")
    _, why = run(GUARD, "grep -viF \"$COMPANY_DOMAIN\" authors.txt")
    check("LC_ALL=C.UTF-8 grep" in why, "names the prefix that fixes it")
    check("exit 134" in why, "says how it fails")
    check("does NOT reach grep" in why, "warns that a bare assignment is not enough")
    check("no override" in why, "says there is no override")
    check('grep -viF "$COMPANY_DOMAIN" authors.txt' in why, "quotes the offending grep")
    _, why = run(GUARD, "grep -i -e alpha -e bravo -e charlie chart.txt")
    check("3 patterns" in why, "the multi-pattern reason counts the patterns")

    print("\nregistration:")
    spec = importlib.util.spec_from_file_location("dispatcher", DISPATCHER)
    dispatcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dispatcher)
    check("pretool-grep-abort-guard.py" in dispatcher.GUARDS,
          "the guard is in the dispatcher's GUARDS tuple, so it actually runs")
    verdict, why = run(DISPATCHER, "grep -iF abc notes.txt")
    check(verdict == "deny" and "ABORTS in git-bash" in why,
          "the dispatcher denies it end to end, with this guard's reason", verdict)


    if failures:
        print("\nFAIL: %d of %d case(s)" % (len(failures), checks))
        for f in failures:
            print("  - " + f)
        return 1
    print("\nPASS: %d cases (%d block, %d false-positive guards)." % (checks, len(BLOCK),
                                                                     len(PASS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
