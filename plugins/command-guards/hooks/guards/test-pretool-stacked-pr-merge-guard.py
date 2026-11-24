"""Self-checks for pretool-stacked-pr-merge-guard.py.

The guard refuses `gh pr merge` while another open pull request is based on the merging pull
request's head branch, because the merge deletes that branch and deleting a pull request's base
closes it. That is how a stacked pull request closed on 2026-10-05.

THE GUARD CALLS GITHUB, SO THIS SUITE RUNS IT AGAINST A FAKE `gh`. Each case writes the answers
the fake gives, puts the fake first on PATH, and drives the guard as a SUBPROCESS on stdin, the
same way the hook does. The fake logs every call it receives, which is how the false-positive
cases prove the guard never reached GitHub at all rather than merely deciding not to deny. On
Windows the fake is a `.cmd` wrapper, so a Windows run also covers the shutil.which route that
keeps a shim from failing with WinError 2; on Linux, where CI runs this, it is an executable
script.

Run: python hooks/guards/test-pretool-stacked-pr-merge-guard.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "pretool-stacked-pr-merge-guard.py")

FAKE_GH = '''
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\\n")
with open(os.environ["FAKE_GH_DATA"], encoding="utf-8") as fh:
    data = json.load(fh)
mode = data.get("mode", "ok")
if mode == "fail":
    sys.stderr.write("HTTP 401: Bad credentials (https://api.github.com/graphql)\\n")
    sys.exit(1)
if mode == "garbage":
    print("<html>not json</html>")
    sys.exit(0)
if args[:2] == ["pr", "view"]:
    rest = args[2:]
    key = rest[0] if rest and not rest[0].startswith("-") else ""
    pr = data.get("views", {}).get(key)
    if pr is None:
        sys.stderr.write("no pull requests found\\n")
        sys.exit(1)
    print(json.dumps(pr))
elif args[:2] == ["pr", "list"]:
    base = args[args.index("--base") + 1] if "--base" in args else ""
    print(json.dumps(data.get("lists", {}).get(base, [])))
else:
    sys.exit(2)
'''

HEAD = "feature/PROJ-102-report-export"
URL_101 = "https://github.com/example-org/example-repo/pull/101"
PR_101 = {"number": 101, "headRefName": HEAD, "baseRefName": "develop",
           "state": "OPEN", "isCrossRepository": False}
PR_102 = {"number": 102,
           "title": "PROJ-111: Paged tables in the report view"}
PR_105 = {"number": 105, "title": "PROJ-114: Preview a dashboard before saving it"}

checks = 0
failures = []


def world(**over):
    """What the fake gh answers: #101 open on HEAD, with #102 stacked on it."""
    data = {"views": {"101": PR_101, "": PR_101, URL_101: PR_101},
            "lists": {HEAD: [PR_102]}}
    data.update(over)
    return data


def install_fake(bindir):
    script = os.path.join(bindir, "fake_gh.py")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write(FAKE_GH)
    if os.name == "nt":
        with open(os.path.join(bindir, "gh.cmd"), "w", encoding="utf-8") as fh:
            fh.write('@"{0}" "{1}" %*\r\n'.format(sys.executable, script))
    else:
        path = os.path.join(bindir, "gh")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!{0}\n".format(sys.executable) + FAKE_GH)
        os.chmod(path, 0o755)


def run(command, data=None, tool="Bash", gh="fake", tool_input=None):
    """Drive the guard once. Returns (decision, reason, gh calls, exit code)."""
    with tempfile.TemporaryDirectory() as tmp:
        bindir = os.path.join(tmp, "bin")
        os.mkdir(bindir)
        if gh == "fake":
            install_fake(bindir)
        data_path = os.path.join(tmp, "data.json")
        log_path = os.path.join(tmp, "calls.log")
        with open(data_path, "w", encoding="utf-8") as fh:
            json.dump(world() if data is None else data, fh)
        env = dict(os.environ)
        env["FAKE_GH_DATA"] = data_path
        env["FAKE_GH_LOG"] = log_path
        # The fake goes first on PATH. With gh="none" PATH holds only an empty directory, so
        # there is no gh to find at all.
        env["PATH"] = bindir + (os.pathsep + env.get("PATH", "") if gh == "fake" else "")
        payload = {"tool_name": tool,
                   "tool_input": tool_input if tool_input is not None else {"command": command},
                   "cwd": tmp}
        done = subprocess.run([sys.executable, GUARD], input=json.dumps(payload),
                              capture_output=True, text=True, timeout=120, env=env)
        calls = []
        if os.path.exists(log_path):
            with open(log_path, encoding="utf-8") as fh:
                calls = [json.loads(line) for line in fh if line.strip()]
    out = (done.stdout or "").strip()
    if not out:
        return "none", "", calls, done.returncode
    try:
        hso = json.loads(out)["hookSpecificOutput"]
        return (hso.get("permissionDecision"), hso.get("permissionDecisionReason") or "",
                calls, done.returncode)
    except Exception:
        return "UNPARSED:" + out[:160], "", calls, done.returncode


def check(ok, label, detail=""):
    global checks
    checks += 1
    print(("  ok   " if ok else "  FAIL ") + label)
    if not ok:
        if detail:
            print("         " + detail)
        failures.append(label)


# --- must BLOCK: a merge that would delete the base of an open pull request ----------------
BLOCK = [
    ("gh pr merge 101 --squash --delete-branch",
     "the 2026-10-05 merge, with the routine cleanup flag"),
    ("gh pr merge 101 --squash",
     "no --delete-branch: delete_branch_on_merge deletes the branch anyway"),
    ("gh pr merge 101 -sd", "combined short flags"),
    ("gh pr merge " + URL_101 + " --squash", "the pull request named by URL"),
    ("gh pr merge --squash --delete-branch", "no selector: the checked-out branch's pull request"),
    ("git fetch origin --prune && gh pr merge 101 --squash", "after &&"),
    ("gh pr merge 101 --auto --squash", "auto-merge deletes the branch when it lands"),
    ("gh pr merge 101 -R example-org/example-repo --squash", "-R names the repository"),
    ("gh pr merge --subject 'PROJ-102: Report export' --body 'Ships it' 101",
     "long value flags before the selector"),
    ("gh pr merge -t 'PROJ-102: Report export' 101 --squash",
     "a short value flag before the selector"),
    ("gh pr merge 101 --squash 2>&1 | tail -3", "stderr merged and piped"),
    ("gh pr merge 101 --squash > merge.log", "stdout redirected, no selector confusion"),
    ("if true; then gh pr merge 101 --squash; fi", "inside an if"),
    ("MSYS_NO_PATHCONV=1 gh pr merge 101 --squash", "behind an environment assignment"),
]

# --- must PASS without ever calling gh: not a merge at command position --------------------
QUIET = [
    ("gh pr view 101", "viewing, not merging"),
    ("gh pr merge 101 --disable-auto", "--disable-auto merges nothing"),
    ('git commit -m "Run gh pr merge 101 once QA passes"', "a commit message that mentions it"),
    ('echo "gh pr merge 101 --squash"', "an echo that mentions it"),
    ('grep -rn "gh pr merge" CLAUDE.md docs/', "a grep for it"),
    ("git merge --no-ff origin/develop", "a git merge, not a pull request merge"),
    ("ls -la", "an ordinary command"),
]


def main():
    print("Blocks: a merge that would close a stacked pull request")
    for command, label in BLOCK:
        decision, reason, calls, rc = run(command)
        check(decision == "deny" and "gh pr edit 102 --base develop" in reason
              and rc == 0, label,
              "decision={0} rc={1} reason={2}".format(decision, rc, reason[:200]))

    decision, reason, calls, rc = run("gh pr merge 101 --squash --delete-branch",
                                      tool="PowerShell")
    check(decision == "deny", "the same merge through the PowerShell tool",
          "decision=" + decision)

    print("\nWhat a block says and asks GitHub")
    decision, reason, calls, rc = run("gh pr merge 101 --squash")
    check("#102" in reason and "delete_branch_on_merge" in reason
          and "rebase only the stacked commits" in reason,
          "the reason names the stacked pull request, the repo setting, and the squash fix",
          reason[:240])
    check(any(c[:2] == ["pr", "list"] and HEAD in c for c in calls),
          "the stacked pull requests are looked up by the merging pull request's HEAD branch",
          json.dumps(calls))

    decision, reason, calls, rc = run("gh pr merge 101 -R example-org/example-repo --squash")
    check(all("--repo" in c and "example-org/example-repo" in c for c in calls) and len(calls) == 2,
          "-R is passed to both gh calls", json.dumps(calls))

    decision, reason, calls, rc = run("gh pr merge " + URL_101 + " --squash")
    lists = [c for c in calls if c[:2] == ["pr", "list"]]
    check(bool(lists) and "example-org/example-repo" in lists[0],
          "a URL selector scopes the list call to the URL's repository", json.dumps(calls))

    decision, reason, calls, rc = run("gh pr merge 101 --squash",
                                      data=world(lists={HEAD: [PR_102, PR_105]}))
    check(decision == "deny" and "2 open pull requests use" in reason
          and "gh pr edit 102 --base develop" in reason
          and "gh pr edit 105 --base develop" in reason,
          "two stacked pull requests are both named, each with its own retarget", reason[:300])

    print("\nPasses without calling gh")
    for command, label in QUIET:
        decision, reason, calls, rc = run(command)
        check(decision == "none" and not calls and rc == 0, label,
              "decision={0} calls={1}".format(decision, json.dumps(calls)))

    decision, reason, calls, rc = run(None, tool="Write", tool_input={
        "file_path": "notes.md", "content": "gh pr merge 101 --squash --delete-branch"})
    check(decision == "none" and not calls, "a Write that contains the command",
          "decision={0} calls={1}".format(decision, json.dumps(calls)))

    print("\nPasses after asking GitHub: nothing stacked, or nothing it can stand behind")
    cases = [
        (world(lists={}), "nothing is based on the branch"),
        (world(lists={"feature/some-other-branch": [PR_102]}),
         "a pull request stacked on a DIFFERENT branch does not count"),
        (world(views={"101": dict(PR_101, isCrossRepository=True)}),
         "a pull request from a fork: its head branch is not in this repository"),
        (world(views={"101": dict(PR_101, state="MERGED")}),
         "a pull request that is no longer open"),
        (world(mode="fail"), "gh fails (unauthenticated, offline): fail open"),
        (world(mode="garbage"), "gh prints something that is not JSON: fail open"),
    ]
    for data, label in cases:
        decision, reason, calls, rc = run("gh pr merge 101 --squash", data=data)
        check(decision == "none" and rc == 0, label, "decision=" + decision)

    decision, reason, calls, rc = run('gh pr merge "$PR" --squash')
    check(decision == "none", "a selector in a shell variable cannot be resolved: fail open",
          "decision=" + decision)

    decision, reason, calls, rc = run("gh pr merge 101 --squash", gh="none")
    check(decision == "none" and rc == 0, "no gh on PATH at all: fail open",
          "decision={0} rc={1}".format(decision, rc))

    print("\n{0} checks, {1} failed".format(checks, len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
