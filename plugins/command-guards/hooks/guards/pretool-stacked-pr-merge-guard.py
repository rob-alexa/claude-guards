#!/usr/bin/env python3
"""
PreToolUse guard — refuse `gh pr merge` while another OPEN pull request uses the merging pull
request's head branch as its BASE.

WHY. A merge usually deletes the head branch: a repository with `delete_branch_on_merge` on does
it automatically, and `gh pr merge --delete-branch` does it explicitly. Deleting a pull request's
base branch CLOSES that pull request; it is not retargeted. On 2026-10-05 a merge closed the pull
request stacked on it two seconds later, its events reading `base_ref_deleted` then `closed`, and
the merge's output did not mention it. It was found the next day, by which point the work was one
QA step from done with no open pull request to carry its code to the integration branch. Undoing
it took restoring the deleted branch at its last commit, reopening, retargeting, and deleting the
branch again, because GitHub will
not reopen a pull request whose base branch no longer exists.

WHAT IT CHECKS. For each `gh pr merge` in a Bash or PowerShell command it resolves the pull
request being merged (the positional argument, or the checked-out branch's when there is none)
and lists the open pull requests based on its head branch. Any hit is a deny that names each one
and the fix: point it at the merging pull request's own base, then merge. After a SQUASH merge
the stacked branch still carries the merged branch's original commits, so merging the base into
it later reports add/add conflicts that are not real; rebase only its own commits onto the new
base instead (`git rebase --onto <base> <old head of the merged branch>`).

EVERY MERGE, NOT ONLY `--delete-branch`. `delete_branch_on_merge` deletes the head branch
whatever flags the merge carries, so keying on the flag would leave the same failure one omitted
flag away. Where neither applies the block is only cautious, and retargeting first costs
nothing. `--disable-auto` merges nothing and is skipped, as is a pull request from a fork,
whose head branch lives in another repository.

COMMAND POSITION ONLY. A `gh pr merge` counts only where a command starts: the start of the
text, or after `;`, `&`, `|`, `(`, `{`, or a newline, optionally followed by `then`, `do`, or
`else`. So a commit message, PR body, `echo`, or `grep` that merely mentions the command never
reaches GitHub, and an ordinary tool call costs two substring tests.

FAIL-OPEN. The check needs GitHub, so when `gh` is missing, unauthenticated, offline, or slow,
or the pull request cannot be resolved (a selector held in a shell variable, for one), this says
nothing and the merge's own permission prompt remains the control. A merge costs two `gh` calls,
about a second each when measured on 2026-10-06, and each is capped at GH_TIMEOUT seconds so
both together stay inside the dispatcher's 30-second hook timeout. `gh` is resolved with shutil.which, which honors PATHEXT, so a `.cmd` shim on Windows
runs instead of failing with WinError 2.

LIMIT. With no positional argument the pull request is the one for the branch checked out in the
hook's working directory, so `cd <worktree> && gh pr merge` is resolved against the wrong
checkout. Name the pull request by number.

There is no override flag: retargeting the stacked pull request is always possible, and it is
the fix.

Self-checks: hooks/guards/test-pretool-stacked-pr-merge-guard.py
"""
import json
import re
import shlex
import shutil
import subprocess
import sys

GH_TIMEOUT = 8

# `gh pr merge` where a command starts, then its arguments up to the next shell separator.
MERGE = re.compile(
    r"(?:^|[;&|({\n])\s*(?:(?:then|do|else)\s+)?"
    r"(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
    r"gh(?:\.exe)?\s+pr\s+merge\b([^;&|\n)]*)"
)

# Redirections, so `> out.txt` or `2>` is never read as the pull request to merge.
REDIRECT = re.compile(r"\d*[<>]{1,2}\s*[^\s;&|]*")

# The `gh pr merge` flags that take a value, so the token after one is not the selector.
VALUE_FLAGS = (
    "-b", "--body", "-F", "--body-file", "-t", "--subject", "-A", "--author-email",
    "--match-head-commit", "-R", "--repo",
)

PR_URL = re.compile(r"^https?://github\.com/([^/\s]+/[^/\s]+)/pull/\d+")


def parse(args_text):
    """Return (selector, repo, disables_auto) for one `gh pr merge` argument string."""
    text = REDIRECT.sub(" ", args_text)
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()
    selector = repo = None
    disables_auto = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("--"):
            name, has_value, value = tok.partition("=")
            if name == "--disable-auto":
                disables_auto = True
            elif name in VALUE_FLAGS and not has_value:
                i += 1
                value = tokens[i] if i < len(tokens) else ""
            if name == "--repo":
                repo = value or None
        elif tok.startswith("-") and len(tok) > 1:
            flag = tok[:2]
            if flag in VALUE_FLAGS:
                value = tok[2:]
                if not value:
                    i += 1
                    value = tokens[i] if i < len(tokens) else ""
                if flag == "-R":
                    repo = value or None
        elif selector is None:
            selector = tok
        i += 1
    if repo is None and selector:
        url = PR_URL.match(selector)
        if url:
            repo = url.group(1)
    return selector, repo, disables_auto


def gh_json(args, cwd):
    """Run gh and parse its JSON output, or return None on ANY failure: this guard fails open."""
    exe = shutil.which("gh")
    if not exe:
        return None
    try:
        done = subprocess.run(
            [exe] + args, cwd=cwd or None, capture_output=True,
            encoding="utf-8", errors="replace", timeout=GH_TIMEOUT,
        )
    except Exception:
        return None
    if done.returncode != 0:
        return None
    try:
        return json.loads(done.stdout)
    except Exception:
        return None


def stacked_on(selector, repo, cwd):
    """(pull request, [open pull requests based on its head]) for one merge, or None."""
    repo_args = ["--repo", repo] if repo else []
    pr = gh_json(
        ["pr", "view"] + ([selector] if selector else []) + repo_args
        + ["--json", "number,headRefName,baseRefName,state,isCrossRepository"],
        cwd,
    )
    if not isinstance(pr, dict) or pr.get("state") != "OPEN" or pr.get("isCrossRepository"):
        return None
    head = pr.get("headRefName")
    if not head:
        return None
    stacked = gh_json(
        ["pr", "list", "--base", head, "--state", "open", "--json", "number,title"] + repo_args,
        cwd,
    )
    if not isinstance(stacked, list) or not stacked:
        return None
    return pr, stacked


def reason_for(pr, stacked):
    number, head, base = pr.get("number"), pr.get("headRefName"), pr.get("baseRefName")
    one = len(stacked) == 1
    listed = "\n".join("  #{0}  {1}".format(s.get("number"), s.get("title") or "")
                       for s in stacked)
    edits = "\n".join("  gh pr edit {0} --base {1}".format(s.get("number"), base)
                      for s in stacked)
    return (
        "Blocked: merging #{number} deletes its branch {head}, and {count} {uses} that branch "
        "as {its} base:\n{listed}\n\n"
        "Deleting a pull request's base branch CLOSES it instead of retargeting it, and a "
        "repository with delete_branch_on_merge on deletes a merged branch whether or not "
        "--delete-branch is passed.\n\n"
        "Point {them} at {base} first, then run the merge again:\n{edits}\n\n"
        "If #{number} is squash-merged, {each} branch still carries its original commits "
        "afterwards, so merging {base} into {it} reports add/add conflicts that are not real; "
        "rebase only the stacked commits onto {base} instead. There is no override: "
        "retargeting is always possible, and it is the fix."
    ).format(
        number=number, head=head, base=base, listed=listed, edits=edits,
        count="1 open pull request" if one else "{0} open pull requests".format(len(stacked)),
        uses="uses" if one else "use",
        its="its" if one else "their",
        them="it" if one else "each one",
        each="that" if one else "each",
        it="it" if one else "one",
    )


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    try:
        if (payload.get("tool_name") or "") not in ("Bash", "PowerShell"):
            return 0
        command = (payload.get("tool_input") or {}).get("command") or ""
        # Cheap bail-out first, so this costs nothing on an ordinary tool call.
        if "gh" not in command or "merge" not in command:
            return 0

        reasons = []
        for match in MERGE.finditer(command):
            selector, repo, disables_auto = parse(match.group(1))
            if disables_auto:
                continue
            hit = stacked_on(selector, repo, payload.get("cwd"))
            if hit:
                reasons.append(reason_for(*hit))
        if not reasons:
            return 0

        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "\n\n".join(reasons),
            }
        }))
    except Exception:
        return 0  # fail-open: a bug here must not wedge every merge
    return 0


if __name__ == "__main__":
    sys.exit(main())
