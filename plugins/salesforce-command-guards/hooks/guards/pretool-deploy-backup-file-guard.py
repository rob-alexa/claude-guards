#!/usr/bin/env python3
"""
PreToolUse guard — refuse an `sf project deploy` whose source tree holds a BACKUP COPY of a
metadata file, because the resolver sends the BACKUP's content and reports success.

WHAT IT IS AIMED AT, AND WHY THIS ONE IS WORTH A GUARD RATHER THAN A DOC LINE. On 2026-09-06
a session copied `Field_Ops.permissionset-meta.xml` to `...-meta.xml.before`, edited
the real file, and deployed that directory. The result was `status=Succeeded`, `1/1`,
`errors=0`, the component listed under `componentSuccesses`, and `changed=false`. The org was
untouched: old description, old object permissions, `LastModifiedDate` unmoved. Deleting the
`.before` file and re-running the IDENTICAL command gave `changed=true` and the change landed.

Nothing in the payload can tell you this happened. `status` is Succeeded, the error count is
zero, and the component is a success, so every check you would run on a deploy
result passes. Only a query against the org disproves it. That is the property this is aimed
at: a failure that renders as a reassuring success. Its sibling shapes are already
written down (a `Flow` reporting `changed=false` beside its `FlowDefinition`, and a permission
whose dependency is absent from the file), which is exactly why another line about
`changed=false` was not the lever.

WHAT IS ACTUALLY BROKEN, measured locally on 2026-09-07 with `sf project convert source`, which
runs the same source resolver with no org involved:

    file present beside the real one          components  content sent
    (none)                                    1           the real file
    Probe_Set.permissionset-meta.xml.before   1           THE BACKUP
    Probe_Set.permissionset-meta.xml.bak      1           THE BACKUP
    Probe_Set.permissionset-meta.xml~         1           THE BACKUP
    notes.txt                                 1           the real file
    Probe_Set_backup.permissionset-meta.xml   2           both, correctly

So it is sharper than "your file was not sent": the resolver registers the backup as the SAME
component and sends the backup's content. The suffix is irrelevant -- anything appended after
`-meta.xml` does it -- and an unrelated file in the directory is harmless. A differently-named
valid component resolves correctly as a second component, which is why the match below is not
"two files with similar names".

NOT BROKEN: a backup of a non-`-meta.xml` source file. `Probe.cls.bak`, `Probe.cls~`, and
`Probe.cls.before` all left the real `Probe.cls` content intact, because the resolver keys the
component off the `-meta.xml` file. So this guard deliberately matches ONLY `-meta.xml` plus at
least one more character, which is a pattern no legitimate source file has -- a real one's name
ends exactly at `-meta.xml`. That is what keeps it quiet.

THE ESCAPE HATCH IS THE CORRECT ACTION: move the backup out of the deploy directory.
There is no flag, because a per-deploy bypass would be
self-applied in exactly the moment the trap bites.

WHAT IT COVERS. `sf project deploy start` and `sf project deploy validate`, both of which send
the payload (a validate against the wrong content reports a clean validation, which is worse
before a release than a bad deploy). It scans the directories named by `-d`/`--source-dir`, and
where the command names none -- a `--manifest` or `--metadata` deploy, which resolves from the
project's `packageDirectories` -- it scans those instead. 2,976 files under `force-app` scan in
about a quarter of a second, so covering that case is affordable; `sf project deploy quick`
takes no source at all and is not covered because there is nothing to scan.

FALSE POSITIVES ARE THE THING TO AVOID, since a guard that cries wolf gets removed. It bails
out before doing any work unless the command text contains `project deploy`, the pattern cannot
match a legitimate source filename, a directory it cannot resolve is skipped rather than
guessed at, and a walk that runs past `MAX_FILES` gives up and says nothing.

Self-checks: test-pretool-deploy-backup-file-guard.py, beside this file.
"""
import json
import os
import re
import sys

# A real source file's name ends exactly at `-meta.xml`. One more character means a copy.
_BACKUP_OF_META = re.compile(r"-meta\.xml.+$", re.IGNORECASE)

# `-d` / `--source-dir` is repeatable, and the value may be quoted.
_SOURCE_DIR = re.compile(
    r"(?:--source-dir|(?<![\w-])-d)[=\s]+('[^']*'|\"[^\"]*\"|[^\s|&;<>]+)")

# A `cd` in the command changes what a relative `-d` resolves against, and the payload's `cwd`
# does not reflect it.
_CD = re.compile(r"(?:^|[;&|]\s*|\bthen\s+|\bdo\s+)cd\s+('[^']*'|\"[^\"]*\"|[^\s;&|]+)")
# A bare `cd` goes to $HOME, which is a directory this cannot name from the command text.
_CD_BARE = re.compile(r"(?:^|[;&|]\s*|\bthen\s+|\bdo\s+)cd\s*(?:$|[;&|])")

# Only these two send a payload. `quick` re-uses a validation id and carries no source. `sf`
# has to be there so `echo project deploy start ...` is not read as running one; a heredoc that
# QUOTES a real `sf project deploy` command still matches, which is the same limitation the
# User.Email guard documents, and the residual harm is near zero -- it can only deny when a
# backup file genuinely exists, and then removing that file is the right move regardless.
_DEPLOY_VERB = re.compile(r"\bsfj?\s+project\s+deploy\s+(?:start|validate)\b")

# A pathological tree must not stall every deploy. Past this, report nothing.
MAX_FILES = 40000


def source_dirs(command):
    """The directories a deploy command names, as written (relative or absolute)."""
    found = []
    for match in _SOURCE_DIR.finditer(command):
        value = match.group(1).strip("'\"")
        if value and "$" not in value and value not in found:
            found.append(value)
    return found


def package_directories(root):
    """`packageDirectories` from the project at `root`, for a deploy that names no directory."""
    path = os.path.join(root, "sfdx-project.json")
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        return []
    dirs = []
    for entry in data.get("packageDirectories") or []:
        if isinstance(entry, dict) and entry.get("path"):
            dirs.append(entry["path"])
    return dirs


def backups_under(directory):
    """Every backup-of-a-metadata-file under `directory`, as paths relative to it.

    Returns None when the tree could not be walked or ran past MAX_FILES, which the caller
    treats as "say nothing" -- the same fail-open every other guard here applies.
    """
    if not os.path.isdir(directory):
        return None
    hits = []
    seen = 0
    for current, _subdirs, files in os.walk(directory):
        for name in files:
            seen += 1
            if seen > MAX_FILES:
                return None
            if _BACKUP_OF_META.search(name):
                full = os.path.join(current, name)
                hits.append(os.path.relpath(full, directory).replace("\\", "/"))
    return hits


def offenders(command, cwd):
    """(directory as written, [backup files]) for every directory this deploy would send."""
    if not _DEPLOY_VERB.search(command):
        return []
    base = cwd or os.getcwd()
    named = source_dirs(command)
    if named:
        candidates = [(d, d if os.path.isabs(d) else os.path.join(base, d)) for d in named]
    elif _SOURCE_DIR.search(command):
        # A `-d` IS there but its value could not be read (a `$VAR`). Falling back to
        # packageDirectories here would scan a DIFFERENT scope than the command deploys, so
        # this reports nothing instead of guessing at one.
        return []
    else:
        # A --manifest or --metadata deploy resolves from the project's packageDirectories.
        candidates = [(d, os.path.join(base, d)) for d in package_directories(base)]
    found = []
    for written, resolved in candidates:
        hits = backups_under(resolved)
        if hits:
            found.append((written, sorted(hits)))
    return found


def effective_cwd(command, cwd):
    """The directory a relative path in the command resolves against, folding each `cd` in order.

    None when a `cd` cannot be resolved from the text (a `$VAR`, a bare `cd`, `cd -`, or a
    directory that is not there), and the caller then keeps the payload `cwd`.
    """
    if _CD_BARE.search(command):
        return None
    matches = _CD.findall(command)
    if not matches:
        return cwd
    directory = cwd or os.getcwd()
    for raw in matches:
        target = raw.strip("'\"")
        if not target or "$" in target or target == "-":
            return None
        directory = target if os.path.isabs(target) else os.path.join(directory, target)
        if not os.path.isdir(directory):
            return None
    return directory


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    try:
        tool = payload.get("tool_name") or ""
        if tool not in ("Bash", "PowerShell"):
            return 0
        command = (payload.get("tool_input") or {}).get("command") or ""
        if "project deploy" not in command:
            return 0  # the cheap bail-out, so this costs nothing on an ordinary tool call

        cwd = payload.get("cwd") or os.getcwd()
        # Honor the command's own `cd`, since new-worktree.sh itself prints
        # `( cd "<worktree>" && sf project deploy ... )` as the way to drive a worktree.
        try:
            resolved = effective_cwd(command, cwd)
            if resolved:
                cwd = resolved
        except Exception:
            pass  # fall back to the payload cwd rather than failing the check

        found = offenders(command, cwd)
        if not found:
            return 0

        blocks = []
        for written, hits in found:
            listed = "\n".join("      " + h for h in hits[:10])
            if len(hits) > 10:
                listed += "\n      ... and {0} more".format(len(hits) - 10)
            blocks.append("  {0}\n{1}".format(written, listed))
        reason = (
            "Blocked: this deploy's source tree holds a BACKUP COPY of a metadata file, and the "
            "resolver would send the BACKUP's content while reporting success.\n\n"
            + "\n".join(blocks)
            + "\n\nA real source file's name ends exactly at `-meta.xml`; each file listed has "
            "something appended, so the resolver registers it as the SAME component and sends "
            "it instead of yours. Measured: the deploy returns `status=Succeeded`, `1/1`, "
            "`errors=0`, the component under `componentSuccesses`, and `changed=false`, having "
            "applied nothing -- so no check on the payload catches it and only a query against "
            "the org disproves it. Move the backup OUTSIDE the directory you deploy (or delete "
            "it) and re-run the identical command. There is deliberately no override flag. Not "
            "what tripped this: an unrelated file in the directory is harmless, a backup of a "
            "non-`-meta.xml` source file (`.cls.bak`) is harmless, and a differently-named "
            "component resolves correctly as its own."
        )
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }))
    except Exception:
        return 0  # fail-open: a bug here must not wedge every deploy
    return 0


if __name__ == "__main__":
    sys.exit(main())
