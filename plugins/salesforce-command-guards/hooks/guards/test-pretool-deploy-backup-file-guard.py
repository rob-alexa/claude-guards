#!/usr/bin/env python3
"""
Self-checks for pretool-deploy-backup-file-guard.py.

WHAT THIS HAS TO PROVE. Two things, and the second decides whether the guard survives. That it
DENIES the shape the 2026-09-06 incident took: a `-meta.xml.before` copy sitting beside the real
file in the directory being deployed. And that it stays SILENT everywhere a deploy is ordinary,
because a guard that cries wolf gets removed -- so most of the cases below are false-positive
guards, not denials.

Every case runs against a REAL directory tree on disk, because the guard's whole decision is a
filesystem question and a mocked answer would prove nothing about it. The trees are throwaway.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "pretool-deploy-backup-file-guard.py")

checks = 0
failures = []


def check(ok, label, detail=""):
    global checks
    checks += 1
    print(("  ok   " if ok else "  FAIL ") + label)
    if not ok:
        if detail:
            print("         " + detail)
        failures.append(label)


def verdict(command, cwd, tool="Bash"):
    payload = json.dumps({"tool_name": tool, "tool_input": {"command": command}, "cwd": cwd})
    done = subprocess.run([sys.executable, GUARD], input=payload,
                          capture_output=True, text=True, timeout=60)
    out = (done.stdout or "").strip()
    if not out:
        return "none"
    try:
        return json.loads(out)["hookSpecificOutput"]["permissionDecision"]
    except Exception:
        return "UNPARSED:" + out[:120]


def reason_for(command, cwd):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd})
    done = subprocess.run([sys.executable, GUARD], input=payload,
                          capture_output=True, text=True, timeout=60)
    try:
        return json.loads(done.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
    except Exception:
        return ""


def make_tree(extra_files=(), package_dir="src"):
    """A project holding one real permission set, plus whatever extra files a case wants."""
    root = tempfile.mkdtemp(prefix="depguard-")
    inner = os.path.join(root, package_dir, "permissionsets")
    os.makedirs(inner, exist_ok=True)
    with open(os.path.join(root, "sfdx-project.json"), "w", encoding="utf-8") as fh:
        json.dump({"packageDirectories": [{"path": package_dir, "default": True}],
                   "namespace": "", "sourceApiVersion": "65.0"}, fh)
    real = os.path.join(inner, "Probe_Set.permissionset-meta.xml")
    with open(real, "w", encoding="utf-8") as fh:
        fh.write("<PermissionSet><label>Probe Set</label></PermissionSet>\n")
    for name in extra_files:
        target = os.path.join(inner, name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("<PermissionSet><label>copy</label></PermissionSet>\n")
    return root


def main():
    clean = make_tree()
    dirty = make_tree(["Probe_Set.permissionset-meta.xml.before"])
    bak = make_tree(["Probe_Set.permissionset-meta.xml.bak"])
    tilde = make_tree(["Probe_Set.permissionset-meta.xml~"])
    nested = make_tree([os.path.join("sub", "Probe_Set.permissionset-meta.xml.orig")])
    many = make_tree(["Probe_Set.permissionset-meta.xml.before",
                      "Probe_Set.permissionset-meta.xml.bak"])
    trees = [clean, dirty, bak, tilde, nested, many]

    print("Denies the shape the 2026-09-06 incident took")
    check(verdict("sf project deploy start --source-dir src", dirty) == "deny",
          "a `-meta.xml.before` copy in the deployed directory")
    check(verdict("sf project deploy start -d src", bak) == "deny",
          "a `-meta.xml.bak` copy, via the short flag")
    check(verdict("sf project deploy start -d src", tilde) == "deny",
          "an editor's `-meta.xml~` copy")
    check(verdict("sf project deploy start -d src", nested) == "deny",
          "a copy in a SUBDIRECTORY of the deployed path, since the walk is recursive")
    check(verdict("sf project deploy validate -d src", dirty) == "deny",
          "a VALIDATE is denied too: it would report a clean validation of the wrong content")
    check(verdict("sf project deploy start -d " + os.path.join(dirty, "src"), clean) == "deny",
          "an ABSOLUTE --source-dir is resolved, not read against the cwd")
    check(verdict("cd " + dirty + " && sf project deploy start -d src", clean) == "deny",
          "the command's own `cd` is honored, which is how new-worktree.sh says to drive one")
    check(verdict("sf project deploy start --manifest package.xml", dirty) == "deny",
          "a MANIFEST deploy is covered, by scanning the project's packageDirectories")

    print("\nThe denial says which files and where")
    text = reason_for("sf project deploy start -d src", many)
    check("Probe_Set.permissionset-meta.xml.before" in text
          and "Probe_Set.permissionset-meta.xml.bak" in text,
          "both offending files are named, so a second one is not hidden behind the first")
    check("changed=false" in text and "no override flag" in text,
          "the reason carries the symptom to recognize and says there is no bypass")

    print("\nStays silent on an ordinary deploy (false-positive guards)")
    check(verdict("sf project deploy start --source-dir src", clean) == "none",
          "a directory holding only real source files")
    check(verdict("sf project deploy start -d src", make_tree(["notes.txt"])) == "none",
          "an unrelated file in the directory is harmless, as measured")
    check(verdict("sf project deploy start -d src",
                  make_tree(["Probe_Set_backup.permissionset-meta.xml"])) == "none",
          "a differently-named component resolves correctly and is not a backup")
    check(verdict("sf project deploy start -d src", make_tree(["Other.permissionset-meta.xml"]))
          == "none", "a second real permission set is not a backup")
    check(verdict("sf project deploy start -d no/such/dir", dirty) == "none",
          "a directory that is not there is skipped, not guessed at")
    check(verdict("sf project deploy start -d $SOME_DIR", dirty) == "none",
          "an unresolvable variable directory is skipped")
    check(verdict("sf project deploy quick --use-most-recent", dirty) == "none",
          "a quick deploy carries no source, so there is nothing to scan")
    check(verdict("sf project retrieve start -d src", dirty) == "none",
          "a RETRIEVE writes into the tree and sends nothing, so it is out of scope")
    check(verdict("sf project convert source --source-dir src", dirty) == "none",
          "convert is not a deploy")
    check(verdict("sfj data query -q \"SELECT Id FROM Account\"", dirty) == "none",
          "an ordinary sf command is untouched")
    check(verdict("git status --porcelain", dirty) == "none",
          "a command that is not a deploy at all")
    check(verdict("echo project deploy start -d src", dirty) == "none",
          "`echo project deploy start` is not running one: the verb needs `sf` before it")
    check(verdict("gh pr create --body 'run sf project deploy start -d src'", dirty) == "deny",
          "KNOWN LIMIT, asserted so it is not a surprise: text QUOTING a deploy command still "
          "matches, same as the User.Email guard, and it can only fire when a backup exists")

    print("\nOut of scope by design")
    check(verdict("sf project deploy start -d src", dirty, tool="Write") == "none",
          "a tool other than Bash/PowerShell is untouched")
    check(verdict("sf project deploy start -d src", dirty, tool="PowerShell") == "deny",
          "PowerShell is covered, since some work runs there")
    apex = make_tree()
    classes = os.path.join(apex, "src", "classes")
    os.makedirs(classes, exist_ok=True)
    for name in ("Probe.cls", "Probe.cls-meta.xml", "Probe.cls.bak"):
        with open(os.path.join(classes, name), "w", encoding="utf-8") as fh:
            fh.write("x\n")
    trees.append(apex)
    check(verdict("sf project deploy start -d src", apex) == "none",
          "a `.cls.bak` is NOT flagged: measured harmless, and flagging it would cry wolf")

    print("\nFails open rather than wedging every deploy")
    done = subprocess.run([sys.executable, GUARD], input="not json at all",
                          capture_output=True, text=True, timeout=60)
    check(done.returncode == 0 and not (done.stdout or "").strip(),
          "unreadable input exits 0 and says nothing",
          "rc={0} out={1}".format(done.returncode, (done.stdout or "")[:120]))

    for path in trees:
        shutil.rmtree(path, ignore_errors=True)

    print("\n{0} checks, {1} failed".format(checks, len(failures)))
    for f in failures:
        print("  - " + f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
