#!/usr/bin/env python3
"""
Self-checks for pretool-guards.py, the plugin's PreToolUse check runner.

WHAT THIS HAS TO PROVE. The runner calls every guard in one process. That is only safe if it
decides EXACTLY what each check would decide on its own, so the load-bearing case is equivalence:
every payload is run through each check standalone as a subprocess and through the runner, and the
two verdicts must agree. A runner that quietly dropped a check would still look healthy at every
call site, because a check that never fires is indistinguishable from a check with nothing to say.

Equivalence alone would be circular, since a wrong precedence rule applied consistently in both
places agrees with itself. So each payload also carries a HARDCODED expected verdict, and the
multi-deny case asserts that every denying check's own reason survives into the combined message.

Two registry checks close the remaining gaps: the runner's GUARDS list has to match the check files
in hooks/guards/ exactly (a new check file that is never listed would never run), and hooks.json
has to register the runner on the anchored union matcher.

No network, no org: every case is a JSON payload on stdin.
"""
import glob
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD_DIR = os.path.join(HERE, "guards")
DISPATCHER = os.path.join(HERE, "pretool-guards.py")
HOOKS_JSON = os.path.join(HERE, "hooks.json")

failures = []
checks = 0


def check(ok, label, detail=""):
    global checks
    checks += 1
    if ok:
        print("  ok   " + label)
    else:
        print("  FAIL " + label + ((" | " + detail) if detail else ""))
        failures.append(label)


def _load_dispatcher():
    spec = importlib.util.spec_from_file_location("dispatcher", DISPATCHER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(script, payload, env):
    proc = subprocess.run([sys.executable, script], input=payload, capture_output=True,
                          text=True, env=env)
    out = (proc.stdout or "").strip()
    if proc.returncode != 0:
        return {"__rc__": proc.returncode, "__stderr__": (proc.stderr or "")[:300]}
    if not out:
        return None
    try:
        return json.loads(out)["hookSpecificOutput"]
    except Exception:
        return {"__unparsed__": out[:300]}


def guard_verdicts(guards, payload, env):
    """What each check, run separately, would have said."""
    return [(g, _run(os.path.join(GUARD_DIR, g), payload, env)) for g in guards]


def summarize(out):
    """Reduce a hookSpecificOutput to a comparable verdict token."""
    if out is None:
        return "none"
    if "__rc__" in out or "__unparsed__" in out:
        return "ERROR:" + json.dumps(out)[:120]
    decision = out.get("permissionDecision")
    if decision in ("allow", "ask") and "updatedInput" in out:
        return decision + "-rewrite:" + (out["updatedInput"].get("command") or "")
    return decision or "none"


def expected_from_guards(verdicts):
    """The precedence the runner is supposed to apply, derived from the checks themselves."""
    if any(o and o.get("permissionDecision") == "deny" for _, o in verdicts):
        return "deny"
    asks = [o for _, o in verdicts if o and o.get("permissionDecision") == "ask"]
    if asks:
        carried = next((o for o in asks if "updatedInput" in o), None)
        if carried is not None:
            return "ask-rewrite:" + (carried["updatedInput"].get("command") or "")
        return "ask"
    for _, o in verdicts:
        if o and o.get("permissionDecision") == "allow" and "updatedInput" in o:
            return "allow-rewrite:" + (o["updatedInput"].get("command") or "")
    return "none"


def payload(tool, tool_input, cwd=None):
    body = {"tool_name": tool, "tool_input": tool_input}
    if cwd:
        body["cwd"] = cwd
    return json.dumps(body)


def _probe(tmp, name, guards_expr, command):
    """Write a script that calls the runner's decide() with a custom guard list."""
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(
            "import importlib.util, json\n"
            "spec = importlib.util.spec_from_file_location('d', r'{0}')\n"
            "d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)\n"
            "pl = json.dumps({{'tool_name': 'Bash', 'tool_input': {{'command': {1}}}}})\n"
            "print(json.dumps(d.decide(pl, guards={2})))\n".format(
                DISPATCHER, repr(command), guards_expr))
    return path


def _stand_in(tmp, name, body):
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("import json\n"
                 "def main():\n"
                 "    print(json.dumps({'hookSpecificOutput': " + body + "}))\n")
    return path


def _decide_with(tmp, name, guards, command, env):
    probe = _probe(tmp, name, "(" + ", ".join("r'{0}'".format(g) for g in guards) + ",)",
                   command)
    proc = subprocess.run([sys.executable, probe], capture_output=True, text=True, env=env)
    got = (proc.stdout or "").strip()
    try:
        return json.loads(got), proc
    except Exception:
        return None, proc


def main() -> int:
    mod = _load_dispatcher()
    guards = tuple(mod.GUARDS)

    print("Registry: GUARDS matches the check files on disk")
    on_disk = sorted(os.path.basename(p)
                     for p in glob.glob(os.path.join(GUARD_DIR, "pretool-*-guard.py")))
    check(bool(on_disk), "found check files under hooks/guards/ (an empty scope is not a clear one)")
    check(sorted(guards) == on_disk, "GUARDS lists exactly the pretool-*-guard.py files on disk",
          "disk={0} registered={1}".format(on_disk, sorted(guards)))
    check(len(guards) == 3, "the plugin carries its three guards", str(len(guards)))
    for g in guards:
        check(os.path.isfile(os.path.join(GUARD_DIR, "test-" + g)),
              "{0} has its own self-check suite beside it".format(g))

    tmp = tempfile.mkdtemp(prefix="pretool-guards-")
    env = dict(os.environ, CLAUDE_PROJECT_DIR=tmp)

    # (label, payload, hardcoded expected verdict)
    cases = [
        ("a clean command says nothing",
         payload("Bash", {"command": "git status --porcelain"}), "none"),
        ("an empty element in a SOQL IN list is denied",
         payload("Bash", {"command":
                          "sf data query -q \"SELECT Id FROM Account WHERE Name IN ('')\""}),
         "deny"),
        ("a read-only sf --json piped to jq is corrected, and still asks",
         payload("Bash", {"command": "sf data query -q \"SELECT Id FROM Account\" --json "
                                     "| jq '.result'"}),
         "ask-rewrite:sfj data query -q \"SELECT Id FROM Account\" | jq '.result'"),
        ("PowerShell $_ trips nothing here",
         payload("PowerShell", {"command":
                                "Get-Process | Where-Object { $_.Name -eq 'python' }"}), "none"),
        ("a file write is outside every guard's scope",
         payload("Write", {"file_path": os.path.join(tmp, "notes.sh"),
                           "content": "echo $NOT_SET_HERE"}, cwd=tmp), "none"),
        ("a tool outside every check's scope says nothing",
         payload("Read", {"file_path": "README.md"}), "none"),
    ]

    print("\nEquivalence: the runner decides what each check decides alone")
    for label, pl, expected in cases:
        from_guards = expected_from_guards(guard_verdicts(guards, pl, env))
        from_dispatcher = summarize(_run(DISPATCHER, pl, env))
        check(from_dispatcher == from_guards, "checks and runner agree: " + label,
              "checks={0} runner={1}".format(from_guards, from_dispatcher))
        check(from_dispatcher == expected, "verdict is the expected one: " + label,
              "expected={0} got={1}".format(expected, from_dispatcher))

    print("\nNo deny is hidden behind another")
    multi = payload("Bash", {"command": "sf project deploy start --json 2>/dev/null | jq . ; "
                                        "echo \"SELECT Id FROM Account WHERE Name IN ('')\""})
    verdicts = guard_verdicts(guards, multi, env)
    denied = [(g, o) for g, o in verdicts if o and o.get("permissionDecision") == "deny"]
    check(len(denied) >= 2, "the payload really does trip more than one check",
          "denied by " + ", ".join(g for g, _ in denied))
    out = _run(DISPATCHER, multi, env)
    check(out is not None and out.get("permissionDecision") == "deny", "the runner denies it")
    combined = (out or {}).get("permissionDecisionReason") or ""
    for g, o in denied:
        own = (o.get("permissionDecisionReason") or "")[:60]
        check(bool(own) and own in combined, "the combined reason still carries " + g,
              "missing: " + own)

    print("\nFail-open: a guard-rail must never wedge every tool call")
    for label, raw in (("unparseable stdin", "not json at all"),
                       ("empty stdin", ""),
                       ("payload with no tool_name", json.dumps({"tool_input": {}})),
                       ("tool_input not an object", json.dumps(
                           {"tool_name": "Bash", "tool_input": "a string"}))):
        proc = subprocess.run([sys.executable, DISPATCHER], input=raw, capture_output=True,
                              text=True, env=env)
        check(proc.returncode == 0 and not (proc.stdout or "").strip(),
              "exits 0 and blocks nothing on " + label,
              "rc={0} out={1}".format(proc.returncode, (proc.stdout or "")[:120]))

    print("\nOne broken check does not take the others down")
    broken = os.path.join(tmp, "broken-guard.py")
    with open(broken, "w", encoding="utf-8") as fh:
        fh.write("raise RuntimeError('this check is broken')\n")
    parsed, proc = _decide_with(tmp, "probe-broken.py",
                                (broken, "pretool-soql-guard.py"),
                                "echo \"SELECT Id FROM Account WHERE Name IN ('')\"", env)
    check(bool(parsed) and parsed.get("permissionDecision") == "deny",
          "a throwing check is skipped and the healthy one still denies",
          "rc={0} out={1} err={2}".format(proc.returncode, (proc.stdout or "")[:160],
                                          (proc.stderr or "")[:160]))

    # Stand-ins prove the precedence for combinations the real guards do not produce together:
    # an auto-correct carries `allow`, which skips the permission prompt, so it must never win
    # over another guard's deny or ask, and an ask that carries a correction keeps it.
    asker = _stand_in(tmp, "always-ask-guard.py",
                      "{'hookEventName': 'PreToolUse', 'permissionDecision': 'ask', "
                      "'permissionDecisionReason': 'stand-in ask'}")
    rewriter = _stand_in(tmp, "always-rewrite-guard.py",
                         "{'hookEventName': 'PreToolUse', 'permissionDecision': 'allow', "
                         "'updatedInput': {'command': 'echo rewritten'}}")

    print("\nPrecedence: deny, then ask, then an auto-correct")
    parsed, _ = _decide_with(tmp, "probe-rewrite.py", (rewriter,), "echo hi", env)
    check(bool(parsed) and parsed.get("permissionDecision") == "allow"
          and "updatedInput" in parsed, "a lone auto-correct is passed through")
    parsed, _ = _decide_with(tmp, "probe-ask.py", (rewriter, asker), "echo hi", env)
    check(bool(parsed) and parsed.get("permissionDecision") == "ask"
          and "updatedInput" not in parsed, "an ask outranks the auto-correct")
    parsed, _ = _decide_with(tmp, "probe-deny.py",
                             (rewriter, asker, "pretool-soql-guard.py"),
                             "echo \"SELECT Id FROM Account WHERE Name IN ('')\"", env)
    check(bool(parsed) and parsed.get("permissionDecision") == "deny"
          and "updatedInput" not in parsed, "a deny outranks both")

    ask_rewriter = _stand_in(tmp, "ask-rewrite-guard.py",
                             "{'hookEventName': 'PreToolUse', 'permissionDecision': 'ask', "
                             "'permissionDecisionReason': 'stand-in ask-rewrite', "
                             "'updatedInput': {'command': 'echo corrected'}}")
    parsed, _ = _decide_with(tmp, "probe-ask-rewrite.py", (rewriter, ask_rewriter), "echo hi", env)
    check(bool(parsed) and parsed.get("permissionDecision") == "ask"
          and (parsed.get("updatedInput") or {}).get("command") == "echo corrected",
          "an ask carrying a correction keeps it and outranks an auto-correct")

    print("\nRegistration: hooks.json wires the runner on the anchored matcher")
    with open(HOOKS_JSON, encoding="utf-8") as fh:
        hooks = json.load(fh)
    pre = hooks.get("hooks", {}).get("PreToolUse") or []
    wired = [" ".join([h.get("command") or ""] + list(h.get("args") or []))
             for entry in pre for h in entry.get("hooks", [])]
    check(any("/hooks/pretool-guards.py" in a for a in wired),
          "the runner is registered as a PreToolUse hook")
    stale = [a for a in wired for g in guards if g in a]
    check(not stale, "no individual check is registered on its own",
          "still wired: " + ", ".join(stale))
    union = next((e.get("matcher", "") for e in pre if "Bash" in e.get("matcher", "")), "")
    for name, want in (("Bash", True), ("PowerShell", True), ("Write", False), ("Edit", False),
                       ("NotebookEdit", False), ("Read", False), ("BashOutput", False),
                       ("mcp__ccd_turn__wrap_up", False)):
        got = bool(union) and re.search(union, name) is not None
        check(got == want, "the matcher {0} {1}".format("reaches" if want else "skips", name),
              "matcher: " + union)

    print("\n{0} checks, {1} failed".format(checks, len(failures)))
    for f in failures:
        print("  - " + f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
