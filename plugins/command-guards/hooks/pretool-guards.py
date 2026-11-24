#!/usr/bin/env python3
"""
PreToolUse check RUNNER: runs every guard in hooks/guards/ inside ONE python process.

WHY ONE PROCESS. On Windows the Claude desktop app is a GUI process, so every console child a hook
starts can flash a console window, and a python interpreter start costs tens of milliseconds where
importing an already-written module costs a few. So this runner is registered once, in
hooks/hooks.json, and calls every guard in-process. On one Windows machine, five separate hook
entries measured 694 ms per tool call against 170 ms for one runner.

WHY THE GUARDS ARE NOT REFACTORED. Each guard has its own self-check suite that drives it as a
SUBPROCESS on stdin, and each can also be wired on its own as a hook. So this runner drives each
one's existing `main()` with `sys.stdin` and `sys.stdout` redirected and reads back the JSON it
printed. Nothing about any guard's decision logic moves.

EACH GUARD STILL FILTERS ITSELF. Every guard's `main()` checks `tool_name` first and returns
silently on a tool it does not cover: the unset-variable and grep-abort guards take `Bash` alone,
and the stacked pull request guard takes `Bash` and `PowerShell`. hooks.json registers this
runner on exactly those two tools.

EVERY GUARD SEES THE ORIGINAL INPUT, never a rewritten one.

PRECEDENCE. Every applicable guard runs, then:
  1. any `deny` wins, and if more than one guard denied, all their reasons are reported
     together so a second problem is not hidden behind the first;
  2. otherwise any `ask` wins, with every asking guard's reason reported together, carrying the
     first asking guard's `updatedInput` if it has one (a correction that still prompts);
  3. otherwise an `allow` + `updatedInput` auto-correct is passed through;
  4. otherwise nothing is printed, which is how a hook says "no opinion".
No guard in this plugin asks or rewrites. The precedence matches salesforce-command-guards, whose
sf JSON guard asks with a correction, so a guard added here later is ranked the same way.

FAIL-OPEN, TWICE OVER. A guard that throws is skipped and the others still run; if the runner
itself throws, it prints nothing and exits 0. A guard-rail that wedges every tool call in the
session gets switched off, which would cost every one of them.

Self-checks: hooks/test-pretool-guards.py, which also fails when GUARDS and the guard files in
hooks/guards/ disagree.
"""
import contextlib
import importlib.util
import io
import json
import os
import sys

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guards")

# Order decides which reason leads when more than one guard denies.
GUARDS = (
    "pretool-bash-unset-var-guard.py",
    "pretool-grep-abort-guard.py",
    "pretool-stacked-pr-merge-guard.py",
)


def _load(filename: str):
    """Import a guard by path. The filenames are hyphenated, so a plain `import` cannot reach
    them. Importing does not run `main()`: every guard is behind `if __name__ == "__main__"`."""
    path = os.path.join(HERE, filename)
    mod_name = "guard_" + filename[:-3].replace("-", "_")
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load guard: " + path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_guard(filename: str, payload_text: str):
    """Drive one guard's own main() and return the hookSpecificOutput it printed, or None.

    stdin is a fresh StringIO per guard, since reading it consumes the stream. stdout is
    captured so the guard's JSON is a value here rather than something already on its way to
    the harness.
    """
    mod = _load(filename)
    buf = io.StringIO()
    real_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO(payload_text)
        with contextlib.redirect_stdout(buf):
            mod.main()
    finally:
        sys.stdin = real_stdin

    printed = buf.getvalue().strip()
    if not printed:
        return None
    parsed = json.loads(printed)
    if not isinstance(parsed, dict):
        return None
    out = parsed.get("hookSpecificOutput")
    return out if isinstance(out, dict) else None


def decide(payload_text: str, guards=GUARDS):
    """Run every guard over the ORIGINAL payload and return one hookSpecificOutput, or None."""
    denies = []
    asks = []
    ask_rewrite = None
    rewrite = None

    for filename in guards:
        try:
            out = run_guard(filename, payload_text)
        except Exception:
            # One broken guard must not take the others down with it. Skipping it is the
            # same fail-open each guard already applies to itself.
            continue
        if not out:
            continue
        decision = out.get("permissionDecision")
        if decision == "deny":
            reason = out.get("permissionDecisionReason") or "(no reason given)"
            denies.append(reason)
        elif decision == "ask":
            asks.append(out.get("permissionDecisionReason") or "(no reason given)")
            if ask_rewrite is None and "updatedInput" in out:
                ask_rewrite = out["updatedInput"]
        elif decision == "allow" and "updatedInput" in out and rewrite is None:
            rewrite = out

    if denies:
        if len(denies) == 1:
            reason = denies[0]
        else:
            numbered = "\n\n".join(
                "({0}) {1}".format(i, r) for i, r in enumerate(denies, 1))
            reason = ("Blocked by {0} guards, all of which have to be satisfied "
                      "before this runs:\n\n{1}").format(len(denies), numbered)
        return {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }

    if asks:
        result = {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": "\n\n".join(asks),
        }
        if ask_rewrite is not None:
            result["updatedInput"] = ask_rewrite
        return result

    return rewrite


def main() -> int:
    try:
        payload_text = sys.stdin.read() or "{}"
    except Exception:
        return 0  # fail-open: cannot read the payload, do not block
    try:
        out = decide(payload_text)
    except Exception:
        return 0  # fail-open: a dispatcher bug must not wedge every tool call
    if out:
        print(json.dumps({"hookSpecificOutput": out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
