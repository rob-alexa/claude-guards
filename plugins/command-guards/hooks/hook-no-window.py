#!/usr/bin/env python
"""Run a hook command without letting Windows flash a console window.

Claude Code spawns hook processes without CREATE_NO_WINDOW, so on Windows a
console-subsystem child (cmd.exe, bash.exe, python.exe) is given a console
window that stays up for as long as the hook runs and TAKES KEYBOARD FOCUS.
At SessionStart that lands exactly while somebody is typing their first prompt.
Anthropic issue #14828 is open, labeled bug/platform:windows, with no fix.

Two halves make this work, and each is load-bearing:

  * pythonw.exe is a GUI-subsystem binary, so Windows allocates no console for
    it at all. python.exe would get one and defeat the entire point, so this
    script is only worth invoking as `pythonw`.
  * the real command is spawned with CREATE_NO_WINDOW, so it gets none either.

Usage from a hooks entry, structured form only:

    "command": "pythonw",
    "args": ["${CLAUDE_PLUGIN_ROOT}/hooks/hook-no-window.py", "--",
             "bash", "${CLAUDE_PLUGIN_ROOT}/hooks/some-hook.sh"]

Use the STRUCTURED command+args form, never a single command string. A command
string has to be parsed by a shell, so Claude Code starts one, and the shell's
console window is the one that flashes -- before this script even starts.

Two behaviors are deliberate:

  * stdio is INHERITED, never relayed. Hooks read a JSON payload on stdin and
    answer on stdout, and relaying means reading stdin to EOF, which deadlocks
    on a hook the parent writes nothing to. Inheriting hands the child the same
    pipes, and this process never touches them.
  * the child's exit code is propagated VERBATIM. A PreToolUse guard blocks a
    tool call with exit 2, so swallowing that code would silently disarm every
    check in hooks/pretool-guards.py. When the child cannot be launched
    at all this exits 1 rather than 0, failing closed for a PreToolUse hook.
"""

import os
import subprocess
import sys

CREATE_NO_WINDOW = 0x08000000


def warn(message):
    """Best-effort stderr note. Under pythonw the stream can be absent, and a
    launcher must never fail because it could not report something."""
    stream = sys.stderr
    if stream is None:
        return
    try:
        stream.write(message)
        stream.flush()
    except Exception:
        pass


def main(argv):
    if "--" in argv:
        command = argv[argv.index("--") + 1:]
    else:
        command = argv
    if not command:
        warn("hook-no-window: no command given\n")
        return 1

    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = CREATE_NO_WINDOW

    # Hand the child our own std handles EXPLICITLY, by descriptor. Leaving them
    # unset is the trap: subprocess defaults to close_fds=True, which calls
    # CreateProcess with bInheritHandles=False, and a child that also has no
    # console (because of CREATE_NO_WINDOW) is then left with invalid std
    # handles -- so everything it prints is discarded and the hook looks like it
    # ran and said nothing. Naming the descriptors makes subprocess duplicate
    # them into the child instead. A descriptor can genuinely be absent under
    # pythonw, so probe each one and only pass the ones that exist.
    for name, fd in (("stdin", 0), ("stdout", 1), ("stderr", 2)):
        try:
            os.fstat(fd)
        except OSError:
            continue
        kwargs[name] = fd

    try:
        return subprocess.call(command, **kwargs)
    except OSError as exc:
        warn("hook-no-window: cannot run {0}: {1}\n".format(command[0], exc))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
