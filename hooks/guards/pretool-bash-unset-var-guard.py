#!/usr/bin/env python3
"""
PreToolUse guard — stops a Bash command from silently reading a variable that was set in a
DIFFERENT tool call.

Why the shape is dangerous: each Bash tool call gets a FRESH shell. The working directory
persists, but shell state does not, so `MB=679e1be` in one call leaves `$MB` **empty** in the
next. Bash expands an unset variable to the empty string without complaint, so the command still
runs and still exits 0 — it just runs a different command than the one that was written.

That produced a confidently wrong answer on 2026-08-01: `git diff $MB..$B -- CLAUDE.md` with both
variables unset collapsed to `git diff .. -- CLAUDE.md`, printed nothing, exited 0, and was read
as "the branch changed nothing". The file had in fact changed, which `git rev-parse <ref>:<path>`
blob hashes disproved a few minutes later. An empty diff and "no differences" are indistinguishable
at the shell, which is what makes this worth a guard rather than a habit.

What this hook does: DENY, with the fix in the message. It deliberately does NOT rewrite the
command. A PreToolUse `updatedInput` is only honored alongside `permissionDecision: allow`, which
bypasses the permission prompt (see the note on pretool-sf-json-stderr-guard.py, which is why THAT
guard only auto-corrects read-only `sf` reads). Prepending `set -u` would be the tidier fix, but
applying it by rewrite would auto-approve every command containing a variable, `rm` and
`sf project deploy` included. A deny costs one round trip and grants nothing.

How a variable is judged UNSAFE — all three must hold:
  1. It is referenced as `$NAME` or `${NAME}` where bash expands it: not inside single quotes,
     `$'...'`, a comment, or a quoted heredoc, and not after a backslash (none of those expand,
     so none can be a source of this bug).
  2. It is not assigned anywhere in the SAME command string — covering `NAME=`, `export NAME=`,
     `local/declare/typeset/readonly NAME=`, `for NAME in`, every name in `read A B C`, and
     `NAME+=`.
  3. It is not a real environment variable (checked against this process's own `os.environ`, so
     the list maintains itself) and not a shell builtin/positional/special parameter.

Deliberately NOT flagged, because each is either safe or not this bug:
  * `${NAME:-default}`, `${NAME:=}`, `${NAME:+x}`, `${NAME-}` — the default makes unset harmless,
    and this is the correct way to write an intentionally-optional variable.
  * `$1`, `$@`, `$?`, `$$`, `$#`, `$!`, `$0`, `$-`, `$_` — positional and special parameters.
  * `$(...)`, `$((...))` — command and arithmetic substitution.
  * PowerShell — `$var` there is a different language with different scoping; this guard skips it.

Quoting is tracked in one left-to-right pass that follows bash's own rules, because what a quote
character means depends on the context it sits in. A `'` inside "..." is a literal apostrophe, a
`"` inside '...' is a literal character, both are literal in a comment and in an unquoted heredoc
body, and `$(...)`, backticks, and `${...}` each start quoting afresh. The first version paired
quotes with a bare '[^']*' regex, and on 2026-09-23 that blocked
`jq --arg s "...the team's..." '...summary:$s}'`: the apostrophe was paired with the jq program's
opening quote, so the program was scanned as unquoted shell and its jq variable `$s` read as an
unset shell variable. The same pairing also HID real expansions, such as the `$ACCT` in
`"Name = '$ACCT'"`, which bash expands and which collapses to `''` when unset.

Scope + limits: scans LITERAL command text, so it cannot see a name built by indirect expansion
(`${!ref}`) or assembled at runtime — a deliberate fail-open. The quote tracking does not model
`case` patterns, so a pattern's unmatched `)` inside `$(...)` ends the substitution early, and it
reads every `'` inside "${...}" as literal, which is right for `${x:-'a'}` and wrong for the
pattern operators (`${x#'a'}`). Fail-OPEN on any internal error too, because a guard bug must
never wedge every shell command.

Run by hooks/pretool-guards.py, which hooks/hooks.json registers on PreToolUse.
Self-checks: hooks/guards/test-pretool-bash-unset-var-guard.py
"""

import json
import os
import re
import sys

# A variable reference we care about: $NAME or ${NAME}, but NOT ${NAME:-...} / ${NAME-...} etc.
# (a default makes an unset variable harmless and is the recommended fix), and not $(...) or $((...)).
_BRACED = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_BARE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")

# Assignment forms that make a name safe within the same command.
_ASSIGNED = (
    re.compile(r"(?:^|[;&|(\s])([A-Za-z_][A-Za-z0-9_]*)\+?=", re.MULTILINE),
    re.compile(r"\b(?:export|local|declare|typeset|readonly)\s+([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b"),
)

# `read` assigns EVERY name it is given, so `while read -r O R` sets both. Crediting only the
# first went unnoticed while the quote pairing happened to hide the usual later reference, the
# `'$R'` inside a double-quoted SOQL string. The group is the rest of the simple command.
_READ = re.compile(r"\bread\s+([^;&|<>()\n]*)")
_READ_OPTS_WITH_ARG = "adinNptu"  # -a NAME, -d DELIM, -p PROMPT, -t SECS, -u FD, ...
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Shell parameters that are always defined. Positionals and specials are handled by the regexes
# above (they are not [A-Za-z_] names), so this is just the well-known always-present names.
_ALWAYS_DEFINED = {
    "IFS", "PWD", "OLDPWD", "SHELL", "PATH", "HOME", "USER", "LOGNAME", "HOSTNAME",
    "PS1", "PS2", "PS4", "BASH", "BASH_VERSION", "BASH_SOURCE", "FUNCNAME", "LINENO",
    "RANDOM", "SECONDS", "UID", "EUID", "PPID", "TMPDIR", "TEMP", "TMP", "LANG", "TZ",
    "REPLY", "OSTYPE", "MACHTYPE", "HOSTTYPE", "COLUMNS", "LINES", "TERM",
}


# A `#` starts a comment only at the beginning of a word, which is after one of these.
_WORD_BREAK = " \t\n;&|()<>"
_NOT_NEWLINE = re.compile(r"[^\n]")
# The characters that can change what comes next, per context. Everything else is skipped in one
# jump, which keeps a long heredoc body cheap to scan.
_SHELL_SPECIAL = re.compile(r"[\\'\"$`#<\n()]")
_DQ_SPECIAL = re.compile(r"[\\\"$`]")
_PARAM_SPECIAL = re.compile(r"[\\'\"$`{}]")
_HEREDOC_SPECIAL = re.compile(r"[\\$`]")
_ANSI_C_SPECIAL = re.compile(r"[\\']")
_BACKTICK_SPECIAL = re.compile(r"[\\`]")


class _Unexpanded:
    """One left-to-right pass over a command that blanks every span bash does not expand.

    Each method scans one quoting context and returns the index where that context ends, so a
    construct opened inside another (a "..." inside $(...) inside "...") is scanned by its own
    rules and hands control back when it closes.
    """

    def __init__(self, command: str):
        self.s = command
        self.out = list(command)
        self.comments = []  # where each comment starts, so a `read` knows where its words end
        # Heredocs opened on the current line, whose bodies start at the next newline:
        # (delimiter, strip_tabs, quoted, opened_inside_a_substitution)
        self.pending = []

    def text(self) -> str:
        self.shell(0, len(self.s))
        return "".join(self.out)

    def blank(self, a: int, b: int) -> None:
        if a < b:
            self.out[a:b] = _NOT_NEWLINE.sub(" ", self.s[a:b])

    def single_quoted(self, i: int, end: int) -> int:
        """At an opening `'`: nothing is special until the next `'`, a backslash included."""
        close = self.s.find("'", i + 1, end)
        stop = end if close < 0 else close + 1
        self.blank(i, stop)
        return stop

    def shell(self, i: int, end: int, closer: bool = False, arith: bool = False) -> int:
        """Command-level text: the whole command, or the inside of $(...), `...`, or $((...)).
        With `closer`, parentheses are counted and the scan returns just past the `)` that closes
        the substitution. `arith` turns off comments and heredocs, since `<<` is a shift there."""
        s = self.s
        start, depth, glued = i, 0, -1
        while i < end:
            m = _SHELL_SPECIAL.search(s, i, end)
            if not m:
                return end
            i = m.start()
            c = s[i]
            # `glued` is where a quote, escape, or expansion just ended: a `#` there is still
            # inside that word ('x'#y is the one word x#y), so it cannot start a comment.
            word_start = i == start or (i != glued and s[i - 1] in _WORD_BREAK)
            if c == "\\":
                self.blank(i, min(i + 2, end))
                i = glued = i + 2
            elif c == "'":
                i = glued = self.single_quoted(i, end)
            elif c == '"':
                i = glued = self.double_quoted(i + 1, end)
            elif c == "$":
                i = glued = self.dollar(i, end, quoted=False)
            elif c == "`":
                i = glued = self.backtick(i, end)
            elif c == "#":
                if word_start and not arith:
                    nl = s.find("\n", i, end)
                    stop = end if nl < 0 else nl
                    self.comments.append(i)
                    self.blank(i, stop)
                    i = stop
                else:
                    i += 1
            elif c == "<":
                if arith or not s.startswith("<<", i):
                    i += 1
                elif s.startswith("<<<", i):
                    i += 3  # a here-string, whose word is scanned like any other
                else:
                    i = self.heredoc_operator(i, end, in_substitution=closer)
            elif c == "\n":
                i = self.heredoc_bodies(i + 1, end) if self.pending else i + 1
            elif c == "(":
                if word_start and not arith and s.startswith("((", i):
                    i = self.shell(i + 1, end, closer=True, arith=True)  # (( arithmetic ))
                else:
                    depth += 1
                    i += 1
            else:  # ")"
                if closer and depth == 0:
                    return i + 1
                depth = max(depth - 1, 0)
                i += 1
        return end

    def double_quoted(self, i: int, end: int) -> int:
        """Just inside an opening `"`. Only a backslash, `$`, a backtick, and the closing quote are
        special here, so a `'` is a literal apostrophe and opens nothing."""
        s = self.s
        while i < end:
            m = _DQ_SPECIAL.search(s, i, end)
            if not m:
                return end
            i = m.start()
            c = s[i]
            if c == '"':
                return i + 1
            if c == "\\":
                if i + 1 < end and s[i + 1] in '$`"\\\n':
                    self.blank(i, i + 2)
                i += 2
            elif c == "$":
                i = self.dollar(i, end, quoted=True)
            else:
                i = self.backtick(i, end)
        return end

    def dollar(self, i: int, end: int, quoted: bool) -> int:
        """At a `$`: scans the construct it opens, if any, and returns where to resume. `quoted`
        means inside "...", a heredoc body, or a ${...} within "...", where $'...' is not
        ANSI-C quoting but a literal `$` followed by a literal `'`."""
        s = self.s
        nxt = s[i + 1] if i + 1 < end else ""
        if nxt == "(":
            return self.shell(i + 2, end, closer=True, arith=s.startswith("$((", i))
        if nxt == "{":
            return self.param(i + 2, end, in_dq=quoted)
        if nxt == "'" and not quoted:
            # ANSI-C quoting: nothing expands, and a backslash escapes the next character, so
            # $'it\'s' is one string and not a string followed by a stray quote.
            j = i + 2
            while True:
                m = _ANSI_C_SPECIAL.search(s, j, end)
                if not m:
                    j = end
                    break
                if s[m.start()] == "'":
                    j = m.start() + 1
                    break
                j = m.start() + 2
            stop = min(j, end)
            self.blank(i, stop)
            return stop
        return i + 1

    def param(self, i: int, end: int, in_dq: bool) -> int:
        """Just inside `${`, up to the `}` that closes it. Nested braces count, and a `"` opens a
        nested double-quoted string. A `'` is a quote at command level but literal within "...",
        which is how bash reads "${x:-'a'}": it prints 'a', quotes and all."""
        s = self.s
        depth = 0
        while i < end:
            m = _PARAM_SPECIAL.search(s, i, end)
            if not m:
                return end
            i = m.start()
            c = s[i]
            if c == "\\":
                self.blank(i, min(i + 2, end))
                i += 2
            elif c == "'":
                i = i + 1 if in_dq else self.single_quoted(i, end)
            elif c == '"':
                i = self.double_quoted(i + 1, end)
            elif c == "$":
                i = self.dollar(i, end, quoted=in_dq)
            elif c == "`":
                i = self.backtick(i, end)
            elif c == "{":
                depth += 1
                i += 1
            else:  # "}"
                if depth == 0:
                    return i + 1
                depth -= 1
                i += 1
        return end

    def backtick(self, i: int, end: int) -> int:
        """At an opening backtick. Bash finds the closing one first, skipping only
        backslash-escaped characters, and then reads what lies between as a command."""
        s = self.s
        j = i + 1
        while True:
            m = _BACKTICK_SPECIAL.search(s, j, end)
            if not m:
                close = end
                break
            if s[m.start()] == "`":
                close = m.start()
                break
            j = m.start() + 2
        self.shell(i + 1, close)
        return min(close + 1, end)

    def heredoc_operator(self, i: int, end: int, in_substitution: bool) -> int:
        """At `<<` or `<<-`. Reads the delimiter word and queues the body, which bash reads from
        the NEXT newline on. Quoting any part of the word makes the whole body literal."""
        s = self.s
        j = i + 2
        strip_tabs = j < end and s[j] == "-"
        if strip_tabs:
            j += 1
        while j < end and s[j] in " \t":
            j += 1
        start, word, quoted = j, [], False
        while j < end and s[j] not in _WORD_BREAK:
            c = s[j]
            if c == "\\":
                quoted = True
                word.append(s[j + 1:j + 2])
                j += 2
            elif c in "'\"":
                quoted = True
                close = s.find(c, j + 1, end)
                close = end if close < 0 else close
                word.append(s[j + 1:close])
                j = close + 1
            else:
                word.append(c)
                j += 1
        j = min(j, end)
        if j > start:
            self.pending.append(("".join(word), strip_tabs, quoted, in_substitution))
            self.blank(start, j)  # the delimiter itself is never expanded
        return j

    def heredoc_bodies(self, i: int, end: int) -> int:
        """Just past the newline that ends a line with heredocs queued on it. Consumes each body
        in order and returns the index just past the last delimiter line."""
        s = self.s
        while self.pending:
            delim, strip_tabs, quoted, in_substitution = self.pending.pop(0)
            body_start = j = i
            body_end = resume = end  # never terminated: bash reads to the end, and so does this
            while j < end:
                nl = s.find("\n", j, end)
                line_end = end if nl < 0 else nl
                line = s[j:line_end]
                lead = len(line) - len(line.lstrip("\t")) if strip_tabs else 0
                if line[lead:] == delim:
                    body_end, resume = j, line_end if nl < 0 else nl + 1
                    break
                if in_substitution and line.startswith(delim + ")", lead):
                    # $(cat <<EOF ... EOF): bash ends the body at the `)` that closes the
                    # substitution (with a warning), and that `)` still closes it.
                    body_end, resume = j, j + lead + len(delim)
                    break
                j = end if nl < 0 else nl + 1
            if quoted:
                self.blank(body_start, body_end)
            else:
                self.heredoc_body(body_start, body_end)
            i = resume
        return i

    def heredoc_body(self, i: int, end: int) -> None:
        """An unquoted heredoc body. `$` and backticks expand and a backslash escapes only `$`, a
        backtick, a backslash, and a newline. Quotes are ordinary characters, so an apostrophe
        here opens nothing."""
        s = self.s
        while i < end:
            m = _HEREDOC_SPECIAL.search(s, i, end)
            if not m:
                return
            i = m.start()
            c = s[i]
            if c == "\\":
                if i + 1 < end and s[i + 1] in "$`\\\n":
                    self.blank(i, i + 2)
                i += 2
            elif c == "$":
                i = self.dollar(i, end, quoted=True)
            else:
                i = self.backtick(i, end)


def _scan(command: str):
    """The command with every span bash does not expand blanked out (single-quoted and $'...'
    strings, backslash escapes, comments, and the bodies of heredocs whose delimiter is quoted:
    <<'EOF' / <<"EOF" / <<\\EOF), plus where each comment starts. Blanks with spaces to preserve
    offsets, and keeps newlines."""
    scanner = _Unexpanded(command)
    return scanner.text(), scanner.comments


def _strip_unexpanded(command: str) -> str:
    """Blank out every span bash does not expand, so a `$VAR` inside one cannot trip the guard."""
    return _scan(command)[0]


def _read_names(command: str, scanned: str, comments: list) -> set:
    """Every name a `read` in the command assigns. Only a `read` bash actually runs counts, so one
    inside a comment, a quoted string, or a quoted heredoc is skipped, and a comment on the same
    line ends the list: `# read MB later` credits nothing."""
    names = set()
    for m in _READ.finditer(command):
        if scanned[m.start()] != "r":
            continue
        stop = min([c for c in comments if c > m.start()] + [m.end()])
        words = command[m.start(1):max(stop, m.start(1))].split()
        i = 0
        while i < len(words):
            word = words[i]
            if word.startswith("-") and len(word) > 1:
                if word[-1] in _READ_OPTS_WITH_ARG and i + 1 < len(words):
                    if word[-1] == "a":
                        names.add(words[i + 1])  # `read -a NAME` fills the array NAME
                    i += 2
                else:
                    i += 1
                continue
            if _NAME.fullmatch(word):
                names.add(word)
            i += 1
    return names


def assigned_names(command: str, scanned: str = None, comments: list = None) -> set:
    if scanned is None:
        scanned, comments = _scan(command)
    names = set()
    for pat in _ASSIGNED:
        names.update(pat.findall(command))
    names.update(_read_names(command, scanned, comments))
    return names


def referenced_names(command: str, scanned: str = None) -> list:
    """Names referenced as $NAME / ${NAME} in expanding context, in order, deduped."""
    if scanned is None:
        scanned = _strip_unexpanded(command)
    seen, out = set(), []
    for m in list(_BRACED.finditer(scanned)) + list(_BARE.finditer(scanned)):
        n = m.group(1)
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def unsafe_names(command: str) -> list:
    """Referenced but neither assigned in this command nor present in the environment."""
    scanned, comments = _scan(command)
    assigned = assigned_names(command, scanned, comments)
    env = set(os.environ)
    return [n for n in referenced_names(command, scanned)
            if n not in assigned and n not in env and n not in _ALWAYS_DEFINED]


_WHY = (
    "Each Bash tool call gets a FRESH shell: the working directory persists but shell state does "
    "not, so a variable set in an earlier call is EMPTY here. Bash expands an unset variable to "
    "the empty string silently and still exits 0, so the command runs a different command than "
    "the one written. On 2026-08-01 `git diff $MB..$B -- CLAUDE.md` collapsed to `git diff .. -- "
    "CLAUDE.md`, printed nothing, exited 0, and was read as 'nothing changed' when the file had "
    "in fact changed. Fix it one of three ways: assign the variable in THIS command "
    "(`MB=679e1be; git diff \"$MB\"..`), use the literal value, or write `${NAME:-}` if it is "
    "genuinely optional. Adding `set -u` to the command also turns this into a loud error."
)


def _emit(decision: str, reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }}))


def main() -> int:
    try:
        data = json.loads(sys.stdin.read() or "{}")
    except Exception:
        return 0  # fail-open: can't parse input, don't block

    try:
        # Bash only. PowerShell's $var is a different language with different scoping.
        if data.get("tool_name") != "Bash":
            return 0
        command = (data.get("tool_input") or {}).get("command") or ""
        if not isinstance(command, str) or "$" not in command:
            return 0

        bad = unsafe_names(command)
        if not bad:
            return 0

        names = ", ".join("$" + n for n in bad[:6]) + ("..." if len(bad) > 6 else "")
        _emit("deny", f"Blocked: {names} is referenced but never set in this command. " + _WHY)
        return 0
    except Exception:
        return 0  # fail-open


if __name__ == "__main__":
    sys.exit(main())
