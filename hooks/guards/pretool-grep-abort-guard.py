#!/usr/bin/env python3
"""
PreToolUse guard -- refuse a git-bash grep that GNU grep 3.0 ABORTS on, because the abort reads as
"nothing matched".

THE TRAP. GNU grep 3.0, the copy Git for Windows ships, dies with SIGABRT (exit 134, no output, no
message) whenever it has to fold case through its fixed-string matcher under the C locale. The C
locale is what a Claude Code Bash command gets here, because LANG, LC_ALL, and LC_CTYPE are all
unset. (`locale` prints C.UTF-8 in that state, which is misleading: grep behaves as C, and `grep -P`
says this locale is neither unibyte nor UTF-8.) It aborts before reading input, so nothing is
printed. In the middle of a pipeline the later stages simply see no input, and under `if grep -q`
the test is just false, so a crash is indistinguishable from "no matches". That is how
one audit script printed an empty list of outside accounts on every Windows run while its count
of them was right, until the filter moved into jq.

TWO SHAPES REACH IT, measured 2026-09-25 against that grep:

  * -i together with -F, in every spelling: -iF, -Fi, -i -F, -viF, -qiF, -y (the old synonym for
    -i), --ignore-case, --fixed-strings, --fixed-regexp, an unambiguous prefix of any of those
    (--ign, --fixed), fgrep -i, zfgrep -i, and -X fgrep. The pattern does not matter: an empty
    one, digits only, non-ASCII, and -w or -x all abort the same way.
  * -i with TWO OR MORE patterns that are all plain strings: -e A -e B, --regexp twice, -f FILE
    holding two or more lines, or a pattern containing a newline. Given several literal patterns
    grep 3.0 switches to its -F matcher on its own, as a speed-up, so this is the same abort
    reached without typing -F. It needs EVERY pattern to be literal as grep judges it: one real
    regex among them (a `.`, `*`, `[`, `^`, `$`, a backslash class such as \\w or \\<, or in -E an
    alternation, `+`, `?`, or an interval) keeps grep on its regex matcher, and that works. Each
    rule in _is_literal was checked against the binary; `a\\.b`, `a+b` in a basic regex, and
    `a)b` all count as literal and abort.

WHAT THIS DOES: deny, with the fix in the message. The fix is the same command with LC_ALL=C.UTF-8
in front of that grep (measured: C.UTF-8, C.utf8, en_US.UTF-8, and LANG= or LC_CTYPE= alone all
work), or the Grep tool, which is ripgrep. It deliberately does not rewrite the command. pretool-guards.py
passes through only one rewrite, so a pipeline this guard and the sfj guard both wanted to change
would still abort. A deny costs one round trip and grants nothing. It came up 23 times across 84,967 distinct past Bash commands in the local
transcripts, every one a real abort and 17 of them the multi-pattern shape (replayed 2026-09-25).

WHY NOT EXPORT A UTF-8 LOCALE FOR EVERY COMMAND INSTEAD. It would fix the abort everywhere the Bash
tool reaches, and it was the close runner-up. Measured the same day, a UTF-8 locale also changes
what every other command in the session does: grep prints "Binary file X matches" IN PLACE OF the
matching lines for any file holding a byte that is not valid UTF-8 (which Windows PowerShell 5.1's
Set-Content writes by default), bash's ${#var} and awk's length() count characters instead of
bytes, and sed's `.` stops matching such a byte. ASCII sort order does NOT change (C and C.UTF-8
sort identically here), so a sort pinned to LC_ALL=C was never the risk. That trades one silent failure for
several quieter ones, and this guard leaves every command it does not block exactly as it was.

WHAT IT READS. The command text, parsed as bash: quotes, escapes, $'...', $(...), backticks,
process substitution, heredocs, comments, and the wrappers a grep hides behind (command, env, exec,
nice, nohup, stdbuf, time, timeout, xargs, find -exec, bash -c, and a heredoc or here-string fed to
bash or sh). It also reads a script the command runs directly (bash f.sh, sh f.sh, source f.sh,
. f.sh, ./f.sh) and a readable -f pattern file, because a tracked script is where the
first real case lived and a worktree session often has to keep its commands in a
file. It tracks LC_ALL, LC_CTYPE, and LANG the way bash passes them on: a prefix on the grep or on
any wrapper around it counts, `export` counts from that point on, and a bare `LC_ALL=C.UTF-8`
statement does NOT count, since it never reaches a child process unless the name was already
exported (measured: still exit 134). This process's own environment stands in for the Bash tool's,
so a machine that already runs a UTF-8 locale is never blocked.

WHAT PASSES, because a guard that cries wolf gets switched off: -i or -F alone; -i with one
pattern, however it is spelled; -i with several patterns when any one is a real regex; a pattern
held in a variable (it could hold a newline, but blocking every `grep -i "$x"` would block a shape
sessions use all day); conflicting matchers and -P, which grep refuses loudly with a message; git
grep and rg, which are other programs; and any grep inside quotes, a comment, or a quoted heredoc,
such as a commit message or a doc describing this trap.

LIMITS. It cannot see a grep in a script it does not follow (one script running another, a python
subprocess), options held in a variable, or a pattern file that does not exist yet; an unreadable
-f FILE is treated as holding several literal lines, since that is what -f is usually for. On
Linux, where grep does not abort, it all but stands down: with no locale set, Python coerces the C
locale (PEP 538) and puts LC_CTYPE=C.UTF-8 into this process's environment, which reads as a
UTF-8 locale. That is the right answer there, and it is why the self-check sets
PYTHONCOERCECLOCALE=0. PowerShell is out of scope. Fail-open on any internal error, like every
guard here.

Self-checks: hooks/guards/test-pretool-grep-abort-guard.py
"""
import json
import os
import re
import sys

# Stands in for text an expansion produces, which cannot be known before the command runs.
_DYN = "\x00"

# Every grep front end Git for Windows ships, and the matcher its name implies.
GREP_FAMILY = {
    "grep": None, "zgrep": None, "bzgrep": None,
    "egrep": "E", "zegrep": "E", "bzegrep": "E",
    "fgrep": "F", "zfgrep": "F", "bzfgrep": "F",
}

# In the order the C library consults them: the first one set to a non-empty value wins.
LOCALE_NAMES = ("LC_ALL", "LC_CTYPE", "LANG")
_UTF8 = re.compile(r"utf-?8", re.IGNORECASE)

_MAX_FILE = 1024 * 1024
_MAX_DEPTH = 4
_SHEBANG = re.compile(r"#![^\n]*\b(?:ba|da|z|k)?sh\b")

# --- grep 3.0's own option table (src/grep.c), which is what decides how a word is read --------
_SHORT_WITH_ARG = set("ABCDXdefm")
_SHORT_FLAGS = set("0123456789EFGHILPTUVZabchilnoqrsuvwxyz")
_LONG = {  # name: (has_arg: 0 none, 1 required, 2 optional, identity)
    "basic-regexp": (0, "G"), "extended-regexp": (0, "E"), "fixed-regexp": (0, "F"),
    "fixed-strings": (0, "F"), "perl-regexp": (0, "P"),
    "after-context": (1, "A"), "before-context": (1, "B"), "binary-files": (1, "binary-files"),
    "byte-offset": (0, "b"), "context": (1, "C"), "color": (2, "color"), "colour": (2, "color"),
    "count": (0, "c"), "devices": (1, "D"), "directories": (1, "d"), "exclude": (1, "exclude"),
    "exclude-from": (1, "exclude-from"), "exclude-dir": (1, "exclude-dir"), "file": (1, "f"),
    "files-with-matches": (0, "l"), "files-without-match": (0, "L"),
    "group-separator": (1, "group-separator"), "help": (0, "help"), "include": (1, "include"),
    "ignore-case": (0, "i"), "initial-tab": (0, "T"), "label": (1, "label"),
    "line-buffered": (0, "line-buffered"), "line-number": (0, "n"), "line-regexp": (0, "x"),
    "max-count": (1, "m"), "no-filename": (0, "h"),
    "no-group-separator": (0, "no-group-separator"), "no-messages": (0, "s"), "null": (0, "Z"),
    "null-data": (0, "z"), "only-matching": (0, "o"), "quiet": (0, "q"), "recursive": (0, "r"),
    "dereference-recursive": (0, "R"), "regexp": (1, "e"), "invert-match": (0, "v"),
    "silent": (0, "q"), "text": (0, "a"), "binary": (0, "U"), "unix-byte-offsets": (0, "u"),
    "version": (0, "V"), "with-filename": (0, "H"), "word-regexp": (0, "w"),
}
_X_MATCHERS = {"grep": "G", "egrep": "E", "fgrep": "F", "perl": "P",
               "awk": "awk", "gawk": "awk", "posixawk": "awk"}

# What keeps a pattern off grep 3.0's -F matcher when there are several, measured 2026-09-25:
# `$ * . [ ^` in either syntax; `( + ? { |` in -E; a backslash class, anchor, or back-reference
# (`\w`, `\<`, `\b`, `\1`, ...) in either; and `\( \+ \? \{ \|` in a basic regex. Any other
# backslash escape is read as the literal character, so `a\.b` still aborts.
_ALWAYS_SPECIAL = set("$*.[^")
_ERE_SPECIAL = set("(+?{|")
_ESCAPE_SPECIAL = set("\nBSW'<bsw`>123456789")

# --- bash ---------------------------------------------------------------------------------------
_NAME_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_FD = re.compile(r"[0-9]+(?=[<>])")
_OPERATORS = ("<<<", "<<-", "&>>", ";;&", "&&", "||", ";;", ";&", "|&", "<<", ">>", "<&", ">&",
              "<>", ">|", "&>", ";", "&", "|", "<", ">")
_SEPARATORS = {";", "&", "&&", "||", "|", "|&", ";;", ";&", ";;&"}
_WORD_END = set(" \t\n;&|()<>")
_ANSI_C = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b",
           "f": "\f", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
# Reserved words that a command can follow within one simple command.
_LEADING_RESERVED = {"if", "then", "elif", "else", "do", "while", "until", "!", "{", "time",
                     "coproc"}
# Statements whose remaining words are not a command being run.
_NOT_A_COMMAND = {"for", "select", "case", "[[", "]]", "}", "fi", "done", "esac", "in", "{}"}
_SHELLS = {"bash", "sh", "dash", "zsh", "ksh"}
_WORTH_A_LOOK = re.compile(r"grep|\.sh\b|\bsource\b|(?:^|[\s;&|(])\.\s|\b(?:ba|da|z|k)?sh\b")


class Word(object):
    __slots__ = ("text", "dynamic", "quoted", "start", "end")

    def __init__(self, text, dynamic, quoted, start, end):
        self.text = text          # the word as bash would pass it, _DYN where an expansion goes
        self.dynamic = dynamic    # any part of it comes from an expansion
        self.quoted = quoted      # any part of it was quoted or escaped
        self.start = start        # offsets into the source the word was read from
        self.end = end


class Command(object):
    __slots__ = ("words", "heredocs", "herestrings", "scanner")

    def __init__(self, scanner):
        self.words = []
        self.heredocs = []        # (body_start, body_end, delimiter_was_quoted)
        self.herestrings = []     # the Word after <<<
        self.scanner = scanner


class Scanner(object):
    """One left-to-right pass over a bash source that records every simple command in it.

    Each method reads one quoting context and returns the index where it ends, so a construct
    opened inside another (a "..." inside $(...) inside "...") is read by its own rules. Commands
    inside $(...), backticks, and process substitution are recorded too, ahead of the command
    that contains them, which is the order bash runs them in.
    """

    def __init__(self, src, label=None, line_base=0, sink=None):
        self.s = src
        self.label = label
        self.line_base = line_base
        self.commands = [] if sink is None else sink
        self.pending = []  # heredocs opened on the current line: (delim, strip_tabs, quoted, cmd)

    def line_of(self, offset):
        return self.line_base + self.s.count("\n", 0, offset) + 1

    def run(self):
        self.seq(0, len(self.s), False)
        return self.commands

    def seq(self, i, end, closer):
        s = self.s
        cmd = Command(self)
        while i < end:
            c = s[i]
            if c == " " or c == "\t":
                i += 1
                continue
            if c == "\\" and i + 1 < end and s[i + 1] == "\n":
                i += 2
                continue
            if c == "#":
                j = s.find("\n", i, end)
                i = end if j < 0 else j
                continue
            if c == "\n":
                self._finish(cmd)
                cmd = Command(self)
                i = self._heredoc_bodies(i + 1, end)
                continue
            if c == ")":
                self._finish(cmd)
                if closer:
                    return i + 1
                cmd = Command(self)  # a case pattern's `)`, or a stray one
                i += 1
                continue
            if c == "(":
                self._finish(cmd)
                cmd = Command(self)
                i = self.seq(i + 1, end, True)
                continue
            if (c == "<" or c == ">") and i + 1 < end and s[i + 1] == "(":
                w, i = self.word(i, end)  # process substitution is a word
                if w is not None:
                    cmd.words.append(w)
                continue
            m = _FD.match(s, i, end)
            j = m.end() if m else i
            op = self._operator(j, end)
            if op is not None:
                i = j + len(op)
                if op in _SEPARATORS:
                    self._finish(cmd)
                    cmd = Command(self)
                elif op == "<<" or op == "<<-":
                    i = self._skip_blank(i, end)
                    w, i = self.word(i, end)
                    if w is not None:
                        self.pending.append((w.text, op == "<<-", w.quoted, cmd))
                elif op == "<<<":
                    i = self._skip_blank(i, end)
                    w, i = self.word(i, end)
                    if w is not None:
                        cmd.herestrings.append(w)
                else:
                    i = self._skip_blank(i, end)
                    _, i = self.word(i, end)  # a redirection's target is not an argument
                continue
            w, i2 = self.word(i, end)
            if w is None:
                i2 = i + 1  # never stall on a character no branch of this loop claimed
            else:
                cmd.words.append(w)
            i = i2
        self._finish(cmd)
        return i

    def word(self, i, end):
        s = self.s
        start = i
        out = []
        dynamic = False
        quoted = False
        while i < end:
            c = s[i]
            if c in _WORD_END:
                if i == start and (c == "<" or c == ">") and i + 1 < end and s[i + 1] == "(":
                    i = self.seq(i + 2, end, True)
                    out.append(_DYN)
                    dynamic = True
                    continue
                break
            if c == "\\":
                if i + 1 < end:
                    if s[i + 1] != "\n":
                        out.append(s[i + 1])
                        quoted = True
                    i += 2
                else:
                    out.append(c)
                    i += 1
                continue
            if c == "'":
                j = s.find("'", i + 1, end)
                if j < 0:
                    out.append(s[i + 1:end])
                    i = end
                else:
                    out.append(s[i + 1:j])
                    i = j + 1
                quoted = True
                continue
            if c == '"':
                i, dyn = self._double_quoted(i + 1, end, out)
                quoted = True
                dynamic = dynamic or dyn
                continue
            if c == "$":
                i, dyn, q = self._dollar(i, end, out, False)
                dynamic = dynamic or dyn
                quoted = quoted or q
                continue
            if c == "`":
                i = self._backtick(i + 1, end)
                out.append(_DYN)
                dynamic = True
                continue
            out.append(c)
            i += 1
        if i == start:
            return None, i
        return Word("".join(out), dynamic, quoted, start, i), i

    def _double_quoted(self, i, end, out):
        s = self.s
        dynamic = False
        while i < end:
            c = s[i]
            if c == '"':
                return i + 1, dynamic
            if c == "\\" and i + 1 < end:
                d = s[i + 1]
                if d in '$`"\\':
                    out.append(d)
                elif d != "\n":
                    out.append(c + d)
                i += 2
                continue
            if c == "$":
                i, dyn, _ = self._dollar(i, end, out, True)
                dynamic = dynamic or dyn
                continue
            if c == "`":
                i = self._backtick(i + 1, end)
                out.append(_DYN)
                dynamic = True
                continue
            out.append(c)
            i += 1
        return end, dynamic

    def _dollar(self, i, end, out, in_dq):
        """At a `$`: return (index after the construct, came from an expansion, was quoted)."""
        s = self.s
        nxt = s[i + 1] if i + 1 < end else ""
        if nxt == "(":
            if i + 2 < end and s[i + 2] == "(":
                j = self._skip_arith(i + 3, end)
            else:
                j = self.seq(i + 2, end, True)
            out.append(_DYN)
            return j, True, False
        if nxt == "{":
            out.append(_DYN)
            return self._skip_braced(i + 2, end), True, False
        if nxt == "'" and not in_dq:
            j, text = self._ansi_c(i + 2, end)
            out.append(text)
            return j, False, True
        if nxt == '"' and not in_dq:
            j, dyn = self._double_quoted(i + 2, end, out)
            return j, dyn, True
        if nxt and nxt in _NAME_CHARS:
            j = i + 2
            if not nxt.isdigit():
                while j < end and s[j] in _NAME_CHARS:
                    j += 1
            out.append(_DYN)
            return j, True, False
        if nxt and nxt in "@*#?$!-":
            out.append(_DYN)
            return i + 2, True, False
        out.append("$")
        return i + 1, False, False

    def _skip_arith(self, i, end):
        s = self.s
        depth = 2
        while i < end:
            c = s[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return end

    def _skip_braced(self, i, end):
        s = self.s
        depth = 1
        while i < end:
            c = s[i]
            if c == "\\":
                i += 2
                continue
            if c == "'":
                j = s.find("'", i + 1, end)
                i = end if j < 0 else j + 1
                continue
            if c == '"':
                i, _ = self._double_quoted(i + 1, end, [])
                continue
            if c == "`":
                i = self._backtick(i + 1, end)
                continue
            if c == "$" and i + 1 < end and s[i + 1] == "(":
                i, _, _ = self._dollar(i, end, [], True)
                continue
            if c == "$" and i + 1 < end and s[i + 1] == "{":
                depth += 1
                i += 2
                continue
            if c == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return end

    def _ansi_c(self, i, end):
        s = self.s
        out = []
        while i < end:
            c = s[i]
            if c == "'":
                return i + 1, "".join(out)
            if c == "\\" and i + 1 < end:
                d = s[i + 1]
                if d in _ANSI_C:
                    out.append(_ANSI_C[d])
                    i += 2
                    continue
                m = re.match(r"x([0-9A-Fa-f]{1,2})|([0-7]{1,3})", s[i + 1:i + 4])
                if m:
                    out.append(chr(int(m.group(1), 16)) if m.group(1) else chr(int(m.group(2), 8)))
                    i += 1 + len(m.group(0))
                    continue
                out.append(c + d)
                i += 2
                continue
            out.append(c)
            i += 1
        return end, "".join(out)

    def _backtick(self, i, end):
        """After an opening backtick: record the commands inside and return the index after it."""
        s = self.s
        inner = []
        j = i
        while j < end and s[j] != "`":
            if s[j] == "\\" and j + 1 < end:
                inner.append(s[j + 1] if s[j + 1] in "`\\$" else s[j:j + 2])
                j += 2
                continue
            inner.append(s[j])
            j += 1
        Scanner("".join(inner), self.label, self.line_of(i) - 1, self.commands).run()
        return j + 1 if j < end else end

    def _heredoc_bodies(self, i, end):
        """At the start of the line after one that opened heredocs: step over each body."""
        s = self.s
        while self.pending:
            delim, strip, quoted, cmd = self.pending.pop(0)
            body_start, body_end, k = i, end, i
            while k < end:
                j = s.find("\n", k, end)
                line_end = end if j < 0 else j
                line = s[k:line_end]
                if (line.lstrip("\t") if strip else line) == delim:
                    body_end = k
                    k = end if j < 0 else j + 1
                    break
                k = end if j < 0 else j + 1
            cmd.heredocs.append((body_start, body_end, quoted))
            if not quoted:
                # An unquoted body still runs every $(...) and backtick in it.
                saved, self.pending = self.pending, []
                self._expand_body(body_start, body_end)
                self.pending = saved
            i = k
        return i

    def _expand_body(self, i, end):
        s = self.s
        while i < end:
            c = s[i]
            if c == "\\":
                i += 2
                continue
            if c == "$" and i + 1 < end and s[i + 1] in "({":
                i, _, _ = self._dollar(i, end, [], True)
                continue
            if c == "`":
                i = self._backtick(i + 1, end)
                continue
            i += 1

    def _operator(self, i, end):
        for op in _OPERATORS:
            if i + len(op) <= end and self.s.startswith(op, i):
                return op
        return None

    def _skip_blank(self, i, end):
        s = self.s
        while i < end and (s[i] in " \t" or (s[i] == "\\" and i + 1 < end and s[i + 1] == "\n")):
            i += 2 if s[i] == "\\" else 1
        return i

    def _finish(self, cmd):
        if cmd.words:
            self.commands.append(cmd)


def _assignment(w, src):
    """(name, value) when the word is a NAME=value assignment, else None."""
    m = _ASSIGN.match(src, w.start, w.end)
    if not m:
        return None
    name = src[w.start:m.end()].rstrip("=").rstrip("+")
    k = w.text.find("=")
    return name, (w.text[k + 1:] if k >= 0 else "")


def _basename(text):
    base = text.replace("\\", "/").rsplit("/", 1)[-1]
    return base[:-4] if base.lower().endswith(".exe") else base


def _sub(w, text):
    """The part of a word that follows an option letter, as a word of its own."""
    return Word(text, _DYN in text, w.quoted, w.start, w.end)


def _utf8_locale(env):
    for name in LOCALE_NAMES:
        value = env.get(name)
        if value:
            return _DYN in value or bool(_UTF8.search(value))
    return False


def _is_literal(pattern, extended):
    """True when grep 3.0 would hand this pattern to its -F matcher, given several of them."""
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c in _ALWAYS_SPECIAL or (extended and c in _ERE_SPECIAL):
            return False
        if c == "\\":
            if i + 1 >= n:
                return False  # a trailing backslash: grep refuses it outright
            d = pattern[i + 1]
            if d in _ESCAPE_SPECIAL or (not extended and d in _ERE_SPECIAL):
                return False
            i += 2
            continue
        i += 1
    return True


def _long_option(name):
    """getopt_long's lookup: an exact name, or a prefix every candidate for which agrees."""
    if name in _LONG:
        return _LONG[name]
    candidates = [_LONG[k] for k in _LONG if name and k.startswith(name)]
    if candidates and all(c == candidates[0] for c in candidates):
        return candidates[0]
    return None  # unknown or ambiguous, which grep refuses with a message


class _GrepArgs(object):
    __slots__ = ("icase", "matchers", "patterns", "operands")

    def __init__(self):
        self.icase = False
        self.matchers = []
        self.patterns = []   # ("e", Word) or ("f", Word)
        self.operands = []


def _apply(ident, arg, st):
    """Record one option. False means grep would stop with a message, which is not this bug."""
    if ident in ("i", "y"):
        st.icase = True
    elif ident in ("F", "G", "E", "P"):
        st.matchers.append(ident)
    elif ident == "X":
        matcher = None if arg.dynamic else _X_MATCHERS.get(arg.text)
        if matcher is None:
            return False
        st.matchers.append(matcher)
    elif ident == "e" or ident == "f":
        st.patterns.append((ident, arg))
    elif ident in ("V", "help"):
        return False
    return True


def parse_grep(args):
    """Read grep's arguments the way grep 3.0's getopt_long does, options after operands included.

    Returns None when grep would refuse the command with a message of its own (an unknown or
    ambiguous option, a missing argument, --help, --version), since a loud refusal is not the
    silent failure this guard exists for.
    """
    st = _GrepArgs()
    i, n = 0, len(args)
    options_done = False
    while i < n:
        w = args[i]
        t = w.text
        if options_done or t == "-" or not t.startswith("-"):
            st.operands.append(w)
            i += 1
            continue
        if t == "--":
            options_done = True
            i += 1
            continue
        if t.startswith("--"):
            name, eq, value = t[2:].partition("=")
            opt = _long_option(name)
            if opt is None:
                return None
            has_arg, ident = opt
            arg = None
            if has_arg == 1:
                if eq:
                    arg = _sub(w, value)
                elif i + 1 < n:
                    i += 1
                    arg = args[i]
                else:
                    return None
            elif has_arg == 0 and eq:
                return None
            if not _apply(ident, arg, st):
                return None
            i += 1
            continue
        j = 1
        while j < len(t):
            ch = t[j]
            if ch in _SHORT_WITH_ARG:
                rest = t[j + 1:]
                if rest:
                    arg = _sub(w, rest)
                elif i + 1 < n:
                    i += 1
                    arg = args[i]
                else:
                    return None
                if not _apply(ch, arg, st):
                    return None
                break
            if ch not in _SHORT_FLAGS or not _apply(ch, None, st):
                return None  # an option grep does not know, or one an expansion supplies
            j += 1
        i += 1
    return st


def _resolve(text, cwd):
    if not text or _DYN in text:
        return None
    p = text
    if p.startswith("~/"):
        p = os.path.join(os.path.expanduser("~"), p[2:])
    m = re.match(r"/([A-Za-z])(?:/|$)", p)
    if m and os.name == "nt":
        p = m.group(1) + ":/" + p[3:]
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    return p


def _read_small(path):
    try:
        if path and os.path.isfile(path) and os.path.getsize(path) <= _MAX_FILE:
            with open(path, "rb") as fh:
                return fh.read().decode("utf-8", "replace").replace("\r\n", "\n")
    except OSError:
        pass
    return None


class Hit(object):
    __slots__ = ("kind", "where", "snippet", "count", "unread_file")

    def __init__(self, kind, where, snippet, count, unread_file):
        self.kind = kind            # "fixed" (-i with -F) or "multi" (-i, 2+ literal patterns)
        self.where = where          # "" for the command itself, else "<file>, line N: "
        self.snippet = snippet
        self.count = count
        self.unread_file = unread_file


class Analyzer(object):
    def __init__(self, cwd=None, environ=None, follow=True):
        env = os.environ if environ is None else environ
        self.base = dict((k, env[k]) for k in LOCALE_NAMES if env.get(k))
        self.cwd = cwd
        self.follow = follow
        self.visited = set()

    def source(self, src, label=None, line_base=0, exported=None, shellvars=None, depth=0):
        """Read one bash source and return the first aborting grep in it, or None."""
        if depth > _MAX_DEPTH:
            return None
        exported = dict(self.base) if exported is None else exported
        shellvars = {} if shellvars is None else shellvars
        for cmd in Scanner(src, label, line_base).run():
            hit = self.command(cmd, exported, shellvars, depth)
            if hit is not None:
                return hit
        return None

    def command(self, cmd, exported, shellvars, depth):
        words = cmd.words
        src = cmd.scanner.s
        n = len(words)
        i = 0
        prefix = {}
        while i < n:
            w = words[i]
            if not w.quoted and not w.dynamic:
                if w.text in _LEADING_RESERVED:
                    i += 1
                    while w.text == "time" and i < n and words[i].text == "-p":
                        i += 1
                    continue
                if w.text == "function":
                    k = i + 1
                    while k < n and words[k].text != "{":
                        k += 1
                    i = k + 1  # into the body, when it opens on this line
                    continue
            a = _assignment(w, src)
            if a is None:
                break
            if a[0] in LOCALE_NAMES:
                prefix[a[0]] = a[1]
            i += 1
        if i >= n:
            # Bare assignments reach a child process only for a name already exported.
            for name, value in prefix.items():
                if name in exported:
                    exported[name] = value
                else:
                    shellvars[name] = value
            return None
        head = words[i]
        if head.dynamic or (not head.quoted and head.text in _NOT_A_COMMAND):
            return None
        if head.text in ("export", "declare", "typeset", "readonly", "local", "unset"):
            self._note_exports(head.text, words[i + 1:], src, exported, shellvars)
            return None
        env = dict(exported)
        env.update(prefix)
        return self.invocation(cmd, words, i, env, exported, shellvars, depth)

    def invocation(self, cmd, words, i, env, exported, shellvars, depth):
        """Walk past the wrappers in front of a command until it is a grep, or not."""
        n = len(words)
        src = cmd.scanner.s
        while i < n:
            head = words[i]
            if head.dynamic:
                return None
            name = _basename(head.text)
            if name in GREP_FAMILY:
                return self.grep(cmd, words, i, env, GREP_FAMILY[name])
            if name == "command":
                i += 1
                while i < n and words[i].text.startswith("-") and words[i].text != "-":
                    if "v" in words[i].text or "V" in words[i].text:
                        return None  # a lookup, not a run
                    i += 1
                continue
            if name == "exec":
                i = _skip_options(words, i + 1, "a", ())
                continue
            if name == "nohup":
                i += 1
                continue
            if name == "time":
                i = _skip_options(words, i + 1, "fo", ("format", "output"))
                continue
            if name == "nice":
                i = _skip_options(words, i + 1, "n", ("adjustment",))
                continue
            if name == "stdbuf":
                i = _skip_options(words, i + 1, "ioe", ("input", "output", "error"))
                continue
            if name == "timeout":
                i = _skip_options(words, i + 1, "sk", ("signal", "kill-after")) + 1
                continue
            if name == "xargs":
                i = _skip_xargs(words, i + 1)
                continue
            if name == "env":
                parsed = _env_arguments(words, i + 1, env, src)
                if parsed is None:
                    return None
                i, env = parsed
                continue
            if name == "find":
                return self._find_exec(cmd, words, i + 1, env, depth)
            if name in _SHELLS:
                return self._shell(cmd, words, i + 1, env, depth)
            if head.text in ("source", ".") and not head.quoted:
                if i + 1 < n:
                    return self._follow(words[i + 1], exported, shellvars, depth, False)
                return None
            if "/" in head.text or "\\" in head.text:
                return self._follow(head, dict(env), {}, depth, True)
            return None
        return None

    def grep(self, cmd, words, i, env, implied):
        if _utf8_locale(env):
            return None
        st = parse_grep(words[i + 1:])
        if st is None or not st.icase:
            return None
        chosen = set(st.matchers)
        if implied:
            chosen.add(implied)
        if len(chosen) > 1:
            return None  # "conflicting matchers specified", which grep says out loud
        matcher = chosen.pop() if chosen else "G"
        sources = st.patterns or [("e", w) for w in st.operands[:1]]
        if not sources:
            return None  # no pattern at all: grep prints its usage line and stops
        if matcher == "F":
            return self._hit(cmd, words, i, "fixed", 0, False)
        if matcher not in ("G", "E"):
            return None
        extended = matcher == "E"
        known, unknown, unread_file, regex_seen = [], 0, False, False
        for kind, w in sources:
            if kind == "f":
                content = self._pattern_file(w)
                if content is None:
                    unknown += 1
                    unread_file = True
                    continue
                lines = content.split("\n")
                if lines and lines[-1] == "":
                    lines.pop()
                known.extend(lines)
            elif w.dynamic:
                if _is_literal(w.text.replace(_DYN, "x"), extended):
                    unknown += w.text.count("\n") + 1
                else:
                    regex_seen = True
            else:
                known.extend(w.text.split("\n"))
        if regex_seen or not all(_is_literal(p, extended) for p in known):
            return None  # one real regex keeps grep on its regex matcher, which works
        count = len(known) + unknown
        if count < 2 and not unread_file:
            return None
        return self._hit(cmd, words, i, "multi", count, unread_file)

    def _pattern_file(self, w):
        if w.text == "/dev/null":
            return ""
        if not self.follow or w.dynamic or w.text in ("-", "/dev/stdin"):
            return None
        return _read_small(_resolve(w.text, self.cwd))

    def _hit(self, cmd, words, i, kind, count, unread_file):
        sc = cmd.scanner
        start = words[i].start
        snippet = " ".join(sc.s[start:words[-1].end].split())
        if len(snippet) > 160:
            snippet = snippet[:157] + "..."
        where = "" if sc.label is None else "{0}, line {1}: ".format(sc.label, sc.line_of(start))
        return Hit(kind, where, snippet, count, unread_file)

    def _find_exec(self, cmd, words, i, env, depth):
        n = len(words)
        while i < n:
            if words[i].text in ("-exec", "-execdir", "-ok", "-okdir"):
                k = i + 1
                while k < n and words[k].text not in (";", "+"):
                    k += 1
                hit = self.invocation(cmd, words[i + 1:k], 0, dict(env), {}, {}, depth)
                if hit is not None:
                    return hit
                i = k
            i += 1
        return None

    def _shell(self, cmd, words, i, env, depth):
        n = len(words)
        run_string = False
        while i < n:
            w = words[i]
            t = w.text
            if w.dynamic:
                break
            if t in ("--", "-"):
                i += 1
                break
            if t.startswith("--"):
                i += 2 if t in ("--rcfile", "--init-file") else 1
                continue
            if t[:1] in ("-", "+") and len(t) > 1:
                if t[0] == "-" and "c" in t:
                    run_string = True
                i += 2 if ("o" in t or "O" in t) else 1
                continue
            break
        sc = cmd.scanner
        if run_string:
            if i < n and not words[i].dynamic:
                return self.source(words[i].text, sc.label, sc.line_of(words[i].start) - 1,
                                   dict(env), {}, depth + 1)
            return None
        if i < n:
            return self._follow(words[i], dict(env), {}, depth, False)
        for start, stop, _ in cmd.heredocs:  # the shell reads its script from stdin
            hit = self.source(sc.s[start:stop], sc.label, sc.line_of(start) - 1, dict(env), {},
                              depth + 1)
            if hit is not None:
                return hit
        for w in cmd.herestrings:
            hit = self.source(w.text.replace(_DYN, ""), sc.label, sc.line_of(w.start) - 1,
                              dict(env), {}, depth + 1)
            if hit is not None:
                return hit
        return None

    def _follow(self, w, exported, shellvars, depth, need_shell_script):
        """Read a script the command runs and check it too."""
        if not self.follow or w.dynamic or depth >= _MAX_DEPTH:
            return None
        path = _resolve(w.text, self.cwd)
        if path is None:
            return None
        key = os.path.normcase(os.path.abspath(path))
        if key in self.visited:
            return None
        text = _read_small(path)
        if text is None:
            return None
        if need_shell_script and not (path.endswith(".sh") or _SHEBANG.match(text)):
            return None
        self.visited.add(key)
        return self.source(text, w.text, 0, exported, shellvars, depth + 1)

    def _note_exports(self, name, args, src, exported, shellvars):
        if name == "unset":
            for w in args:
                exported.pop(w.text, None)
                shellvars.pop(w.text, None)
            return
        export = name == "export"
        unexport = False
        for w in args:
            t = w.text
            a = _assignment(w, src)
            if a is None and t.startswith("-"):
                if name in ("declare", "typeset") and "x" in t:
                    export = True
                if name == "export" and "n" in t:
                    unexport = True
                continue
            if a is not None:
                var, value = a
                if var not in LOCALE_NAMES:
                    continue
                if unexport:
                    exported.pop(var, None)
                    shellvars[var] = value
                elif export or var in exported:
                    exported[var] = value
                else:
                    shellvars[var] = value
            elif t in LOCALE_NAMES:
                if unexport and t in exported:
                    shellvars[t] = exported.pop(t)
                elif export and t in shellvars:
                    exported[t] = shellvars.pop(t)


def _skip_options(words, i, with_arg, long_with_arg):
    """Step over a wrapper's own options. Returns the index of the command it runs."""
    n = len(words)
    while i < n:
        t = words[i].text
        if t == "--":
            return i + 1
        if not t.startswith("-") or t == "-":
            return i
        if t.startswith("--"):
            i += 2 if ("=" not in t and t[2:] in long_with_arg) else 1
            continue
        i += 2 if (len(t) == 2 and t[1] in with_arg) else 1
    return i


def _skip_xargs(words, i):
    n = len(words)
    long_with_arg = ("arg-file", "delimiter", "eof", "replace", "max-lines", "max-args",
                     "max-procs", "max-chars", "process-slot-var")
    while i < n:
        t = words[i].text
        if t == "--":
            return i + 1
        if not t.startswith("-") or t == "-":
            return i
        if t.startswith("--"):
            i += 2 if ("=" not in t and t[2:] in long_with_arg) else 1
            continue
        step = 1
        for k in range(1, len(t)):
            if t[k] in "adEILnPs":      # takes an argument, attached or the next word
                step = 2 if k == len(t) - 1 else 1
                break
            if t[k] in "eil":           # optional argument, attached only
                break
        i += step
    return i


def _env_arguments(words, i, env, src):
    """env's own options and NAME=value words. Returns (index of the command, its env)."""
    n = len(words)
    env = dict(env)
    while i < n:
        w = words[i]
        t = w.text
        if w.dynamic:
            return None
        if t in ("-i", "-", "--ignore-environment"):
            env = {}
        elif t in ("-u", "--unset", "-C", "--chdir"):
            if t in ("-u", "--unset") and i + 1 < n:
                env.pop(words[i + 1].text, None)
            i += 1
        elif t.startswith("-u") and not t.startswith("--"):
            env.pop(t[2:], None)
        elif t.startswith("--unset="):
            env.pop(t[len("--unset="):], None)
        elif t.startswith("-S") or t.startswith("--split-string"):
            return None
        elif t == "--":
            i += 1
            break
        elif t.startswith("-"):
            pass
        else:
            break
        i += 1
    while i < n:
        a = _assignment(words[i], src)
        if a is None:
            break
        if a[0] in LOCALE_NAMES:
            env[a[0]] = a[1]
        i += 1
    return i, env


def find_abort(command, cwd=None, environ=None, follow=True):
    """The first grep in `command` that GNU grep 3.0 would abort on, as a Hit, or None."""
    return Analyzer(cwd, environ, follow).source(command.replace("\r\n", "\n"))


REASON = (
    "Blocked: this grep ABORTS in git-bash, and the abort reads as \"no matches\".\n\n"
    "  {where}{snippet}\n\n"
    "GNU grep 3.0, the copy Git for Windows ships, dies with SIGABRT (exit 134, no output, no "
    "message) when it folds case through its fixed-string matcher under the C locale, which is "
    "the locale a Bash command gets here (LANG unset). Mid-pipeline the later stages just see "
    "no input, and `if grep -q...` is just false. It once emptied an audit script's "
    "list on every Windows run.\n\n"
    "{shape}\n\n"
    "Fix: the same command with LC_ALL=C.UTF-8 in front of THIS grep:\n"
    "  ... | LC_ALL=C.UTF-8 grep ...\n"
    "A separate `LC_ALL=C.UTF-8;` statement does NOT reach grep, since it is not exported; the "
    "prefix or `export LC_ALL=C.UTF-8` does. If the input might not be UTF-8, add -a, or grep "
    "prints \"Binary file ... matches\" in place of the lines. The Grep tool (ripgrep) is "
    "unaffected too.\n\n"
    "Measured 2026-09-25. There is no override, because the "
    "prefixed command runs the same search."
)

SHAPE_FIXED = (
    "It has -i and -F together (-iF, -Fi, -y, --ignore-case, --fixed-strings, fgrep -i, and "
    "-X fgrep are all the same pair). Every such combination aborts, whatever the pattern."
)

SHAPE_MULTI = (
    "It has -i and {count} patterns that are all plain strings{how}. grep 3.0 quietly switches "
    "several literal patterns to its -F matcher, so this aborts exactly as -iF does. A single "
    "real regex among them (a `.`, `*`, `[`, `^`, `$`) would keep it on the regex matcher, but "
    "the prefix is the reliable fix."
)


def reason(hit):
    if hit.kind == "fixed":
        shape = SHAPE_FIXED
    else:
        how = (", counting a -f file this guard could not read as several lines"
               if hit.unread_file else "")
        count = "two or more" if hit.unread_file else str(hit.count)
        shape = SHAPE_MULTI.format(count=count, how=how)
    return REASON.format(where=hit.where, snippet=hit.snippet, shape=shape)


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    try:
        if (payload.get("tool_name") or "") != "Bash":
            return 0
        command = (payload.get("tool_input") or {}).get("command") or ""
        # Cheap bail-out first, so this costs nothing on an ordinary tool call.
        if not _WORTH_A_LOOK.search(command):
            return 0
        hit = find_abort(command, cwd=payload.get("cwd"))
        if hit is None:
            return 0
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason(hit),
            }
        }))
    except Exception:
        return 0  # fail-open: a bug here must not wedge every tool call
    return 0


if __name__ == "__main__":
    sys.exit(main())
