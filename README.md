# Claude Code guards for commands that fail silently

Six [PreToolUse hooks](https://code.claude.com/docs/en/hooks) that stop a shell command before it
runs when the command would fail without saying so: it exits 0, prints nothing or something
plausible, and reads as a real answer. Each one exists because that happened on real work and the
wrong answer was believed.

Packaged as a Claude Code plugin named `command-guards`. Each guard is also a standalone script,
so you can wire just the ones you want.

## The guards

| Guard | What it catches | What it does |
|---|---|---|
| [Empty SOQL values](hooks/guards/pretool-soql-guard.py) | A SOQL `IN (...)` list with an empty element, such as `IN ('')`. SOQL reads that as every record where the field is blank, so a narrow filter becomes a broad one, and under a delete it removes far more than intended. | Blocks. |
| [Hidden CLI errors](hooks/guards/pretool-sf-json-stderr-guard.py) | `sf ... --json \| jq`, where a failed command's error envelope has no `.result`, so jq prints nothing and the failure reads as an empty result. `2>/dev/null` and a `?` in the jq filter make it worse. | Rewrites a read-only command to `sfj` and still asks before it runs. Blocks a mutating command that hides stderr. |
| [Backup files](hooks/guards/pretool-deploy-backup-file-guard.py) | `sf project deploy start` or `validate` over a folder holding a backup copy such as `X.permissionset-meta.xml.bak`. The source resolver sends the backup's content in place of the real file and the deploy reports success. | Blocks. |
| [Unset shell variables](hooks/guards/pretool-bash-unset-var-guard.py) | A `$VAR` set in an earlier Bash tool call. Each call gets a fresh shell, so the variable expands to nothing and a different command runs. | Blocks. |
| [Silent search failures](hooks/guards/pretool-grep-abort-guard.py) | `grep -i` with `-F`, or with two or more literal patterns, in Git Bash. The GNU grep 3.0 that Git for Windows ships aborts on these under the C locale, with no output and no message. | Blocks, with the `LC_ALL=C.UTF-8` fix. Stands down where grep does not abort. |
| [Stacked pull requests](hooks/guards/pretool-stacked-pr-merge-guard.py) | `gh pr merge` while another open pull request uses the merging one's branch as its base. Deleting that branch closes the stacked pull request instead of retargeting it. | Blocks, naming the `gh pr edit --base` fix. |

Every guard fails open: an internal error, or a missing tool such as `gh`, lets the command
through rather than blocking every call. None has an override flag, because in each case the
corrected command is always available and does the same work.

The [`sfj`](bin/sfj) wrapper that the CLI-errors guard rewrites to ships in `bin/`, which Claude
Code puts on the Bash tool's PATH while the plugin is enabled. It runs `sf <args> --json`, prints
only the JSON, and when sf really failed, prints sf's error name and message to stderr and exits
non-zero.

## Install

In a Claude Code session:

```
/plugin marketplace add rob-alexa/claude-code-guards
/plugin install command-guards@command-guards
```

Requirements:

- Python 3, run as `python3` on macOS and Linux and as `python` in Git Bash on Windows.
- `sf` and `jq` for the Salesforce guards and `sfj`.
- `gh`, signed in, for the stacked pull request guard. Without it that guard stays silent.

The hooks are registered on the `Bash` and `PowerShell` tools only.

### Windows and the Claude desktop app

The plugin's hook runs through Git Bash, and on Windows the Claude desktop app gives every console
process a hook starts its own console window, which can flash and take focus on each tool call
([anthropics/claude-code#14828](https://github.com/anthropics/claude-code/issues/14828)). If that
happens, skip the plugin and wire the runner by hand in `~/.claude/settings.json` with
[`hook-no-window.py`](hooks/hook-no-window.py), which starts it without a console:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(Bash|PowerShell)$",
        "hooks": [
          {
            "type": "command",
            "command": "pythonw",
            "args": [
              "C:/path/to/claude-code-guards/hooks/hook-no-window.py", "--",
              "python", "C:/path/to/claude-code-guards/hooks/pretool-guards.py"
            ],
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

Wired by hand, `bin/` is not on the PATH automatically, so add it yourself if you use the
CLI-errors guard.

## Wire a single guard by hand

Each guard reads the hook payload on stdin and prints its decision, so any one of them works as
its own hook:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/claude-code-guards/hooks/guards/pretool-soql-guard.py"
          }
        ]
      }
    ]
  }
}
```

The plugin instead registers one runner, [`hooks/pretool-guards.py`](hooks/pretool-guards.py),
which runs all six in a single Python process. Starting one interpreter per tool call rather than
six is faster, most of all on Windows. When more than one guard has something to say, a block wins
over an ask, and every blocking guard's reason is reported together.

## Self-checks

Each guard has a suite beside it that drives it the way Claude Code does, as a subprocess with a
JSON payload on stdin. No org, no network: the stacked pull request suite puts a fake `gh` on the
PATH.

```bash
python hooks/test-pretool-guards.py
for t in hooks/guards/test-*.py; do python "$t" || echo "FAILED: $t"; done
```

Most of each suite is false-positive coverage, on purpose. A guard that blocks ordinary commands
gets switched off, and then it guards nothing.

## What was changed on the way out

These guards come from a working Salesforce delivery repository and were rewritten for general use,
with names, identifiers, and organization-specific references removed. The decision logic of each
guard is unchanged, with one exception: the CLI-errors guard's rewrite now asks before it runs,
where the original approved it, because a plugin should never approve a command on someone's
behalf.

Each guard's docstring keeps the mechanism and the evidence for it. The measurements there come
from real environments during 2026, all at one organization, so verify anything you plan to rely
on against your own.

## Related

[rob-alexa/claude-skills](https://github.com/rob-alexa/claude-skills) holds skills from the same
work. A skill is guidance Claude follows when it applies; a guard is enforced on every matching
command. `pull-request-checklist` there explains the stacked pull request trap, and this repository
enforces it.

## License

MIT. See [LICENSE](LICENSE).
