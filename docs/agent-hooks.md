# Agent hooks

SkillTotal checks installs in six coding agents besides Claude Code, with one parser and one set of
verdicts. This page says what each hook can and cannot see, how to install it, and how to roll it
out to a team. For what the check decides, its settings, its cache and CI strict mode, see
[docs/plugin.md](plugin.md): all of it applies to every agent here.

## Install

```bash
pipx install skilltotal
skilltotal hook install             # every agent found on this machine
skilltotal hook install --dry-run   # show the change as a diff and write nothing
skilltotal hook status              # what is protected, and anything wrong
skilltotal hook uninstall           # take it out again
```

`--agent cursor` picks one agent. `--scope project` writes the project's config instead of yours.
In your own config the hook runs the CLI by its full path, because an editor started from a dock
does not see your shell's `PATH`; in a project's config, which others share, it runs `skilltotal`.

The install merges one entry into the agent's config and leaves every other entry alone. A second
run changes nothing, the file as it was is kept beside it as `<file>.skilltotal-backup`, and
`uninstall` removes only that entry. A config that is not plain JSON (`settings.json` with
comments) or that is a link is refused: add the entry by hand from the table below.

For Claude Code, use the [plugin](plugin.md). `hook install` only says so, because the plugin also
brings the sentinel and updates with its marketplace.

## What each agent's hook sees

| Agent | Config (user / project) | Hook events | Can ask? | Blocks with |
|---|---|---|---|---|
| Claude Code | [the plugin](plugin.md) | `PreToolUse` on Bash and PowerShell | Yes | `permissionDecision` |
| Cursor | `~/.cursor/hooks.json` / `.cursor/hooks.json` | `beforeShellExecution`, `beforeMCPExecution`, `sessionStart` | Yes | `permission` |
| Windsurf | `~/.codeium/windsurf/hooks.json` / `.windsurf/hooks.json` | `pre_run_command`, `pre_mcp_tool_use` | No | Exit code 2 |
| Devin | `~/.config/devin/config.json` (`%APPDATA%\devin\config.json`) / `.devin/hooks.v1.json` | `PreToolUse` on `exec` | No | `decision: block` and exit code 2 |
| Codex | `~/.codex/hooks.json` / `.codex/hooks.json` | `PreToolUse` on `Bash` | No | `permissionDecision` |
| Gemini CLI | `~/.gemini/settings.json` / `.gemini/settings.json` | `BeforeTool` on `run_shell_command` | No | `decision: deny` |
| VS Code Copilot | `~/.copilot/hooks/skilltotal.json` / `.github/hooks/skilltotal.json` | `preToolUse` | Yes | `permissionDecision` |

**An agent that cannot ask.** Where SkillTotal would ask you, these agents get a denial that gives
the reason and says how to go ahead: review it, then run the command yourself outside the agent.
Codex is on this list because it parses `ask` but then reports the hook as failed and runs the
command.

**Trust.** Codex runs a new hook only after you approve it under `/hooks`. Until then it is
installed but does nothing. `hook install` says so.

**The console line.** Every install gets one line, as in Claude Code: Cursor's `user_message`,
`systemMessage` in Codex and Gemini CLI, Windsurf's hook output (`show_output`), and stderr for
Copilot and Devin, which have no such field.

**The shell.** These agents do not say which shell runs a command. SkillTotal reads it as
PowerShell on Windows and as a POSIX shell elsewhere.

**A hook that cannot start lets the command run.** That is how these agents work: a hook that
crashes or times out does not block, apart from Copilot, which denies on a crash, and Cursor with
`failClosed`. Run `skilltotal hook status` after moving or reinstalling the CLI. The installed
timeout is 900 seconds so that a slow check ends in an answer. Windsurf documents no timeout
setting, so its default applies.

**Cursor's `allow`.** A Cursor hook must answer with a `permission`, so SkillTotal answers `allow`
when it has no objection. Cursor's documentation does not say whether that also skips Cursor's own
approval settings.

**Gemini CLI and Antigravity CLI.** Gemini CLI's documentation says Antigravity CLI replaced it in
June 2026. The hook follows Gemini CLI's documented format, and it has not been tested on
Antigravity CLI.

**Windsurf and Devin.** Windsurf's hooks page now redirects to Devin Desktop, which uses
`.devin/hooks.v1.json`. `--agent windsurf` writes the format Windsurf documented
(`pre_run_command`), and `--agent devin` writes the new one.

## MCP servers

Cursor and Windsurf call a hook before each MCP tool call. SkillTotal checks a server on its first
call, by the command that starts it, as if that command had been typed. A server that passes is not
checked again for 24 hours, and a changed command counts as a new server. A server that was denied
or asked about gets the same answer on every call, since the hook cannot tell what you answered.
Windsurf's event names only the server, so its command comes from
`~/.codeium/windsurf/mcp_config.json`. A server not listed there is not checked. The record of
servers already checked is `hook-mcp-seen.json` in the [cache folder](plugin.md#git-sources-the-verdict-cache-and-timing).
It holds hashes and times.

Claude Code's plugin does not hook MCP calls: it would start the hook on every tool call. Servers
are checked when `claude mcp add` runs.
