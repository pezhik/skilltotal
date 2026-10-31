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

## The sentinel

No agent has a hook for a plugin install. A person typing `/plugin install`, the Extensions panel
and automatic updates run no command, so no hook is asked. A bad update arrives that way.
`skilltotal watch` looks at what is on disk instead:

```bash
skilltotal watch                 # scan what is new or changed since the last run
skilltotal watch --disable       # also turn off a Claude Code plugin with malicious indicators
```

It lists every installed plugin, skill, MCP server and editor extension, compares a fingerprint of
each with its state file, and scans only what is new or changed. A new ruleset counts as a change.
When nothing changed it reads a few sizes and times and exits.

| Exit code | Meaning |
|---|---|
| 0 | Nothing is flagged |
| 1 | A scan failed; that component is tried again next run |
| 2 | A component is flagged. It stays flagged on every run until it is removed, updated or accepted |

`--accept FILE`, `--block-on`, `--state FILE`, `--no-extensions`, `--project DIR` and `--json` work
as in [`guard --installed`](cli.md#guard), and an update that gains risk is reported as
[drift](installed-components.md#catching-a-malicious-update). The state is kept in
`watch-state.json` in the [cache folder](plugin.md#git-sources-the-verdict-cache-and-timing).

It edits nothing unless you pass `--disable`, which sets `enabledPlugins` to `false` in Claude
Code's user settings for a plugin with malicious indicators, and for nothing else. High risk alone
is your call. The settings file is backed up first, and one that is not plain JSON is left alone.

**Where it runs.**

- Claude Code: the plugin runs it at session start and when skills or user settings change.
- Cursor: `hook install` adds it to `sessionStart`.
- Anywhere else, or as well, schedule it:

  ```bash
  # cron (Linux): every hour
  0 * * * * skilltotal watch --quiet
  ```

  ```xml
  <!-- launchd (macOS): ~/Library/LaunchAgents/skilltotal.watch.plist -->
  <plist version="1.0"><dict>
    <key>Label</key><string>skilltotal.watch</string>
    <key>ProgramArguments</key><array>
      <string>/usr/local/bin/skilltotal</string><string>watch</string><string>--quiet</string>
    </array>
    <key>StartInterval</key><integer>3600</integer>
  </dict></plist>
  ```

  ```powershell
  # Task Scheduler (Windows)
  schtasks /Create /SC HOURLY /TN "SkillTotal watch" /TR "skilltotal watch --quiet"
  ```

**At session start** the hook answers at once from the last run and starts a sweep in the
background, with one worker process, so the session does not wait. What the sweep finds reaches the
agent at the next session start, not in the running one. In CI no sweep starts.

**What the agent is told.** A flagged component is the last place to take words from, so the agent
gets our fixed sentences and the component's kind and name, and a name that holds anything but
plain characters is withheld. It never gets a finding, a reason or a description. The findings are
in `skilltotal watch`.

**What it does not see.**

- A local component is fingerprinted by its manifests, its top folder, the folders that hold its
  code (`hooks`, `commands`, `scripts`, `bin`, `dist`, `src` and a few more) and its entry points. A
  change deeper down that keeps the version is not noticed. `guard --installed` reads everything.
- It runs after the fact: a component that runs code the moment it is installed has already run.
- An MCP server started with `npx -y x` changes on the registry, not on disk, so its release is
  looked up once a day and a new one is scanned. Between lookups it is not seen.
- A package whose installer reads a custom registry is listed and not scanned, so a sweep nobody
  asked for never sends a company's package name to the public registry.
- It does not look at skills an agent writes itself as they are written, by `Write` or `Edit`: the
  next sweep reads them.

**Network.** A sweep fetches what changed and is not on disk from npm, PyPI or GitHub, and asks the
registry for the current release of an unpinned server once a day, as `guard --installed` does. A
component on disk is scanned without a network request.
