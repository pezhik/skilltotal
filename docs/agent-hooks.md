# Agent hooks

SkillTotal has one parser and one set of verdicts, with a hook for Claude Code and six other coding
agents. Not all of them have been proven in the agent itself, so each carries a tier:

| Agent | Tier |
|---|---|
| Claude Code | verified against Claude Code 2.1.316 on 2026-10-31 |
| Gemini CLI | verified against Gemini CLI 0.45.2 on 2026-10-31, with its real hook runner and a stand-in model |
| Cursor | preview: built to the agent's documented hook format, not yet run in the agent |
| Windsurf | preview: built to the agent's documented hook format, not yet run in the agent |
| Devin | preview: built to the agent's documented hook format, not yet run in the agent |
| Codex | preview: built to the agent's documented hook format, not yet run in the agent |
| VS Code Copilot | preview: built to the agent's documented hook format, not yet run in the agent |

Gemini CLI's run used a local stand-in for the model, since no account was signed in: the CLI, its
tool scheduler and its hook runner were real, and so were the deny, the denial of a question and the
install that went through. `hook status` and `hook install` show the same tier.

This page says what each hook can and cannot see, how to install it, and how to roll it out to a
team. For what the check decides, its settings, its cache and CI strict mode, see
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
On macOS and Linux your own config runs the CLI by its full path, because an editor started from a
dock does not see your shell's `PATH`. On Windows, and in a project's config, which others share, it
runs `skilltotal`.

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
| Cursor | `~/.cursor/hooks.json` / `.cursor/hooks.json` | `beforeShellExecution`, `beforeMCPExecution`, `sessionStart` | Not reliably | `permission` |
| Windsurf | `~/.codeium/windsurf/hooks.json` / `.windsurf/hooks.json` | `pre_run_command`, `pre_mcp_tool_use` | No | Exit code 2 |
| Devin | `~/.config/devin/config.json` (`%APPDATA%\devin\config.json`) / `.devin/hooks.v1.json` | `PreToolUse` on `exec` | No | `decision: block` and exit code 2 |
| Codex | `~/.codex/hooks.json` / `.codex/hooks.json` | `PreToolUse` on `Bash` | No | `permissionDecision` |
| Gemini CLI | `~/.gemini/settings.json` / `.gemini/settings.json` | `BeforeTool` on `run_shell_command` | No | `decision: deny` |
| VS Code Copilot | `~/.copilot/hooks/skilltotal.json` / `.github/hooks/skilltotal.json` | `preToolUse` | Yes | `permissionDecision` |

**An agent that cannot ask.** Where SkillTotal would ask you, these agents get a denial that gives
the reason and says how to go ahead: review it, then run the command yourself outside the agent.
Codex is on this list because it parses `ask` but then reports the hook as failed and runs the
command. Gemini CLI 0.45.2 reads `ask` too, though its documentation does not list it, but with
`gemini -p`, where nobody can answer, the run hangs until it is killed, so SkillTotal denies there.

**A hook never approves.** An `allow` from a hook could skip a question you would otherwise be
asked, so SkillTotal never sends one, with one exception below. With nothing to object to it answers
in the form each agent documents as no decision: no output for Gemini CLI, Codex, Copilot, Windsurf
and Devin, whose normal approval flow then applies.

**Cursor.** Cursor documents no reply that means "no opinion", and does not say what `allow` does to
its own approval settings. Cursor's staff say on its forum that only `deny` is enforced in every
mode, and that `ask` does not stop every mode. So in Cursor:

- what SkillTotal would ask about is denied, with how to go ahead;
- an install that passed gets `ask`, which approves nothing;
- any other command gets exit code 1, which the documentation says lets the action proceed as a
  failed hook. It is the one documented outcome that cannot be an approval, and Cursor may log it
  as a hook failure;
- with `failClosed`, that exit code would block every command, so a config that sets it runs
  `skilltotal hook cursor --fail-closed`, and there such a command gets `allow`. Whether that skips
  Cursor's own approval is not documented. Forum reports say its allowlist still decides, but we
  have not checked that in Cursor.

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

**The cost.** A hook starts before every shell command. A command that cannot install anything is
answered with nothing loaded but `json`, by the same test as the Claude Code plugin's pre-filter:
about 130 to 150 ms here, of which about 120 ms is Python starting (Windows, on a busy machine).
Anything else takes about 500 ms before a check starts.

**Gemini CLI and Antigravity CLI.** Gemini CLI's documentation says Antigravity CLI replaced it in
June 2026, but Gemini CLI 0.45.2 still runs `BeforeTool` hooks from `settings.json`. The hook has not
been tested on Antigravity CLI.

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

- Claude Code: the plugin runs it at session start and when skills or settings change. A plugin
  install fires that change, as a run confirmed at project scope.
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

## What goes over the network

Scanning itself stays offline: `scan` of a local folder, archive or file, `guard` on a file and
everything `engine.analyze` does on a folder make no network request. The hook does two things that
do:

1. **It fetches the packages a command names**, from the npm registry, PyPI, GitHub or a
   marketplace, to scan them on your machine. Those hosts see an ordinary download.
2. **For an install that names no package, it looks the lockfile up in OSV.** It sends the names and
   exact versions of public-registry packages to [OSV](https://osv.dev) (`api.osv.dev`, operated by
   Google), and nothing else: no path, project name, file content, hash, account or identifier. To
   turn it off, set `SKILLTOTAL_OSV=0`.

### The lockfile lookup

`npm ci`, `npm install` and `yarn` with no package named, `pip install -r`, `uv sync`,
`poetry install` and similar name no package to scan, but a lockfile lists every package at an exact
version, transitive ones included. OSV publishes known malicious releases under `MAL-` ids, and the
hook asks about them in one batch.

| Result | What happens |
|---|---|
| A version is listed as `MAL-...` | Denied, in and out of CI. The answer names the package, the version and the id |
| None of those looked up is listed | The console says "No known-malicious version in OSV for the N package(s) looked up" |
| OSV is unreachable or times out | The console says they were not checked, with the number. Outside CI the install goes on. In CI it is denied unless `SKILLTOTAL_ALLOW_UNCHECKED` includes `osv` |
| An entry could not be parsed, or a batch was cut short | Counted as not checked, with the number, and treated as above |

**What is sent.** A package is sent only when the install itself would fetch it from the public
registry:

1. **The lockfile records a public URL** (`registry.npmjs.org` or `registry.yarnpkg.com` for npm,
   `pypi.org` or `files.pythonhosted.org` for Python). The entry is sent, whatever else is
   configured. A scoped name (`@scope/x`) is sent too, unless an `.npmrc` maps that scope to another
   registry or holds a token for it. A token for `registry.npmjs.org` itself can reach any private
   scope there, so with one present no scoped name is sent.
2. **The lockfile records no URL.** The entry is sent only when no custom registry is configured
   anywhere the installer reads. The same scope check applies.
3. **Anything else is never sent:** another host, and git, file, link and path dependencies.

| Lockfile | Records a URL? |
|---|---|
| `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1) | Yes, `resolved`. An entry without one is not sent |
| `uv.lock` | Yes, its `source` |
| `poetry.lock` | Only for an entry with a `[package.source]` |
| `pnpm-lock.yaml`, `yarn.lock` (berry) | No, except a `tarball` |
| Requirements files | No. A `==` pin is treated as an entry with no URL. An unpinned line cannot be looked up, and is counted as not checked |

For rule 2, these count as a custom registry when they name anything but the public registry:

| Ecosystem | Where |
|---|---|
| npm, pnpm, yarn, bun | The project's and your `.npmrc` (a default or a scoped registry), `NPM_CONFIG_REGISTRY` and every `npm_config_*registry`, `YARN_REGISTRY`, `YARN_NPM_REGISTRY_SERVER`, `BUN_CONFIG_REGISTRY`, `.yarnrc`, `.yarnrc.yml` (`npmRegistryServer`, `npmScopes`), `pnpm-workspace.yaml`, `bunfig.toml` |
| Python | `pip.conf` or `pip.ini`, `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_FIND_LINKS`, `UV_INDEX_URL`, `UV_DEFAULT_INDEX`, `UV_EXTRA_INDEX_URL`, `UV_INDEX`, `UV_FIND_LINKS`, `uv.toml`, `[tool.uv]`, `[[tool.poetry.source]]` and `[[tool.pdm.source]]` in `pyproject.toml`, and `--index-url`, `--extra-index-url` and `--find-links` in the requirements file |
| Both | `--index-url`, `--extra-index-url`, `--find-links` or `--registry` on the command |

A config file too large to read, or a home folder that cannot be found, counts as configured. The
console says how many entries were not sent. `bun.lock`, `Pipfile.lock` and other formats are not
read, and the console says so.

**Limits.**

- OSV lists known malware only. A package nobody has reported yet is not on the list, and a
  brand-new malicious release will not be there.
- A lookup is not a scan of the code. "No known-malicious version" says what OSV knows and nothing
  about the package.
- `npm install` with no lockfile: transitive packages are not known until the installer resolves
  them, so OSV is not asked, and the console says so.
- `npm update` and similar choose new versions when they run, so nothing is looked up.
- Installers can resolve a version the lockfile does not hold when it is out of date.
- `guard --installed` and `watch` do not do this lookup, so they add no network request of this
  kind.

**Requests.** One batch per command, of at most 1,000 packages, for at most 5 seconds in all, with no
retry. Answers are kept for an hour by name and version in `osv-cache.json` in the
[cache folder](plugin.md#git-sources-the-verdict-cache-and-timing), so the next command sends only
what is new. There is no telemetry.

## What each surface can and cannot see

| What happens | Agent hook | Sentinel |
|---|---|---|
| The agent runs an install command | Checked before it runs | Seen afterwards |
| The agent runs a lockfile install | Looked up in OSV before it runs; code not scanned | No |
| The agent calls an MCP server (Cursor, Windsurf) | Checked on the first call | Seen in the config |
| A person types `/plugin install` | Not seen | Seen at the next sweep |
| A person uses the Extensions panel | Not seen | Seen at the next sweep |
| A plugin or extension updates itself | Not seen | Seen at the next sweep |
| `npx -y server` starts a new release | Not seen | Seen within a day |
| An agent writes a skill or `.mcp.json` itself | Not seen | Seen at the next sweep |
| A script on disk installs something | Not seen | Seen if it lands where an agent looks |

Neither is a sandbox. A hook reads a command line, and the sentinel runs after the fact. Code that
runs the moment it is installed has run by the time a sweep finds it. For code you do not trust, run
the agent in a container.

## Rolling out to a fleet

Install the CLI at a pinned version on each machine, then put the hook where a person cannot remove
it. All of these run `skilltotal`, so it must be on the `PATH` of the process that starts the agent.
Run `skilltotal hook status` on a machine to confirm it.

### Claude Code

`managed-settings.json` goes in `/Library/Application Support/ClaudeCode/` (macOS),
`/etc/claude-code/` (Linux and WSL) or `C:\Program Files\ClaudeCode\` (Windows). This enables the
plugin, which brings the hook and the sentinel, and allows no other hooks. Under
`allowManagedHooksOnly`, the hooks of a plugin that managed settings force-enable keep running.

```json
{
  "extraKnownMarketplaces": {
    "skilltotal": { "source": { "source": "github", "repo": "pezhik/skilltotal" } }
  },
  "enabledPlugins": { "skilltotal@skilltotal": true },
  "allowManagedHooksOnly": true,
  "strictKnownMarketplaces": [{ "source": "github", "repo": "pezhik/skilltotal" }]
}
```

`strictKnownMarketplaces` allows only the marketplaces it lists, so add your own. Where plugins are
not an option, use a managed hook instead. It starts Python for every command, as it lacks the
plugin's pre-filter, and it brings no sentinel:

```json
{
  "allowManagedHooksOnly": true,
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [{ "type": "command", "command": "skilltotal hook claude-code", "timeout": 900 }]
      }
    ]
  }
}
```

### Cursor

`hooks.json` goes in `/Library/Application Support/Cursor/` (macOS), `/etc/cursor/` (Linux and WSL)
or `C:\ProgramData\Cursor\` (Windows). With `failClosed`, a crash, a timeout or no output blocks the
action. That also means a machine with no working CLI can run no shell command through the agent,
so roll out the CLI first. Note `--fail-closed`, and what it means for
[`allow`](#what-each-agents-hook-sees).

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      { "command": "skilltotal hook cursor --fail-closed", "timeout": 900, "failClosed": true }
    ],
    "beforeMCPExecution": [
      { "command": "skilltotal hook cursor --fail-closed", "timeout": 900, "failClosed": true }
    ],
    "sessionStart": [{ "command": "skilltotal hook cursor", "timeout": 10 }]
  }
}
```

### Windsurf

`hooks.json` goes in `/Library/Application Support/Windsurf/` (macOS), `/etc/windsurf/` (Linux and
WSL) or `C:\ProgramData\Windsurf\` (Windows). It runs before the user's and the workspace's hooks.

```json
{
  "hooks": {
    "pre_run_command": [{ "command": "skilltotal hook windsurf", "show_output": true }],
    "pre_mcp_tool_use": [{ "command": "skilltotal hook windsurf", "show_output": true }]
  }
}
```

### VS Code Copilot

A file in `/etc/github-copilot/policy.d/` (Linux and macOS) or `C:\ProgramData\GitHub\Copilot\policy.d\`
(Windows) applies to the Copilot CLI across the machine. Copilot's cloud agent reads only
`.github/hooks/*.json` from the repository, and there `ask` counts as `deny`. A hook that crashes
denies the call, and one that times out does not.

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [{ "type": "command", "command": "skilltotal hook copilot", "timeoutSec": 900 }]
  }
}
```

### Everywhere

Schedule `skilltotal watch --quiet` on each machine and act on exit code 2. For CI, set
`SKILLTOTAL_STRICT=1` if your CI service is not one SkillTotal recognizes, and list what you allow in
`SKILLTOTAL_ALLOW_UNCHECKED` ([CI strict mode](plugin.md#ci-strict-mode)). If your policy forbids
sending package names to a third party, set `SKILLTOTAL_OSV=0` in the same place.
