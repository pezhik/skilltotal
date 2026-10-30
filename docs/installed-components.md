# Installed components

`skilltotal inventory` and `skilltotal guard --installed` check what is already installed on a
machine: the MCP servers your agents start, Claude Code plugins, skills and editor extensions.
This page covers where they look, what blocks, how to catch a malicious update with `--state`,
how to run the check daily on one machine or a fleet, and the AI-BOM export.

```bash
skilltotal inventory                          # list everything installed and scan it
skilltotal inventory --no-scan                # list only
skilltotal guard --installed                  # allow/block every installed component (exit 2 on a block)
skilltotal guard --installed --project .      # also this project's agent configs
skilltotal guard --installed --state ~/.skilltotal-state.json   # also catch risk gained in an update
skilltotal inventory --sbom                   # AI-BOM: CycloneDX 1.6 JSON
```

## The two commands

| | `inventory` | `guard --installed` |
|---|---|---|
| Answers | What is installed, and how risky is each component? | Should anything installed be removed? |
| Output | A table: host, name, kind, source, verdict, risk; then the components that need attention | One line per component (`[ok]`, `[BLOCK]`, `[ACCEPTED]`, `[RISKY]`, ...) and a last line `ALLOW:`, `BLOCK:` or `UNCHECKED:` |
| Exit code | 0 whatever it finds; 1 when it cannot run (a bad `--state` or `--accept` file, a missing `--project` folder, a state file it cannot write) | 2 when a component blocks; else 1 when a component could not be checked or none was found (`--allow-unchecked` turns that into 0), or when it cannot run; else 0. With `--write-accept`, 0 once the file is written |
| Formats | text, `--json`, `--sbom` | text, `--json` |

Use `inventory` to see the stack and to export it. Use `guard --installed` as the check that fails:
in a scheduled job, a login script or a fleet tool. Both apply the same decision to each
component, so `inventory` shows a component as blocked exactly when `guard --installed` would
block it at its default level.

Both read configuration files and folders and never start a server or an editor. Flags for both
are in the [CLI reference](cli.md#inventory); the JSON they print is in
[Output formats](report-schema.md#inventory-and-guard---installed-json).

## Where they look

| Kind | Host | Read from |
|---|---|---|
| MCP server | Claude Code | `~/.claude.json` (user-scope servers, and local-scope servers per project; also `$CLAUDE_CONFIG_DIR/.claude.json`) |
| MCP server | Claude Code (managed) | An organization's `managed-mcp.json` in `/Library/Application Support/ClaudeCode`, `/etc/claude-code` or `C:\Program Files\ClaudeCode` |
| MCP server | Claude Desktop | `claude_desktop_config.json` in `%APPDATA%\Claude`, `~/Library/Application Support/Claude` or `~/.config/Claude` |
| MCP server | Cursor | `~/.cursor/mcp.json` |
| MCP server | Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| MCP server | VS Code | The user `mcp.json` and `settings.json` (`mcp.servers`) of VS Code and VS Code Insiders |
| MCP server | Gemini CLI | `~/.gemini/settings.json` |
| Plugin | Claude Code plugins | The plugins Claude Code installed (`~/.claude/plugins`). A plugin is scanned as one component (its hooks, skills, commands and server code), and the MCP servers it starts are listed too |
| Skill | Claude skills | Each folder in `~/.claude/skills` (or `$CLAUDE_CONFIG_DIR/skills`) |
| Editor extension | VS Code, VS Code Insiders, Cursor, Windsurf, VSCodium | `~/.vscode/extensions`, `~/.vscode-insiders/extensions`, `~/.cursor/extensions`, `~/.windsurf/extensions`, `~/.vscode-oss/extensions`, and the folder `VSCODE_EXTENSIONS` names |
| Editor extension | VS Code Server, VSCodium Server, Cursor Server | `~/.vscode-server/extensions`, `~/.vscodium-server/extensions`, `~/.cursor-server/extensions` (remote development hosts) |

With `--project DIR` they also read that project's `.mcp.json`, `.cursor/mcp.json`,
`.vscode/mcp.json` and `.claude/skills`. A project skill folder that links outside the project is
listed and not scanned. Claude Code's `~/.claude/settings.json` is not read: it holds permissions
and hooks, not server definitions.

## How each MCP server is checked

A server's launch command is read by the same parser the Claude Code plugin uses, which derives
what to scan: `npx -y some-server@1.2.3` becomes `npm:some-server@1.2.3`, `uvx some-server`
becomes `pypi:some-server`, a `git+https://` source a git URL, and `node ./server.js` the local
folder. A server that cannot be scanned is listed with the reason:

| Decision | Meaning | Counts as checked |
|---|---|---|
| `remote` | Reached at a URL: there is no code on this machine to scan | No |
| `risky` | Its launch command runs a downloaded script (`curl ... \| sh`) each time it starts | No |
| `not scanned` | Nothing scannable could be derived (an unsupported launcher, a container image, a link out of the extensions folder) | No |
| `error` | The scan failed (the package could not be fetched, a size limit) | No |
| `this scanner` | SkillTotal's own MCP server (`skilltotal mcp`) | Yes |

An inline secret in a config entry (an `env` value, an `Authorization` header, a key in a URL) is
reported, redacted.

## What blocks

A component blocks when any of these holds, at every `--block-on` level:

- it has a malicious indicator;
- a script it runs at install time could not be read, or nothing in it could be read;
- its name is a letter or two away from a popular npm or PyPI package (not checked for editor
  extensions, which an editor installs by marketplace id, not by the name in their `package.json`);
- with `--state`, it was updated and the update added a malicious indicator or a high or critical
  risky construct ([drift](#catching-a-malicious-update)).

Its risk level also blocks at or above the block level: `high` (high or critical risk) for MCP
servers, plugins and skills, and `malicious` (risk level alone never blocks) for editor
extensions. Large, legitimate extensions that bundle a language server or a debugger score high
on the risky constructs in their bundled code, so `high` would block widely used extensions on
every machine that has them. `--block-on LEVEL` sets one level for every kind. Capabilities alone
never block.

## Editor extensions

Each extension folder with its own `package.json` is one component, named `publisher.name@version`
from that manifest. Folders the editor marked for deletion in `.obsolete`, dot folders and
`extensions.json` are left out: the editor does not load them. An extension folder that links to a
folder outside the extensions folder is listed and not scanned.

An extension is scanned as a `vscode_extension` component: the entry points its `package.json`
names (`main`, `browser` and the others) are read up to 8 MiB even when minified, which is where
a loader added to a bundle sits. Scanning takes time: a machine with a few large extensions (language servers that
ship thousands of type-stub files) can take 15 minutes or more. Run the check daily rather than at
every login. `--no-extensions` leaves extensions out of both commands.

Extensions in a folder an editor was started with (`--extensions-dir`), or in a portable
install's own folder, are not read: that setting exists only inside the editor's process.

## Catching a malicious update

An editor extension updates itself from its marketplace, and an MCP server started with
`npx -y some-server` runs the latest release, so no install command runs that the Claude Code
plugin could check. A scheduled run with `--state FILE` catches such an update the next time it
runs:

1. Each run records every component's version and the fingerprints of its risk findings
   (malicious indicators and risky constructs; capabilities are not recorded) in `FILE`.
2. A component whose version changed and that gained risk findings it did not have before is
   reported as **drift**, with the new rule ids: a `drift:` line in the text, a `drift` object in
   the JSON and a `skilltotal:drift` property in the AI-BOM.
3. Drift that adds a malicious indicator or a high or critical risky construct blocks, whatever
   the block level. Other drift is reported and does not block.

The first run only records. The state file holds component names, versions and fingerprint
hashes, nothing from the scanned files. A file that is not a SkillTotal state file stops the
command with exit 1 and is left as it is; a state file that cannot be written also exits 1.
Components not scanned in a run (a scan error, `--no-extensions`) keep their previous entry.
`--state` with `inventory --no-scan` is an error.

```bash
skilltotal inventory --json --state ~/.skilltotal-state.json
skilltotal guard --installed --state ~/.skilltotal-state.json
```

Drift does not see a change that keeps the version number. A new SkillTotal release with new
rules, installed on the day a component updates, can report drift from those rules.

## Running it every day

The log of each run ends with a `BLOCK:`, `UNCHECKED:` or `ALLOW:` line; exit code 2 means a
component blocked.

Linux and macOS, with cron (`crontab -e`). cron has a short `PATH`, so use the full path that
`which skilltotal` prints:

```bash
0 9 * * * /usr/local/bin/skilltotal guard --installed --state "$HOME/.skilltotal-state.json" >> "$HOME/skilltotal-guard.log" 2>&1
```

Windows, with Task Scheduler:

```powershell
schtasks /Create /SC DAILY /ST 09:00 /TN "SkillTotal guard" /TR "cmd /c skilltotal guard --installed --state %USERPROFILE%\skilltotal-state.json >> %USERPROFILE%\skilltotal-guard.log 2>&1"
```

macOS, with launchd: save this LaunchAgent as `~/Library/LaunchAgents/ai.skilltotal.guard.plist`
and load it with `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.skilltotal.guard.plist`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>ai.skilltotal.guard</string>
  <key>ProgramArguments</key><array>
    <string>/bin/sh</string><string>-c</string>
    <string>/usr/local/bin/skilltotal guard --installed --state "$HOME/.skilltotal-state.json" >> "$HOME/skilltotal-guard.log" 2>&amp;1</string>
  </array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>9</integer></dict>
</dict></plist>
```

## Running it on a fleet

Run `skilltotal guard --installed --json --state FILE` from your fleet or MDM tool on each
machine, **as the signed-in user**. The command reads that user's home folder, so a job running as
root or SYSTEM sees root's or SYSTEM's components, not the user's. Keep one state file per user.

- **Alert on the exit code.** 2: a component blocked. 1: something could not be checked (a remote
  server, a scan error), none was found, or the state or accept file could not be used. Add
  `--allow-unchecked` if only blocks should alert.
- **Send the JSON to your SIEM.** It is one object per component with `host`, `name`, `kind`,
  `source`, `decision`, `risk_level`, `reasons`, and `drift` or `accepted` when they apply
  ([field reference](report-schema.md#inventory-and-guard---installed-json)). Accept-file
  warnings go to stderr: keep stderr in the log.
- **Keep an asset record.** `skilltotal inventory --sbom` writes the same components as a
  CycloneDX AI-BOM ([below](#ai-bom)).

### Sharing an accept file

When a component blocks on a false positive, accept it rather than turn the job off. Keep one
accept file for the team in a git repository:

1. On a machine that shows the block, run the job's command with `--write-accept accept.json`.
   It adds an entry for each blocked component, with an empty `reason`.
2. Open a pull request with the new entries. A reviewer fills in each `reason` (and an `expires`
   date) before it merges; the file is refused while any reason is empty.
3. Ship the reviewed file with the job, the way you ship its command, and add `--accept`:

```bash
skilltotal guard --installed --json --state ~/.skilltotal-state.json --accept /opt/skilltotal/accept.json
```

An entry covers one component at one exact version, so the next update is checked again. Each run
names every accepted malicious indicator, expired entry and stale entry on stderr. The file format
and the rules are in [Accepting findings](accepting-findings.md#accept-file).

## AI-BOM

`skilltotal inventory --sbom` prints the inventory as a CycloneDX 1.6 JSON document: one
`application` component per installed component, with a `purl` for `npm:` and `pypi:` sources
(and a `version` when the source pins one; an editor extension gets its manifest version), and the scan result as
`skilltotal:*` properties (`skilltotal:verdict`, `skilltotal:risk_level`, `skilltotal:drift`,
`skilltotal:accepted`, ...; the full list is in
[Output formats](report-schema.md#ai-bom-properties)). Any CycloneDX consumer can read it, such as
OWASP Dependency-Track or an asset inventory that imports SBOMs.

```bash
skilltotal inventory --sbom --state ~/.skilltotal-state.json > aibom.json
```

The AI-BOM, like the other outputs, describes the machine it ran on. Run it as the user whose
components you want to record.
