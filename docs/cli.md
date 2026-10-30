# CLI reference

Installing the `skilltotal` command, its commands and flags, the exit codes and the status
badge. The [README](../README.md) has the short version.

## Install

Requires **Python 3.10+**. Zero runtime dependencies. `git` is required only for scanning
remote URLs and for `scan --staged`.

For the CLI, [pipx](https://pipx.pypa.io) is recommended. It installs into an isolated environment
and also works on Debian/Ubuntu and Homebrew Python, where PEP 668 blocks a bare `pip install`:

```bash
pipx install skilltotal
```

If `skilltotal` is not found afterwards, run `pipx ensurepath` and open a new terminal. On a fresh
Linux machine, pipx's folder is not on `PATH` yet.

To install into a virtual environment, or to use it as a library:

```bash
pip install skilltotal
```

You can also run it with npx. The npm package only starts this engine, so it needs uv, pipx, or
Python 3.11+ with `skilltotal` installed. With uv or pipx it runs the PyPI release that matches
the npm version; when it falls back to an installed Python `skilltotal` of another release, it
says so on stderr. Name the release with `--package`: a plain `npx skilltotal` run inside a
repository first runs any `skilltotal` program in that repository's `node_modules/.bin`, and a
repository you are about to scan can ship one (with `--package`, npx runs only that exact release;
`uvx` does not look in the folder at all).

```bash
npx -y --package=skilltotal@0.87.0 -- skilltotal scan https://github.com/owner/repo
```

From source (development):

```bash
pip install -e ".[dev]"
```

**Running it inside a directory you don't trust** (a checkout you are about to scan): use the
`skilltotal` console script or `python -P -m skilltotal ...` (Python 3.11+). Plain `python -m`
puts the current directory first on the import path, so a `json.py` or `skilltotal/` planted there
would run instead of the standard library or the engine.

## Usage

```bash
# Human-readable report
skilltotal scan ./path/to/component

# Scan a remote repository (shallow git clone), or one folder of it at a ref
skilltotal scan https://github.com/owner/repo
skilltotal scan https://github.com/owner/repo/tree/main/src/server

# Scan a project archive or a single file (e.g. an AI-generated project downloaded as a ZIP)
skilltotal scan ./my-project.zip
skilltotal scan ./app.tar.gz
skilltotal scan ./suspicious.py

# Scan a package from a registry (latest, or a pinned version)
skilltotal scan npm:left-pad
skilltotal scan npm:left-pad@1.3.0
skilltotal scan pypi:requests
skilltotal scan pypi:requests==2.31.0

# JSON to stdout
skilltotal scan ./component --json

# SARIF 2.1.0 (GitHub Code Scanning / IDE) to a file; the console gets a short summary
skilltotal scan ./component --sarif --output report.sarif

# Write the report to a file (SARIF if --sarif, else JSON); the folder must exist
skilltotal scan ./component --output report.json

# SARIF for a subfolder: repository-root paths and a Code Scanning category of its own
skilltotal scan ./services/agent --sarif --output agent.sarif --sarif-uri-prefix services/agent --sarif-category skilltotal/agent

# CI gate: exit code 2 by finding severity (low, medium, high, critical) or by risk score
skilltotal scan ./component --fail-on-high             # alias for --fail-on high
skilltotal scan ./component --fail-on medium
skilltotal scan ./component --fail-on-score 50
# ...or when part of the component could not be analyzed: unreadable, too large or unparseable
# files, or code in a language SkillTotal does not analyze (binaries and dependency folders don't count)
skilltotal scan ./component --fail-on-unanalyzed
# Report only: no gate at all, also none from the config
skilltotal scan ./component --fail-on none
# Use the config's gate when it sets one, else this level (for wrappers)
skilltotal scan ./component --fail-on-default high

# Skip paths (repeatable; combined with the config file's `exclude`)
skilltotal scan ./component --exclude "vendor/*" --exclude "*.min.js"

# Scan what the next commit will contain (git's index), as the pre-commit hook does
skilltotal scan . --staged --fail-on-high

# Use a config file from another place, or ignore any .skilltotal.toml in the current directory
skilltotal scan ./component --config ci/skilltotal.toml
skilltotal scan ./component --no-config

# Opt-in provenance for npm:/pypi: sources (registry metadata -> needs_review, never scored)
skilltotal scan npm:some-lib --provenance

# Baseline: snapshot current findings (exits 0), then suppress them on later scans
skilltotal scan ./component --write-baseline .skilltotal-baseline.json
skilltotal scan ./component --baseline .skilltotal-baseline.json --fail-on-high

# Diff two versions of a component: what changed between them?
# Each side is any scannable source (path/archive/git/npm:/pypi:) or a saved --json report.
skilltotal diff npm:some-lib@1.2.3 npm:some-lib@1.2.4
skilltotal diff ./old-checkout ./new-checkout --json
skilltotal diff old-report.json new-report.json
# CI gate: fail (exit 2) if the new version INTRODUCES a high/critical finding
skilltotal diff npm:some-lib@1.2.3 npm:some-lib@1.2.4 --fail-on-new high
# ...or has a part the scan could not analyze that the old version did not
skilltotal diff npm:some-lib@1.2.3 npm:some-lib@1.2.4 --fail-on-new high --fail-on-unanalyzed

# Pre-install guard: allow/block decision (exit 2 on block) you can chain before installing
skilltotal guard npm:some-mcp-server && claude mcp add some-mcp-server -- npx some-mcp-server
skilltotal guard npm:x --block-on malicious   # block only on malicious indicators
skilltotal guard --installed                  # check the MCP servers, plugins, skills and editor extensions
skilltotal guard --installed --allow-unchecked  # exit 0 even if some could not be checked
skilltotal guard --installed --state ~/.skilltotal-state.json  # also catch risk gained in an update
skilltotal guard --installed --write-accept accept.json  # draft entries for what blocks (exits 0)
skilltotal guard --installed --accept accept.json  # accept reviewed false positives

# Inventory: list the MCP servers, plugins, skills and editor extensions installed, and scan them
skilltotal inventory
skilltotal inventory --json
skilltotal inventory --no-scan          # list only, do not scan
skilltotal inventory --no-extensions    # leave out editor extensions (their scan takes minutes)
skilltotal inventory --project .        # also include this project's agent configs
skilltotal inventory --sbom             # AI-BOM: CycloneDX 1.6 JSON of your agent stack,
                                        # scan verdicts attached as component properties

# List every detection rule
skilltotal rules list
skilltotal rules list --json
```

`scan` on its own exits 0 whatever it finds, even for a malicious verdict. In a script, use
`skilltotal guard` or a gate (`--fail-on`) and check the exit code. With `--output FILE`, the full
report goes to the file and the console gets a short summary: the verdict, the risk, the finding
counts, any gate lines and `Full report: FILE`. Options must be spelled out in full: `--out` is
an error, not `--output`.

**Baseline** suppresses findings by a stable fingerprint of
`(rule id, file, code snippet)`, independent of line numbers, so it survives edits.
Suppressed findings are removed before scoring and do not affect the risk score. Writing a baseline
is how you adopt the tool on existing code: `--write-baseline` writes the file and exits 0,
whatever it found, and warns on stderr when the baseline accepts a malicious indicator. A scan
with a baseline says how many occurrences it suppressed on a `Baseline  :` line; when the baseline
hides a malicious indicator, that line names the rule, the CLI warns on stderr (so a CI log shows
it even with `--json` or `--sarif`), and the report's `metadata.baseline_suppressed_malicious`
lists it. The verdict and the exit-code gates do not see a hidden finding.

**Diff** reports new / resolved / changed findings, evidence-level additions and removals
(matched by the same line-independent fingerprint as the baseline, so pure line shifts are
not noise), capability changes, and the risk-score delta. `--fail-on-new LEVEL` gates only
on risk the new version *introduces*, counted like `scan --fail-on` (a malicious indicator at any
severity, never a capability on its own). Existing accepted findings never trip it, so it fits
upgrade reviews ("is 1.2.4 riskier than the 1.2.3 we already vetted?") without a baseline file.
A second copy of a line the old version already had counts as new evidence. A finding can also
disappear because the new version's scan could not read the file it was in (too large, minified,
unparseable): the diff lists those parts as `coverage_gaps_added` (JSON) and under "Not analyzed
in the new version only" (text), and `--fail-on-unanalyzed` exits 2 on them. A side given as a
saved `--json` report is not scanned: its findings are taken as the file states them, and the
console says so. In CI, scan both sides rather than accept a report file from the change under
review.

**Guard** is the install-time answer to "should I trust this component right now?".
Malicious indicators always block; scored risk at/above `--block-on` blocks;
**capabilities alone never block**: a legitimate MCP server with shell/network access
passes, so the guard stays quiet enough to leave enabled everywhere. Unlike `--fail-on`, it
weighs the aggregate risk level rather than single findings. It also does not block a package for
a secret it ships: that puts the publisher at risk, not the person installing the package.

**Inventory and `guard --installed`** read agent configuration files and never start a server:
`~/.claude.json` (Claude Code's user-scope servers and its local-scope servers per project), the
Claude Code plugins you installed, an organization's Claude Code `managed-mcp.json` (in
`/etc/claude-code`, `/Library/Application Support/ClaudeCode` or `C:\Program Files\ClaudeCode`),
Claude Desktop, Cursor (`~/.cursor/mcp.json`), Windsurf, VS Code
(the user `mcp.json` and `settings.json` `mcp.servers`) and Gemini CLI configs, and the skills in
`~/.claude/skills`. With `--project DIR` they also read that project's `.mcp.json`,
`.cursor/mcp.json`, `.vscode/mcp.json` and `.claude/skills`. They also list the editor extensions
installed in `~/.vscode/extensions` (or the folder `VSCODE_EXTENSIONS` names),
`~/.vscode-insiders/extensions`, `~/.cursor/extensions`, `~/.windsurf/extensions`,
`~/.vscode-oss/extensions` (VSCodium) and the remote-server folders `~/.vscode-server/extensions`,
`~/.vscodium-server/extensions` and `~/.cursor-server/extensions`: one entry per extension folder
with a `package.json`, named `publisher.name@version`, leaving out the folders the editor marked
for deletion in `.obsolete`. Claude Code's `~/.claude/settings.json`
is not read: it holds permissions and hooks, not server definitions. Each server's launch command
is read by the same parser as the plugin hook, which derives the `npm:`, `pypi:`, git or local
source to scan. A launcher that pipes a download into a shell is marked risky, a remote (URL)
server cannot be scanned, and an inline secret in a config entry (an `env` value, an
`Authorization` header, a key in a URL) is reported redacted. `guard --installed` exits 2 when a
component blocks, else 1 when any component could not be checked (a scan error, a remote or
unsupported server, a risky launcher) or none was found; `--allow-unchecked` turns that 1 into 0.

An editor extension blocks only on malicious indicators unless you pass `--block-on`: large,
legitimate extensions that bundle a language server or a debugger score high on the risky
constructs in their bundled code, so the default `high` would block widely used extensions on
every machine that has them. The typosquatting check does not apply to them: an editor installs an
extension by its marketplace id, not by the name in its `package.json`.

### Accepting a reviewed false positive

`scan` accepts findings through a baseline; `guard` (both forms) and `inventory` take an **accept
file** instead, `--accept FILE`. Each entry accepts the findings it lists for one component at one
exact version:

```json
{
  "format": "skilltotal-accept",
  "version": 1,
  "accepted": [
    {
      "component": "VS Code|editor_extension|acme.quillwidget",
      "version": "1.4.2",
      "findings": ["3f9c2a7e1b6d4c08"],
      "rules": ["ST-OBF-DECODE-EXEC"],
      "reason": "Decodes a bundled test fixture; reviewed in SEC-123, nothing runs it",
      "accepted_by": "security team",
      "expires": "2027-03-31"
    }
  ]
}
```

- `component` is `host|kind|name` for an installed component (the host, kind and name the
  inventory prints, without an extension's `@version`), and for `guard <source>` the source:
  `npm:<name>` or `pypi:<name>` without its version, anything else as written.
- `version` is the exact version scanned (`""` for a component that has none, such as a skill
  folder). An update is judged afresh, so a trojanized update of an accepted extension still blocks.
- `findings` are the fingerprints of the accepted evidence (the baseline's: rule id, file and
  snippet). A new finding in the same version is judged as usual. `rules` is for the reader only.
- `reason` is required; `accepted_by` and `expires` (valid through that day) are optional.

Accepted evidence is removed before scoring, so the score, verdict and decision are those of the
rest. Nothing disappears silently: `guard --installed` marks the component `[ACCEPTED]` and prints
the rules, count and reason, `guard <source>` adds an `Accepted  :` line, the JSON gets an
`accepted` object (`rules`, `count`, `reason`, `expires`, `accepted_by`) and the AI-BOM a
`skilltotal:accepted` property. Every run warns on stderr when an accepted finding is a malicious
indicator, names expired entries (which no longer apply), and lists stale entries (no component
matched at that version). A file that is not valid (not JSON, wrong `format` or `version`, an
unknown key, an empty `reason`, a malformed fingerprint or date) is an error, exit 1, and nothing
is scanned.

To write the entries, run `--write-accept FILE`: it adds one entry for each component the run
blocks (`guard`) or flags as high risk, malicious or blocked (`inventory`), with the fingerprints
of its risk findings and an empty `reason`, and exits 0. The file is refused until a reviewer
fills in every reason. It adds to an existing accept file and never overwrites any other file.
An accepted finding is not drift, and `--state` still records it, so the state file is the same
as without `--accept`.

A combination finding (`ST-COMBO-EXFIL`, `ST-FLOW-TRIFECTA`, `ST-INSTALL-DROPPER`,
`ST-CONVERGENCE`) follows its inputs: it disappears when they are accepted and keeps firing while
they are present, even if its own fingerprints are listed. A finding capped out of the report can
appear once the shown ones are accepted; accept it the same way. A block that is not a finding (an
install script that could not be read) cannot be accepted.

### Catching a malicious editor extension update

An editor extension updates itself from its marketplace, so no install command runs that the
Claude Code hook could check. A scheduled `guard --installed` run catches a bad update the next
time it runs. With `--state FILE`, each run records every component's version and the
fingerprints of its risk findings (the same fingerprints as a baseline; capabilities are not
recorded), and compares them with the last run. A component whose version changed and that gained
risk findings it did not have before is reported as **drift**, with the new rule ids (text, JSON
`drift` and the AI-BOM's `skilltotal:drift` property). The guard blocks drift that adds a malicious
indicator or a high or critical risky construct. The first run only records. The state file holds
component names, versions and fingerprint hashes, nothing from the scanned files. A file that is
not a state file is an error and is left as it is.

Scanning extensions takes time: on one developer machine, the 9 installed extensions took about
15 minutes, most of it one language extension's 7,500 type-stub files. Run it daily, not on every login;
`--no-extensions` leaves them out.

For one machine, run it once a day and keep the state file:

```bash
# Linux and macOS (crontab -e). cron has a short PATH: use the full path `which skilltotal` prints.
0 9 * * * /usr/local/bin/skilltotal guard --installed --state "$HOME/.skilltotal-state.json" >> "$HOME/skilltotal-guard.log" 2>&1
```

```powershell
# Windows Task Scheduler
schtasks /Create /SC DAILY /ST 09:00 /TN "SkillTotal guard" /TR "cmd /c skilltotal guard --installed --state %USERPROFILE%\skilltotal-state.json >> %USERPROFILE%\skilltotal-guard.log 2>&1"
```

On macOS, launchd works as well: save a LaunchAgent at
`~/Library/LaunchAgents/ai.skilltotal.guard.plist` and load it with
`launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.skilltotal.guard.plist`.

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

The log ends with a `BLOCK:`, `UNCHECKED:` or `ALLOW:` line; exit code 2 means a component
blocked.

For a company, run `skilltotal guard --installed --json --state FILE` from your fleet or MDM tool
on each machine, **as the signed-in user**: the command reads that user's home folder, so a job
running as root or SYSTEM sees root's or SYSTEM's extensions, not the user's. Keep one state file
per user on the machine. Treat a non-zero exit as an alert (2: a component blocked; 1: something
could not be checked, or the state file could not be used) and send the JSON to your SIEM: one
object per component with `host`, `name`, `kind`, `decision`, `reasons` and, after an update that
added risk, `drift`.

When a component blocks on a false positive, accept it rather than turn the job off. Keep one
accept file for the team in a git repository: on a machine that shows the block, run the job's
command with `--write-accept accept.json`, open a pull request with the new entries, and have a
reviewer fill in each `reason` (and an `expires` date) before it merges; the file is refused while
any reason is empty. Ship the reviewed file with the job, the way you ship its command, and add
`--accept /path/to/accept.json`, for example
`skilltotal guard --installed --json --state FILE --accept /opt/skilltotal/accept.json`. Each run
then names every accepted malicious indicator, expired entry and stale entry on stderr, so the
log shows what the file still covers.

**Provenance** (`--provenance`, opt-in) adds registry-metadata signals for `npm:` /
`pypi:` sources: *recently published*, *deprecated / yanked*, *no recent releases*, *no
repository link*. Metadata is context about a component, not component content, so these
signals go to `needs_review` and **never** affect the score or verdict, and the default
scan stays component-only.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success: no gate tripped. Also after `--write-baseline` or `--write-accept` has written its file (no gate is applied) |
| 1 | Usage, config or collection error (for example an unknown or abbreviated flag, an invalid `.skilltotal.toml` or an unknown rule id in it, an invalid `--accept` file, a missing path, an `--output` folder that does not exist, a failed clone, a source over a size limit). `guard --installed` also exits 1 when a component could not be checked or none was found, unless `--allow-unchecked` is given |
| 2 | A configured gate tripped (`--fail-on`/`--fail-on-high` severity, `--fail-on-score`, `--fail-on-unanalyzed`, a `block` policy or `diff --fail-on-new`/`--fail-on-unanalyzed`), or `guard` blocked a component |

When a gate trips, stderr gets one `gate:` line per gate, naming the gate, the finding that
tripped it and why it counts, for example
`gate: --fail-on high tripped by ST-COMBO-EXFIL (index.js:7), severity critical and 1 more` or
`gate: fail_on = "critical" in .skilltotal.toml tripped by ST-INSTALL-NPM-REMOTE-EXEC
(package.json:1), a malicious indicator`.

> **Gate semantics:** `--fail-on`/`--fail-on-high` trip on the **severity of a single finding**,
> not the aggregate `risk_score`. They count risk findings: a malicious indicator at any severity,
> and a risky construct or a shipped secret at or above the level you set. A *capability*, such as
> shell or network access, is what a component can do. It is reported but never trips the gate on
> its own; to forbid one, give its rule a `block` policy. The gate also fails closed on what the
> scan could not read: an install script it could not analyze, or a component with nothing it
> could read. A component can therefore report `risk_level: low` and still fail the gate on one
> high-severity risky construct. To gate on the score instead, use `--fail-on-score`; to accept
> known findings, use a baseline, an inline `# skilltotal:ignore[ST-ID]`, or a per-rule `[policy]`
> action (`block` / `warn` / `ignore`). `--fail-on none` turns off every gate the config sets
> (`fail_on`, `fail_on_score`, `fail_on_unanalyzed`, `block` policies); gate flags given on the
> same command line still apply.

## Status badge

Scan a component on [skilltotal.ai](https://www.skilltotal.ai) and each report offers an
**"Add this badge"** snippet: a small SVG that reflects the website's latest public scan of that
component and links back to the full report.

```markdown
[![SkillTotal](https://www.skilltotal.ai/badge?source=npm:your-package)](https://www.skilltotal.ai)
```

The badge comes from the website's scan, not from your CI, so it works only for components the
website can fetch: published npm/PyPI packages and public repositories. Copy the exact markdown
from the report page; it fills in the badge URL for you.
