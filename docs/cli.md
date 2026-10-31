# CLI reference

Every `skilltotal` command and flag, the sources it reads, the exit codes and the gates. The
[README](../README.md) has the short version.

| Command | What it does |
|---|---|
| [`scan <source>`](#scan) | Scan one component and print a report; gate CI on it |
| [`diff <old> <new>`](#diff) | What changed between two versions; gate an upgrade on new risk |
| [`guard <source>`](#guard) | Allow or block one component before you install it (exit 2 on a block) |
| [`guard --installed`](#guard) | Allow or block everything installed on this machine |
| [`inventory`](#inventory) | List and scan what is installed; export an AI-BOM |
| [`rules list`](#rules-list) | List the detection rules |
| [`mcp`](#mcp) | Run SkillTotal as an MCP server for your agent |
| [`hook claude-code`](#hook-claude-code) | The Claude Code plugin's install check |

`skilltotal --version` prints the version, and `skilltotal <command> --help` the flags of a
command. Options must be spelled out in full: `--out` is an error, not `--output`. A usage error
exits 1.

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
npx -y --package=skilltotal@0.88.0 -- skilltotal scan https://github.com/owner/repo
```

From source (development):

```bash
pip install -e ".[dev]"
```

**Running it inside a directory you don't trust** (a checkout you are about to scan): use the
`skilltotal` console script or `python -P -m skilltotal ...` (Python 3.11+). Plain `python -m`
puts the current directory first on the import path, so a `json.py` or `skilltotal/` planted there
would run instead of the standard library or the engine.

**Offline.** A local folder, archive or file is scanned without any network request, so the CLI
works air-gapped: download a pinned wheel on a connected machine
(`pip download skilltotal==0.88.0 --no-deps`), copy it over and `pip install` the file. `npm:`,
`pypi:` and git sources need the network, or a [registry mirror](configuration.md#scanning-through-a-registry-mirror).

## Sources

`scan`, `diff`, `guard` and the MCP server's `scan_component` accept the same sources:

| Source | Example | Notes |
|---|---|---|
| A local folder | `./path/to/component` | |
| A git URL | `https://github.com/owner/repo` | A shallow clone. `/tree/<ref>/<path>` scans one folder at a ref |
| An npm package | `npm:left-pad`, `npm:left-pad@1.3.0`, `npm:@scope/name@next` | The latest release, a version or a dist-tag |
| A PyPI package | `pypi:requests`, `pypi:requests==2.31.0` | One file of the release: a pure-Python wheel when there is one |
| An archive | `./project.zip`, `./app.tar.gz` | `.zip`, `.tar.gz`, `.tgz`, `.tar`, `.tar.bz2`, `.tar.xz`, and any other file that starts with the zip signature |
| A packaged extension or wheel | `./server.mcpb`, `./ext.vsix`, `./pkg-1.0-py3-none-any.whl` | Claude Desktop extensions (`.mcpb`, `.dxt`), VS Code extensions (`.vsix`) and Python wheels are unpacked and scanned like a folder |
| A single file | `./suspicious.py` | |

Archives are unpacked into a temporary folder with size and entry limits
([environment variables](configuration.md#environment-variables)). Links and devices in an
archive are left out, and an entry that would land outside the folder stops the scan. Scan a
downloaded extension or wheel before you install it:

```bash
skilltotal scan ./downloads/some-server.mcpb
skilltotal scan ./downloads/some-extension.vsix
skilltotal guard ./downloads/some-extension.vsix
```

## scan

Scans one component and prints a report. With no gate flag and no gate in a `.skilltotal.toml`,
`scan` exits 0 whatever it finds, even for a malicious verdict. In a script, use a gate
(`--fail-on`) or [`guard`](#guard) and check the exit code.

```bash
skilltotal scan ./path/to/component
skilltotal scan https://github.com/owner/repo/tree/main/src/server
skilltotal scan npm:left-pad@1.3.0
skilltotal scan pypi:requests==2.31.0
skilltotal scan ./component --json
skilltotal scan ./component --sarif --output report.sarif
skilltotal scan ./component --fail-on high
skilltotal scan ./component --fail-on-score 50 --fail-on-unanalyzed
skilltotal scan ./component --exclude "vendor/*" --exclude "*.min.js"
skilltotal scan . --staged --fail-on-high
skilltotal scan ./component --write-baseline .skilltotal-baseline.json
skilltotal scan ./component --baseline .skilltotal-baseline.json --fail-on-high
skilltotal scan npm:some-lib --provenance
skilltotal scan ./services/agent --sarif --output agent.sarif --sarif-uri-prefix services/agent --sarif-category skilltotal/agent
```

| Flag | What it does |
|---|---|
| `--json` | Print the JSON report ([format](report-schema.md)) instead of text |
| `--sarif` | Print SARIF 2.1.0 instead of text, for GitHub Code Scanning and IDEs |
| `--output FILE` | Write the report to `FILE` (SARIF with `--sarif`, else JSON). The console then gets a short summary: the verdict, the risk, the finding counts, any gate lines and `Full report: FILE`. The folder must exist. A `FILE` that is a link, or a linked folder between the working directory and it, is refused |
| `--sarif-uri-prefix PATH` | Put `PATH` in front of every SARIF location, such as the scanned folder relative to the repository root, so Code Scanning alerts point at real files |
| `--sarif-category NAME` | Set the SARIF Code Scanning category, so two scans uploaded from one job keep their alerts apart |
| `--fail-on LEVEL` | Exit 2 on a risk finding at or above `low`, `medium`, `high` or `critical` ([gate semantics](#gates)). `none` turns off every gate the config sets |
| `--fail-on-high` | Same as `--fail-on high` |
| `--fail-on-score N` | Exit 2 when the risk score is `N` (0-100) or more |
| `--fail-on-unanalyzed` | Exit 2 when part of the component could not be analyzed: a file too large, minified, unreadable or unparseable, or code in a language whose behavior is not analyzed. Binaries and dependency folders do not count |
| `--fail-on-default LEVEL` | The `--fail-on` level to use only when no gate flag is given and the config sets no `fail_on` or `fail_on_score`; for wrappers such as the GitHub Action |
| `--exclude GLOB` | Skip matching paths (repeatable; added to the config's `exclude`) |
| `--staged` | Scan what the next commit will contain (git's index), not the working tree; untracked and ignored files are left out. The pre-commit hook uses it |
| `--config FILE` | Read this `.skilltotal.toml` instead of the one in the current directory |
| `--no-config` | Ignore any `.skilltotal.toml` |
| `--baseline FILE` | Drop the findings this baseline lists before scoring ([baseline](accepting-findings.md#baseline)) |
| `--write-baseline FILE` | Write a baseline of the current findings and exit 0, with no gate applied |
| `--provenance` | For `npm:` and `pypi:` sources, also read registry metadata and add *recently published*, *deprecated / yanked*, *no recent releases* and *no repository link* to `needs_review`. These never change the score or the verdict |

`--json` and `--sarif` exclude each other, and so do `--config` and `--no-config`. A
`.skilltotal.toml` in the current directory is applied unless you pass `--no-config`, and the
report names it ([Configuration](configuration.md#project-config)). Inline
`skilltotal:ignore[ST-ID]` markers count when the source is a local folder
([Accepting findings](accepting-findings.md#inline-marker)).

## diff

Compares two versions of a component. Each side is any [source](#sources), or a report saved with
`scan --json`.

```bash
skilltotal diff npm:some-lib@1.2.3 npm:some-lib@1.2.4
skilltotal diff ./old-checkout ./new-checkout --json
skilltotal diff old-report.json new-report.json
skilltotal diff npm:some-lib@1.2.3 npm:some-lib@1.2.4 --fail-on-new high
skilltotal diff npm:some-lib@1.2.3 npm:some-lib@1.2.4 --fail-on-new high --fail-on-unanalyzed
```

| Flag | What it does |
|---|---|
| `--json` | Print the diff as JSON ([format](report-schema.md#diff-json)) |
| `--output FILE` | Also write the diff to `FILE` as JSON |
| `--fail-on-new LEVEL` | Exit 2 when the new version adds a risk finding, or new evidence of one, at or above `LEVEL`. Counted like `scan --fail-on`: a malicious indicator at any severity, never a capability on its own |
| `--fail-on-unanalyzed` | Exit 2 when the new version has a part the scan could not analyze and the old version did not |
| `--exclude GLOB` | Skip matching paths on both sides (repeatable) |
| `--config FILE` / `--no-config` | As for `scan`; `diff` uses only the config's `exclude` and `ignore` (and `[policy]` `ignore` entries) |

The diff lists new, resolved and changed findings, evidence added and removed (matched by the
baseline's line-independent fingerprint, so moved lines are not noise), capability changes and the
risk-score change. `--fail-on-new` gates only on risk the new version *introduces*, so findings you
already accepted in the old version never trip it: it answers "is 1.2.4 riskier than the 1.2.3 we
vetted?" without a baseline file. A second copy of a line the old version already had counts as
new evidence.

A finding can also disappear because the new version's scan could not read the file it was in (too
large, minified, unparseable). The diff lists those parts as `coverage_gaps_added` (JSON) and under
"Not analyzed in the new version only" (text), and `--fail-on-unanalyzed` exits 2 on them.

A side given as a saved report is not scanned: its findings are taken as the file states them, and
the console says so. In CI, scan both sides rather than accept a report file from the change under
review. A CI recipe for dependency-upgrade pull requests is in
[CI](ci.md#reviewing-a-dependency-upgrade).

## guard

Answers "should I install this?" with an exit code you can chain an install on. `guard <source>`
checks one component; `guard --installed` checks everything installed on this machine
([Installed components](installed-components.md)).

```bash
skilltotal guard npm:some-mcp-server
skilltotal guard npm:some-mcp-server && claude mcp add some-mcp-server -- npx some-mcp-server
skilltotal guard npm:x --block-on malicious
skilltotal guard pypi:some-tool --json
skilltotal guard --installed
skilltotal guard --installed --allow-unchecked
skilltotal guard --installed --state ~/.skilltotal-state.json
skilltotal guard --installed --write-accept accept.json
skilltotal guard --installed --accept accept.json
```

A component blocks (exit 2) when any of these holds, at every `--block-on` level:

- it has a malicious indicator;
- its risk level is at or above the block level (not at `malicious`);
- a script it runs at install time could not be read;
- nothing in it could be read;
- its name is a letter or two away from a popular npm or PyPI package (possible typosquatting;
  not checked for installed editor extensions).

With `--installed --state`, an update that added a malicious indicator or a high or critical
risky construct also blocks. Each reason is printed under `Decision  : BLOCK` and listed in the
JSON `reasons`.

Capabilities alone never block: a legitimate MCP server with shell or network access passes, so
the guard is quiet enough to leave on everywhere. Unlike `--fail-on`, it weighs the risk level
rather than single findings. It does not block a package for a secret the package ships: that puts
the publisher at risk, not the person installing it.

| Flag | What it does |
|---|---|
| `<source>` | The component to check, any [source](#sources). Give either a source or `--installed` |
| `--installed` | Check every installed MCP server, plugin, skill and editor extension |
| `--block-on LEVEL` | `malicious`: only the reasons that always block. `high` (the default): also high or critical risk. `medium`: also medium risk. With `--installed`, editor extensions default to `malicious` |
| `--json` | Print JSON ([format](report-schema.md#guard-json)) |
| `--accept FILE` | Accept the reviewed findings this accept file lists ([accept file](accepting-findings.md#accept-file)) |
| `--write-accept FILE` | Add an entry to `FILE` for each component that blocks, with an empty `reason` to fill in, and exit 0 |
| `--project DIR` | With `--installed`: also read this project's agent configs |
| `--allow-unchecked` | With `--installed`: exit 0, not 1, when a component could not be checked or none was found |
| `--no-extensions` | With `--installed`: leave out editor extensions |
| `--state FILE` | With `--installed`: record versions and risk fingerprints in `FILE` and report [drift](installed-components.md#catching-a-malicious-update) |

`guard` reads no `.skilltotal.toml`, baseline or inline marker: it judges the component as
published.

## inventory

Lists the MCP servers, plugins, skills and editor extensions installed on this machine and scans
each one. It exits 0 whatever it finds; use `guard --installed` for a check that fails. Where it
looks, the per-kind block levels, drift and scheduling are in
[Installed components](installed-components.md).

```bash
skilltotal inventory
skilltotal inventory --json
skilltotal inventory --no-scan
skilltotal inventory --no-extensions
skilltotal inventory --project .
skilltotal inventory --sbom
skilltotal inventory --json --state ~/.skilltotal-state.json --accept accept.json
```

| Flag | What it does |
|---|---|
| `--json` | Print JSON ([format](report-schema.md#inventory-and-guard---installed-json)) |
| `--sbom` | Print a CycloneDX 1.6 AI-BOM with the scan results as properties ([AI-BOM](installed-components.md#ai-bom)) |
| `--no-scan` | List only. Cannot be combined with `--state`, `--accept` or `--write-accept` |
| `--project DIR` | Also read this project's agent configs |
| `--no-extensions` | Leave out editor extensions (their scan can take minutes) |
| `--state FILE` | Record versions and risk fingerprints in `FILE` and report drift |
| `--accept FILE` | Accept the reviewed findings this accept file lists |
| `--write-accept FILE` | Add an entry for each component flagged as high risk, malicious or blocked, and exit 0 |

## rules list

```bash
skilltotal rules list
skilltotal rules list --json
```

Prints every detection rule: id, severity, category and title, and with `--json` also the
description, recommendation, capability and threat class.

## mcp

```bash
skilltotal mcp
```

Runs SkillTotal as an MCP server on stdio, with the tools `scan_component`, `diff_components` and
`list_rules`. Client setup and path rules are in [docs/mcp-server.md](mcp-server.md).

## hook claude-code

```bash
skilltotal hook claude-code --help
```

The check the Claude Code plugin runs before each Bash or PowerShell command: it reads one hook
event (JSON) on stdin and prints Claude Code's answer on stdout. It always exits 0; the decision is
in the answer. `--protocol N` names the hook protocol the caller needs, and a CLI that speaks an
older one exits 1, so the plugin can tell that the CLI needs an update. `--help` lists the
environment variables the hook reads. Behavior and settings are in [docs/plugin.md](plugin.md).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No gate tripped and nothing blocked. Also after `--write-baseline` or `--write-accept` has written its file (no gate applies), and for `inventory` whatever it finds |
| 1 | The command could not do its job: an unknown or abbreviated flag, an invalid `.skilltotal.toml` or an unknown rule id in it, an invalid `--accept` or `--state` file, a state file that cannot be written, a missing path, an `--output` folder that does not exist, a failed clone or download, a source over a size limit. `guard --installed` also exits 1 when a component could not be checked or none was found, unless `--allow-unchecked` is given |
| 2 | A gate tripped (`--fail-on`/`--fail-on-high`, `--fail-on-score`, `--fail-on-unanalyzed`, a `fail_on`, `fail_on_score`, `fail_on_unanalyzed` or `block` policy in `.skilltotal.toml`, `diff --fail-on-new`/`--fail-on-unanalyzed`), or `guard` blocked a component |

When a gate trips, stderr gets one `gate:` line per gate, naming the gate, the finding that
tripped it and why it counts, for example
`gate: --fail-on high tripped by ST-COMBO-EXFIL (index.js:7), severity critical and 1 more` or
`gate: fail_on = "critical" in .skilltotal.toml tripped by ST-INSTALL-NPM-REMOTE-EXEC
(package.json:1), a malicious indicator`.

### Gates

`--fail-on` and `--fail-on-high` trip on the **severity of a single finding**, not on the risk
score. They count risk findings: a malicious indicator at any severity, and a risky construct or
a shipped secret at or above the level you set. A *capability*, such as shell or network access,
is what a component can do; it is reported but never trips the gate on its own. To forbid one, give
its rule a `block` policy. The gate also fails closed on what the scan could not read: an install
script it could not analyze, or a component with nothing it could read.

A component can therefore report `risk_level: low` and still fail the gate on one high-severity
risky construct. To gate on the score instead, use `--fail-on-score`. To accept known findings, see
[Accepting findings](accepting-findings.md).

Flags override the config. `--fail-on none` turns off every gate the config sets (`fail_on`,
`fail_on_score`, `fail_on_unanalyzed`, `block` policies); gate flags given on the same command
line still apply.

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
