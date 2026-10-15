<!-- mcp-name: ai.skilltotal/skilltotal -->

# SkillTotal

[![PyPI](https://img.shields.io/pypi/v/skilltotal)](https://pypi.org/project/skilltotal/)
[![Python](https://img.shields.io/pypi/pyversions/skilltotal)](https://pypi.org/project/skilltotal/)
[![License](https://img.shields.io/pypi/l/skilltotal)](https://github.com/pezhik/skilltotal/blob/main/LICENSE)
[![CI](https://github.com/pezhik/skilltotal/actions/workflows/ci.yml/badge.svg)](https://github.com/pezhik/skilltotal/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/pezhik/skilltotal/badge)](https://scorecard.dev/viewer/?uri=github.com/pezhik/skilltotal)

**Scan packages before Claude Code installs them.** SkillTotal is a static security scanner for
what coding agents install: npm and PyPI packages, MCP servers, agent skills and git repositories.
It runs on your machine, never executes the code it reads and never calls an LLM. Every finding
cites the file and line it came from.

## Quick start

```bash
pipx install skilltotal
```

Then, inside Claude Code:

```
/plugin marketplace add pezhik/skilltotal
/plugin install skilltotal@skilltotal
/reload-plugins
```

From then on, when the agent runs `npx`, `npm install`, `pip install`, `uvx` or `claude mcp add`,
the plugin first scans the package the command names. If the package has malicious indicators, the
command is denied and the agent is told what was found and where:

```
SkillTotal blocked this install: it found malicious indicators. npm:some-pkg@1.0.3:
Decode-and-execute (obfuscated execution) at `scripts/setup.js:4`. Run
`skilltotal scan npm:some-pkg@1.0.3` to see every finding with its file:line evidence.
```

Without the plugin, scan anything from a terminal:

```bash
skilltotal scan npm:some-package         # or pypi:name, a git URL, a local folder or an archive
skilltotal guard npm:some-mcp-server     # exit code 2 if it should not be installed
```

**Try it online (no install, no account):** [www.skilltotal.ai](https://www.skilltotal.ai) runs the
same engine.

SkillTotal analyzes **only the component itself**, not the user, company, environment, deployment
or runtime context around it. Every score and finding comes from the files inside the component.

> Core principle: **every confirmed finding carries evidence** (file, line range, code
> snippet). Anything that cannot be tied to evidence goes to `needs_review` instead of
> `findings` and never affects the score.

## Why SkillTotal

- **Checks packages before your agent installs them.** The Claude Code plugin reads each `npx`,
  `npm install`, `pip install` or `claude mcp add` command the agent is about to run. It blocks
  packages with malicious indicators, and asks you first about high- or critical-risk packages and
  any it could not check. [Set it up](#claude-code-plugin).
- **Runs on your machine.** It needs no account or API token, uploads nothing and sends no
  telemetry. A local folder, archive or file is scanned offline. The network is used only to fetch
  what you asked for: see [Network access](#network-access).
- **Safe to point at untrusted components.** The engine reads them and never runs them.
- **Zero runtime dependencies.** It uses only the Python standard library, so it is easy to audit,
  vendor or run air-gapped.
- **Deterministic.** Detection is regex and AST matching with no LLM, so the same input on
  the same Python version always yields the same findings and score. The AST parser comes
  from the Python interpreter that runs the scan, and a file written in newer syntax than it
  understands falls back to regex and is listed for review, so run the scan on the newest
  Python you can.
- **Evidence-anchored, with few false positives.** Every finding points at an exact file:line.
- **Standards-aligned.** Every component gets a behavioral trait fingerprint mapped to the Cloud
  Security Alliance (CSA) agentic threat model, MAESTRO threat-model layers and MITRE ATLAS
  tactics. Three of the traits record how the component authenticates its tool calls (an embedded
  static credential, delegated OAuth/OIDC or a least-privilege scoped identity), which shows the
  blast radius of a compromise, not only whether a secret exists.
- **Free and open source** (Apache-2.0). The full static report is free, forever.

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
says so on stderr.

```bash
npx -y skilltotal scan https://github.com/owner/repo
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

# SARIF 2.1.0 (GitHub Code Scanning / IDE) to a file; the console gets the readable summary
skilltotal scan ./component --sarif --output report.sarif

# Write the report to a file (SARIF if --sarif, else JSON)
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

# Pre-install guard: allow/block decision (exit 2 on block) you can chain before installing
skilltotal guard npm:some-mcp-server && claude mcp add some-mcp-server -- npx some-mcp-server
skilltotal guard npm:x --block-on malicious   # block only on malicious indicators
skilltotal guard --installed                  # check the MCP servers, plugins and skills your agents use
skilltotal guard --installed --allow-unchecked  # exit 0 even if some could not be checked

# Inventory: list the MCP servers, plugins and skills your agents are configured with, and scan them
skilltotal inventory
skilltotal inventory --json
skilltotal inventory --no-scan          # list only, do not scan
skilltotal inventory --project .        # also include this project's agent configs
skilltotal inventory --sbom             # AI-BOM: CycloneDX 1.6 JSON of your agent stack,
                                        # scan verdicts attached as component properties

# List every detection rule
skilltotal rules list
skilltotal rules list --json
```

**Baseline** suppresses findings by a stable fingerprint of
`(rule id, file, code snippet)`, independent of line numbers, so it survives edits.
Suppressed findings are removed before scoring and do not affect the risk score. Writing a baseline
is how you adopt the tool on existing code: `--write-baseline` writes the file and exits 0,
whatever it found.

**Diff** reports new / resolved / changed findings, evidence-level additions and removals
(matched by the same line-independent fingerprint as the baseline, so pure line shifts are
not noise), capability changes, and the risk-score delta. `--fail-on-new LEVEL` gates only
on risk the new version *introduces*, counted like `scan --fail-on` (a malicious indicator at any
severity, never a capability on its own). Existing accepted findings never trip it, so it fits
upgrade reviews ("is 1.2.4 riskier than the 1.2.3 we already vetted?") without a baseline file.

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
`.cursor/mcp.json`, `.vscode/mcp.json` and `.claude/skills`. Claude Code's `~/.claude/settings.json`
is not read: it holds permissions and hooks, not server definitions. Each server's launch command
is read by the same parser as the plugin hook, which derives the `npm:`, `pypi:`, git or local
source to scan. A launcher that pipes a download into a shell is marked risky, a remote (URL)
server cannot be scanned, and an inline secret in a config entry (an `env` value, an
`Authorization` header, a key in a URL) is reported redacted. `guard --installed` exits 2 when a
component blocks, else 1 when any component could not be checked (a scan error, a remote or
unsupported server, a risky launcher) or none was found; `--allow-unchecked` turns that 1 into 0.

**Provenance** (`--provenance`, opt-in) adds registry-metadata signals for `npm:` /
`pypi:` sources: *recently published*, *deprecated / yanked*, *no recent releases*, *no
repository link*. Metadata is context about a component, not component content, so these
signals go to `needs_review` and **never** affect the score or verdict, and the default
scan stays component-only.

### Project config

Commit a `.skilltotal.toml` instead of repeating flags (CLI flags override it):

```toml
fail_on = "high"           # low | medium | high | critical
fail_on_score = 50         # or gate on the 0-100 risk score
fail_on_unanalyzed = true  # or when part of the component could not be analyzed (true/false)
exclude = ["vendor/*", "*.min.js"]
ignore = ["ST-NET-PY"]     # rule ids to drop
baseline = ".skilltotal-baseline.json"   # relative to this file

# Per-rule policy: reviewable gate decisions that live in the repo, not in a dashboard.
[policy]
"ST-SHELL-PIPE-EXEC" = "block"   # gate trips (exit 2) whenever this rule fires,
                                 # even with no fail_on configured
"ST-DESERIALIZE-PY" = "warn"     # explicit accept-but-show: reported, still counts toward
                                 # the risk score, but exempt from the fail_on severity gate
"ST-SENS-WORD" = "ignore"        # suppressed entirely (same effect as `ignore`)
```

The config is read from the directory you run `skilltotal` in (not from the scanned folder), or
from the file `--config` names; `--no-config` ignores it. A config it cannot honor stops the scan
with exit code 1, so a typo can't turn a gate off: invalid TOML, an unknown key, a value of the
wrong kind, an unknown policy action, a rule id in `ignore` or `[policy]` that no rule has (the
error suggests the closest id), or a `--config` path that does not exist. A relative `baseline`
path is resolved against the config file's folder.

An applied config is always named: on a `Config    :` line in the text report, as a
`config applied: ...` line on stderr with `--json` or `--sarif`, and in the report's
`metadata.config_applied`.

> **Protect the config in CI.** The GitHub Action and the pre-commit hook run from the root of the
> repository they scan, so that repository's own `.skilltotal.toml` is applied, and a pull request
> can change it: lower `fail_on`, `ignore` a rule, point `baseline` at a file that suppresses
> everything. Inline `skilltotal:ignore` markers come with the code too. Put `.skilltotal.toml` and
> the baseline file under CODEOWNERS with branch protection, and review new ignore markers like any
> other code. When you scan code you don't control from its own root, pass `--no-config` (Action:
> `config: none`).

### Inline suppression

To accept a single finding, add a `skilltotal:ignore[ST-ID]` comment (any comment syntax: `#`,
`//`, `<!-- -->`) on the finding's line or on the line just above it. Several ids are separated by
commas; a bare `skilltotal:ignore` accepts every rule on that line. Inline markers count only when
you scan a local directory (your own code, as in CI). In a package, repository, archive or file
that SkillTotal fetches or unpacks they are ignored, so a component cannot silence its own
findings. Suppressed occurrences are counted in the report (`metadata.suppressed_count`).

### Environment variables

**Settings** (environment variables, for the CLI, the plugin and the action):

| Variable | Default | What it sets |
|---|---|---|
| `SKILLTOTAL_MAX_ARCHIVE_MB` | 150 | Largest archive downloaded or read |
| `SKILLTOTAL_MAX_EXTRACT_MB` | 400 | Largest total size an archive may extract to |
| `SKILLTOTAL_MAX_ARCHIVE_MEMBERS` | 30000 | Most entries an archive may hold |
| `SKILLTOTAL_MAX_CLONE_MB` | 200 | Largest git working tree cloned |
| `SKILLTOTAL_MAX_READABLE_MB` | same as clone | Most text a scan reads |
| `SKILLTOTAL_CLONE_TIMEOUT` | 300 | Seconds a git clone may take |
| `SKILLTOTAL_WORKERS` | up to 4 | Processes a large scan uses (1 for one) |

A source over a limit is refused with its size and the variable to raise. A value that is not a
positive whole number is an error. The plugin's own settings are listed in
[docs/plugin.md](https://github.com/pezhik/skilltotal/blob/main/docs/plugin.md).

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success: no gate tripped. Also after `--write-baseline` has written its file (no gate is applied) |
| 1 | Usage, config or collection error (for example an unknown flag value, an invalid `.skilltotal.toml` or an unknown rule id in it, a missing path, a failed clone, a source over a size limit). `guard --installed` also exits 1 when a component could not be checked or none was found, unless `--allow-unchecked` is given |
| 2 | A configured gate tripped (`--fail-on`/`--fail-on-high` severity, `--fail-on-score`, `--fail-on-unanalyzed`, a `block` policy or `diff --fail-on-new`), or `guard` blocked a component |

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

## CI / GitHub Action

Run SkillTotal in CI and surface findings in your repository's **Security → Code scanning** tab.

```yaml
# .github/workflows/skilltotal.yml
name: SkillTotal
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # required to upload SARIF to Code Scanning
  actions: read            # required for the SARIF upload in a private repository
  pull-requests: write     # required only for comment-on-pr (optional)
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: pezhik/skilltotal@v0.72.0
        with:
          source: .             # a path, a git URL, or an npm:/pypi:<name> spec
          fail-on: high         # fail on a high/critical risk finding (or 'none')
          fail-on-unanalyzed: 'false' # 'true': also fail when part of it could not be analyzed
          comment-on-pr: 'true' # post a sticky summary comment on pull requests (optional)
```

The action runs the engine that ships with the tag you pin, so nothing is downloaded from PyPI and
the tag pins the scanner too. Pin it to a released tag (see
[Releases](https://github.com/pezhik/skilltotal/releases)), or to that release's commit SHA
(`pezhik/skilltotal@<commit> # vX.Y.Z`), which, unlike a tag, cannot be moved. Without the action,
the same scan is `skilltotal scan . --sarif --output skilltotal.sarif --fail-on-high`.

| Input | Default | What it does |
|---|---|---|
| `source` | `.` | A path in the repository, a git URL, or an `npm:`/`pypi:<name>` spec |
| `fail-on` | empty | `low`, `medium`, `high`, `critical` or `none`. Empty uses the gate of the applied `.skilltotal.toml` (`fail_on` / `fail_on_score`) when it sets one, else `high`. A level overrides the config's `fail_on`; `none` turns off every gate the config sets |
| `fail-on-score` | empty | Also fail at or above this risk score (0-100); overrides the config's `fail_on_score` |
| `fail-on-unanalyzed` | `false` | `true`: also fail when part of the component could not be analyzed |
| `exclude` | empty | Path globs to skip, relative to `source`, one per line or comma-separated (added to the config's `exclude`) |
| `config` | empty | Path to a `.skilltotal.toml`. Empty reads one from the working directory if present; `none` ignores any config |
| `baseline` | empty | Baseline file of accepted findings |
| `upload-sarif` | `true` | Upload SARIF to Code Scanning (needs `security-events: write`) |
| `sarif-file` | `skilltotal.sarif` | Where the SARIF report is written |
| `sarif-category` | empty | Code Scanning category. Empty: none for `source: .`, else `skilltotal/<source>`, so two scans in one job keep their alerts apart |
| `comment-on-pr` | `false` | Post a summary comment on pull requests (needs `pull-requests: write`) |
| `version` | empty | Install this `skilltotal` release from PyPI instead of running the engine that ships with the tag. It must be at least as new as the action |

Outputs: `risk-level`, `risk-score`, `sarif-file` and `verdict`, which is `malicious` whenever a
malicious indicator was found, whatever the score.

How it behaves:

- **The gate decides the job.** The semantics above apply: a malicious indicator fails the job at
  any severity, and a capability on its own, such as a shell call or network access, never does.
  The Scan step's log says which gate tripped.
- **The log lists the findings.** It prints a count of risk findings and, separately, capability
  findings (not scored, never gated), then every location of each risk finding: up to 10 per rule,
  then "and N more" (the SARIF and JSON reports have them all). When Code Scanning is off, this is
  where you read why the gate failed. Text from the scanned files cannot issue workflow commands
  in the log.
- **SARIF paths.** For a `source` in a subfolder, SARIF locations are made relative to the
  repository root, so alerts point at real files. SARIF for an `npm:`, `pypi:` or git-URL source is
  written to `sarif-file` but not uploaded: its alerts would point at files the repository does not
  have.
- **Without Code Scanning.** A private repository has Code Scanning only with GitHub Advanced
  Security. Without it, GitHub's upload action shows an error annotation of its own, the next step
  prints a warning explaining why, and the job result is still decided by the gate; the report
  stays in `sarif-file`. Set `upload-sarif: 'false'` to skip the upload.
- **PR comment.** With `comment-on-pr: 'true'`, the action posts one summary comment on the pull
  request (verdict, risk level and score, the gate result, the number of risk findings and of
  malicious indicators, capability findings counted apart, the capabilities) and updates it in
  place on later runs. On a pull request from a fork the token is read-only: the comment is skipped
  with a warning, and the job is not failed for it.
- **The repository's config is applied.** See [Protect the config in CI](#project-config).

### Use as a pre-commit hook

Run SkillTotal on every commit via [pre-commit](https://pre-commit.com):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pezhik/skilltotal
    rev: v0.72.0
    hooks:
      - id: skilltotal
        args: [".", "--fail-on-high"]   # scan the repo; block the commit on a high/critical finding
```

Then `pre-commit install`. The hook installs the CLI in its own environment and scans the repo
on commit; tune the scan with the same flags as the CLI (e.g. `--exclude`, `--fail-on`). It scans
what the commit will contain (`skilltotal scan --staged`): every file in git's index across the
whole repository, not only the changed files, so the verdict matches what CI sees. Untracked
and ignored files are left out. The repository's `.skilltotal.toml` applies here too.

### Other CI systems

Anywhere Python 3.10+ runs, install a pinned release and gate on the exit code: 0 passed, 2 a gate
tripped, 1 the scan could not run. SkillTotal writes SARIF 2.1.0 (`--sarif`) and its own JSON
report; it does not write GitLab's security report format, so publish the files as job artifacts.
Write reports outside the scanned folder, or into a folder you `--exclude` (SkillTotal also
recognises its own SARIF, JSON and baseline files by content and skips them). `--output` does not
create folders, so create the report folder first.

A shell step:

```bash
pipx install skilltotal==0.72.0
OUT="$(mktemp -d)"
skilltotal scan . --sarif --output "$OUT/skilltotal.sarif" --fail-on high
```

GitLab CI (`allow_failure: exit_codes: [2]` would turn the gate into a warning):

```yaml
skilltotal:
  image: python:3.12-slim
  script:
    - pip install skilltotal==0.72.0
    - mkdir -p skilltotal-reports
    - skilltotal scan . --exclude "skilltotal-reports/*" --sarif --output skilltotal-reports/skilltotal.sarif --fail-on high
  artifacts:
    when: always
    paths: [skilltotal-reports/]
```

Jenkins (declarative pipeline, Docker agent):

```groovy
stage('SkillTotal') {
  agent { docker { image 'python:3.12-slim' } }
  steps {
    sh '''
      python -m venv .skilltotal-venv    # a virtual environment is not scanned
      .skilltotal-venv/bin/pip install skilltotal==0.72.0
      mkdir -p skilltotal-reports
      .skilltotal-venv/bin/skilltotal scan . --exclude "skilltotal-reports/*" --sarif --output skilltotal-reports/skilltotal.sarif --fail-on high
    '''
  }
  post { always { archiveArtifacts artifacts: 'skilltotal-reports/*', allowEmptyArchive: true } }
}
```

For a JSON report, drop `--sarif` (`--output` then writes JSON). To publish both, run the scan
twice: once with `--fail-on none` for the report, once with the gate.

### Rolling out on an existing repository

1. **Record what is there today.** `skilltotal scan . --write-baseline .skilltotal-baseline.json`
   writes a baseline of the current findings and exits 0. Read the report first: a baseline
   accepts everything in it, malicious indicators included.
2. **Gate only new findings.** Commit the baseline and a `.skilltotal.toml` with
   `baseline = ".skilltotal-baseline.json"` and `fail_on = "high"` (or pass the action's `baseline`
   input). Findings already in the baseline no longer trip the gate; new ones do.
3. **Protect the gate.** Put `.skilltotal.toml` and the baseline under CODEOWNERS with branch
   protection, so loosening them needs a review.
4. **Accept a false positive.** For one occurrence, prefer an inline
   `# skilltotal:ignore[ST-ID]` on its line or the line above: it sits next to the code and is
   reviewed with it. Re-writing the baseline accepts every current finding at once, which is
   convenient after a review but easy to misuse. A `[policy]` `warn` or `ignore` applies to a rule
   everywhere. [Report false positives](https://github.com/pezhik/skilltotal/issues) too: they are
   fixed in the open.
5. **Decide on `--fail-on-unanalyzed`.** It is off by default, so the gate passes code it could
   not read (files over 2 MiB, minified bundles, code in languages whose behavior is not
   analyzed). Turned on, it fails closed on that code, which also fails a repository that commits
   bundles or Go code. Exclude such paths if you trust them, or turn the flag on for the
   third-party components you scan rather than for your own repository.

## Claude Code plugin

The plugin checks each package the agent is about to install, on your machine and with the same
engine as the CLI, before the install command runs. It reads npm, pnpm, yarn, bun, npx, pip, uv,
uvx, pipx, poetry and similar installs, `claude mcp add` (and the Codex and Gemini equivalents) and
`npx skills add`, also when they are wrapped in `sudo`, `bash -c`, `$(...)` or PowerShell.

Install the CLI first (`skilltotal --version` must work in the terminal you start Claude Code
from), then:

```
/plugin marketplace add pezhik/skilltotal
/plugin install skilltotal@skilltotal
/reload-plugins
```

What happens to an install:

- **Malicious indicators:** denied, and the agent is told the finding and its file:line.
- **High or critical risk, a look-alike package name, or anything it could not check** (a custom
  registry, a name built at run time, a command hidden behind a decoder, a check that failed or ran
  out of time): Claude Code asks you.
- **Clean:** it installs, and the agent gets a one-line note with the version checked and its
  score.
- **Never silent:** every install command gets a line in the console saying what was checked, or
  what was not and why.
- **CI is fail-closed:** in CI (`CI`, `GITLAB_CI`, `JENKINS_URL` and similar, or
  `SKILLTOTAL_STRICT=1`) nobody can answer a question, so everything it would ask about is denied,
  and so are installs it could not check (from a lockfile, a local path or a downloaded script)
  unless `SKILLTOTAL_ALLOW_UNCHECKED` lists their kind.

What it does not check:

- dependencies of the package a command names
- installs that name no package (`npm ci`, `pip install -r`, `uv sync`); the console says so
- scripts on disk and shell-profile aliases or functions; downloaded scripts (`curl ... | bash`)
  are reported as not checked
- repositories fetched with `git clone`
- code already running on your account (it can rewrite the verdict cache or the CLI)

The plugin also adds a `/skilltotal:scan <target>` command and registers the SkillTotal MCP server.
It is a static guardrail, not a sandbox: for code you don't trust, run the agent in a container.
The full reference (every recognized command, the strict-mode variables, cache, timing and
troubleshooting) is in [docs/plugin.md](https://github.com/pezhik/skilltotal/blob/main/docs/plugin.md).

## MCP server

Let your agent check a component *before* installing it. `skilltotal mcp` runs the engine
as a stdio MCP server (stdlib-only, still zero dependencies). The Claude Code plugin already
registers it, so don't add it a second time there. For Claude Desktop, Cursor, Windsurf or any
client that reads `mcpServers`:

```json
{ "mcpServers": { "skilltotal": { "command": "skilltotal", "args": ["mcp"] } } }
```

For VS Code (`.vscode/mcp.json` or the user `mcp.json`):

```json
{ "servers": { "skilltotal": { "type": "stdio", "command": "skilltotal", "args": ["mcp"] } } }
```

If you have not installed it locally, use `"command": "npx", "args": ["-y", "skilltotal", "mcp"]`
instead. This needs uv, pipx, or Python 3.11+ with `skilltotal`; if it falls back to an installed
Python `skilltotal` of another release, it warns on stderr (stdout stays the MCP session).

Tools exposed: `scan_component` (full report for a path / git URL / `npm:` / `pypi:`
source), `diff_components` (upgrade review: what changed between two versions), and
`list_rules` (pass `verbose: true` for each rule's description and recommendation). All three are
annotated read-only. Scans run locally with the same never-execute static engine; the component's
code is not uploaded anywhere.

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

## What it detects

SkillTotal performs **static** security analysis of AI components: MCP servers, agent
skills/plugins, npm and PyPI packages, and AI-generated projects/repositories. The engine
combines capability analysis, dangerous-pattern detection, privilege analysis, supply-chain
(install-time) analysis, prompt-surface analysis, and data-flow correlation (e.g. secret
access combined with network egress). Findings are mapped to risk categories and contribute to
a **0–100 risk score**; capabilities are reported but never inflate the score (capability ≠ risk).
Nothing is executed and no LLM is called, so results are deterministic and reproducible.

| Category | Examples |
|----------|----------|
| Shell execution | `subprocess.*`, `os.system`, `child_process.exec`, `curl … \| bash` handed to a shell call |
| Filesystem access | `open`, `read_text`/`write_text`, `fs.readFile`/`writeFile` |
| Sensitive paths | `~/.ssh`, `~/.aws`, `.env`, `id_rsa`, `credentials`, `secrets` |
| Network egress | `requests`, `urllib`, `aiohttp`, `fetch`, `axios` |
| Install-time execution | npm `preinstall`/`postinstall`/`prepare`, `setup.py` hooks, a lifecycle script that downloads or decodes code and runs it |
| Dynamic code execution | `eval`, `exec`, `compile`, `new Function`, `vm.runInNewContext` |
| Obfuscation | decode-and-execute chains, base64 blobs, hex escaping, minification |
| MCP risks | manifests, dangerous tools (shell/fs/network/credential), server commands |
| Prompt surface | "ignore previous instructions", "reveal system prompt", exfiltration phrasing |

`skilltotal rules list` prints every rule. Which rules catch which malware archetype is in
[docs/detection-coverage.md](https://github.com/pezhik/skilltotal/blob/main/docs/detection-coverage.md).

### Coverage by component type

Legend: **✅** analyzed by default for this component type · **⚠️** the engine detects this, but
that surface is uncommon for this type, so it is flagged only when the component actually contains
it (e.g. prompt-injection text inside an npm/PyPI package) · **❌** not applicable to this type.

Columns are the component types SkillTotal scans. **AI project** = a scanned repository or folder
(an agent skill/plugin, an AI-generated codebase, or a set of prompts/configs) that is not a
published npm/PyPI package.

| Category | MCP | npm | PyPI | AI project |
|---|---|---|---|---|
| Prompt injection / instruction override | ✅ | ⚠️ | ⚠️ | ✅ |
| Tool poisoning (MCP tool and schema text, prompts, resources, server instructions) | ✅ | ❌ | ❌ | ⚠️ |
| Dangerous capabilities (shell / fs / network) | ✅ | ✅ | ✅ | ⚠️ |
| Data exfiltration (secret access + egress) | ✅ | ✅ | ✅ | ⚠️ |
| Secret theft / sensitive-path access | ✅ | ✅ | ✅ | ⚠️ |
| Dynamic code execution | ✅ | ✅ | ✅ | ⚠️ |
| Obfuscation (decode-and-execute) | ✅ | ✅ | ✅ | ✅ |
| Hidden text (tag characters, variation selectors, invisible operators, zero-width characters inside words, ANSI escapes in agent-facing text) | ✅ | ✅ | ✅ | ✅ |
| Embedded secrets (hardcoded keys/tokens) | ✅ | ✅ | ✅ | ✅ |
| Install-time / supply-chain hooks | ⚠️ | ✅ | ✅ | ❌ |
| Overprivileged tools, auto-approve in MCP server entries and agent settings | ✅ | ❌ | ❌ | ⚠️ |

Each row names what the engine checks today. The code-behavior rows (dangerous capabilities, data
exfiltration, dynamic code execution, decode-and-execute) cover Python and JavaScript/TypeScript;
shell, PowerShell and batch scripts are checked for download-and-run, decode-and-run and evasion
idioms. Code in other languages gets only the secret, sensitive-path and hidden-text checks (see
[Limitations](#limitations)). Bidi controls and lone zero-width characters are listed for
review and left out of the score, because locale and CJK files use them legitimately.

### Typical findings

- An MCP tool can execute arbitrary shell commands
- A package downloads and runs code from an external URL, for example in an npm install script
- Access to credential locations (`~/.aws`, `~/.ssh`, `.env`) detected
- Dynamic code execution (`eval` / `exec`) detected
- Prompt-injection / instruction-override phrasing in a tool description or skill
- Sensitive-data access combined with outbound network egress
- Hardcoded API keys or tokens
- An MCP server with auto-approved or overprivileged tools
- Untrusted input (environment, `sys.argv`, a request/response body) flowing into `exec` or a
  shell: a traced path, not just a dangerous API in isolation
- An **agent skill** whose bundled code does more than its declared `allowed-tools` cover. The
  field pre-approves tools and does not limit the skill's code, so a narrow list can make a skill
  look safer than it is.

### Verdict

Every report has a one-line verdict next to the score: `Malicious indicators found` whenever a
malicious indicator fired, whatever the score; `High risk - review before installing` or
`Critical risk - review before installing` for a high or critical score without one;
`Some risk - review before installing` for a medium score; and, for a low score, wording that
says what was found ("No significant risks found", "No malicious
indicators - review capabilities before installing", ...). A low verdict never sounds clean over
code that was not read: it reads `Partially analyzed - ...` when the component ships code in a
language whose behavior is not analyzed, or code files that were not read
(`Partially analyzed - 2 code files not read (2 minified)`), and `Not analyzed - nothing in this
component could be read` when nothing could be read. That wording does not change the score.

### Limitations

- **Files over 2 MiB are not read**, and minified JavaScript/TypeScript bundles are listed but not
  analyzed. The scripts npm runs at install are the exception: they are read even when minified
  or filed in a skipped folder. A low verdict then reads "Partially analyzed", and the report
  counts them in `verdict.unanalyzed_files`.
- **Dependency and environment folders are skipped:** `node_modules/`, `vendor/` (and
  `vendored-*`), Python virtual environments and installed `site-packages`, and in a repository
  (not a published package) the build output in `dist/` and `build/`. Code the component loads
  from those folders by a literal path (a relative `require`/`import`, a Python import, a
  `package.json` or `pyproject.toml` entry point) is read anyway.
- **Dependencies are not scanned.** A scan covers the component's own files, not what it installs.
- **Code that is not in the files is not analyzed:** code fetched or generated at run time, and
  binaries or compiled artifacts (counted in `metadata.files_skipped_binary`).
- **Languages.** Shell execution, network access, file access and dynamic code are analyzed in
  Python and JavaScript/TypeScript. Shell, PowerShell and batch scripts are checked for
  download-and-run, decode-and-run and evasion idioms. Go, Rust, Java, Ruby, PHP, C/C++, C#, Swift,
  Kotlin, Scala, Dart, Lua, Perl, Elixir, Groovy, Haskell, Clojure, Erlang, R and Zig files get only
  the secret, sensitive-path and hidden-Unicode checks; the report adds a `needs_review` note, and
  a low verdict reads "Partially analyzed". See
  [docs/language-scope.md](https://github.com/pezhik/skilltotal/blob/main/docs/language-scope.md).
- **Symbolic links and junctions** in a scanned folder are not followed, and links inside an
  archive are not extracted.
- **The default gate does not count unread code.** `--fail-on` (and the action's `fail-on`) pass a
  component whose code was partly not analyzed, unless you add `--fail-on-unanalyzed` (action:
  `fail-on-unanalyzed: 'true'`).
- **Detection is at the call/import level.** A capability used through an *unrecognized*
  higher-level library (a git library that writes files internally, a browser library) may not be
  flagged as a raw filesystem/shell call. Capabilities indicate *presence*, not proven misuse.

### Out of scope

SkillTotal statically analyzes a **single component's own files**. It does not execute code,
observe runtime behavior, or assess your environment, deployment, or infrastructure. It is **not**
a substitute for:

- a penetration test
- an application-security (app-sec) review
- an architecture / design review
- a cloud-security or infrastructure assessment
- a Kubernetes / container runtime audit
- a business-logic review
- a manual code review

### Accuracy notes

- Python is analyzed via an **AST** (resolves import aliases, tells `open(p,'w')` from a
  read, ignores API names that only appear in strings/comments). Node.js/config use regex.
- **Test code** (`__tests__/`, `*.test.*`, `tests/`, `conftest.py`, …) is demoted to
  `needs_review`: it is not executed by consumers, so it does not affect the score.
- Ambiguous signals (bare `secrets`/`credentials` words, lone base64 blobs, "before
  answering" phrasing, minified files) go to `needs_review`, never to `findings`.
- **Hidden Unicode** (ASCII-smuggling tag characters, variation selectors and invisible math
  operators used as bytes, zero-width characters threaded through words, Hangul filler
  identifiers) is detected; where it encodes text, that text is decoded into the evidence.
  Trojan-Source bidi overrides and lone zero-width characters go to `needs_review`. Attackers
  use hidden text to smuggle instructions past human review. See `tests/manual_eval/` for
  calibration against real-world attacks.
- Shell execution covers `subprocess`/`os.system`, `asyncio.create_subprocess_*`, Node
  `child_process`, and common process-spawning libraries (Python `sh`/`plumbum`/`pexpect`/
  `invoke`/`fabric`; Node `zx`/`execa`/`cross-spawn`/`shelljs`/`tinyexec`/`node-pty`).
- MCP dangerous tools are classified by name/description both in JSON manifests **and when
  defined in code** (`server.tool("run_command", …)`, `@mcp.tool` over `def read_file`).
- SARIF, JSON and baseline files that SkillTotal wrote into the scanned folder are recognised by
  their content, listed in `needs_review` and not scanned (their rule descriptions quote detection
  patterns).

## Network access

A scan of a local folder, archive or file makes no network request. SkillTotal goes online only
for:

- **git URLs:** `git clone --depth 1` of the repository; for github.com, GitHub REST API calls
  (`api.github.com`) first, to check the size of what would be cloned
- **`npm:` / `pypi:` sources:** package metadata and the package archive from the npm registry
  (`registry.npmjs.org`) or PyPI (`pypi.org` and its file host)
- **`--provenance`:** the package's registry metadata
- **`inventory`, `guard --installed` and the Claude Code plugin:** the same registries and git
  hosts, for the packages they check

There is no telemetry, no account and no LLM call. The MCP server makes the same requests for
the sources an agent asks it to scan.

## Measured, not asserted

Detection claims are cheap, so the numbers behind them are published with the data and the code
that produced them.

- **[Detection efficacy](https://github.com/pezhik/skilltotal/blob/main/docs/efficacy-report.md)**:
  recall and precision on a labeled corpus we built and publish (125 malicious and
  89 benign samples), regenerated every release and enforced by CI as a floor. A perfect
  score on our own corpus guards against regressions; it is not a claim about every attack in the
  wild.
- **[The MCP registry, scanned](https://github.com/pezhik/skilltotal/blob/main/docs/mcp-registry-survey.md)**
  (September 2026, engine 0.49.0, rulesets 56 to 59; later rule changes are not reflected): 15,341
  of the 17,535 distinct components in the official registry (87.5%), finished on 2026-09-19.
  Most of the rest were no longer reachable or exceeded a time or size bound, and every exclusion
  is counted. Of the components scanned, 88.2% expose tools to an agent, 64.8% can reach the
  network and 21.1% can execute shell commands, yet all but 116 of them score low risk, because a
  capability on its own scores zero. The rules were tuned on this population: we read every
  malicious-indicator hit from an earlier run by hand and fixed the false positives before this
  run. [Aggregates (JSON)](https://github.com/pezhik/skilltotal/blob/main/docs/mcp-registry-survey.json) ·
  [the harness](https://github.com/pezhik/skilltotal/blob/main/tests/manual_eval/survey_registry.py).

The same code scanned by the same engine on the same Python version gives the same findings.
Nothing is executed and no LLM is involved. The survey read each component's latest release or
default branch when it ran, so a re-run today reads newer code.

## Output

A normalized report containing the component identity, a **risk score (0–100)** and
**risk level** (low / medium / high / critical), a plain-language **verdict**, detected
**capabilities** (each evidence-backed), a behavioral **trait fingerprint** (with a CSA / MAESTRO /
MITRE ATLAS crosswalk), **findings**, **needs_review**, and **metadata**. See
[docs/report-schema.md](https://github.com/pezhik/skilltotal/blob/main/docs/report-schema.md) and [docs/scoring.md](https://github.com/pezhik/skilltotal/blob/main/docs/scoring.md).

Every finding also carries its **OWASP Agentic Skills Top 10** category ids (`owasp`), emitted in
both the JSON report and SARIF (native `taxonomies`/`relationships`);
[docs/owasp-agentic-skills-mapping.md](https://github.com/pezhik/skilltotal/blob/main/docs/owasp-agentic-skills-mapping.md) explains the coverage
(AST01–AST05) and the honest gaps. For MCP servers,
[docs/mcp-owasp-mapping.md](https://github.com/pezhik/skilltotal/blob/main/docs/mcp-owasp-mapping.md) maps SkillTotal's checks to the OWASP MCP
Security Cheat Sheet (and names the runtime controls a static engine can't cover).

The report's **`traits`** array is a behavioral fingerprint: a higher-level projection over the
findings (e.g. `execution_authority`, `embedded_credential`, `untrusted_perception`, and the
*emergent* `exfil_correlation` combination), each mapped to the Cloud Security Alliance
trait-based model, a MAESTRO threat-model layer, and a MITRE ATLAS tactic where there is an honest
fit. It is descriptive and never affects the score; see
[docs/trait-crosswalk.md](https://github.com/pezhik/skilltotal/blob/main/docs/trait-crosswalk.md).

## Architecture

The package under `skilltotal/` (except `cli.py`) is a pure, side-effect-free library so the
same engine powers the web app at [www.skilltotal.ai](https://www.skilltotal.ai). See
[docs/architecture.md](https://github.com/pezhik/skilltotal/blob/main/docs/architecture.md).

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Open source vs SkillTotal Cloud

SkillTotal is **open core**. This engine (the analysis, all detection rules and the CLI) is open
source and **complete on its own**: you can run it locally or in CI, for free, with zero runtime
dependencies. It tells you **what** a component does, with evidence.

Paid features are planned for **SkillTotal Cloud** (the website) and will explain **why it
matters**: LLM interpretation and prioritization of findings, dynamic sandbox execution, scan
history and monitoring. They will run as server-side services on top of this engine, and their
code is not part of this repository. See
[docs/open-core.md](https://github.com/pezhik/skilltotal/blob/main/docs/open-core.md).

## License

[Apache-2.0](https://github.com/pezhik/skilltotal/blob/main/LICENSE). See also [NOTICE](https://github.com/pezhik/skilltotal/blob/main/NOTICE).
