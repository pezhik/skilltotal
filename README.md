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
  anything it could not check. [Set it up](#claude-code-plugin).
- **Runs on your machine.** It needs no account or API token and uploads nothing. It uses the
  network only to fetch the package or repository you asked it to scan.
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

## Measured, not asserted

Detection claims are cheap, so the numbers behind them are published with the data and the code
that produced them.

- **[The MCP registry, scanned](https://github.com/pezhik/skilltotal/blob/main/docs/mcp-registry-survey.md)**:
  15,341 of the 17,535 distinct components in the official registry (87.5%), scanned with
  rulesets 56 to 59 and finished with engine 0.49.0 on 2026-09-19. Most of the rest were no longer
  reachable or exceeded a time or size bound, and every exclusion is counted. Of the components
  scanned, 88.2% expose tools to an agent, 64.8% can reach the network and 21.1% can execute shell
  commands, yet all but 116 of them score low risk, because a capability on its own scores zero. The
  rules were tuned on this population: we read every malicious-indicator hit from an earlier run by
  hand and fixed the false positives before this run.
  [Aggregates (JSON)](https://github.com/pezhik/skilltotal/blob/main/docs/mcp-registry-survey.json) ·
  [the harness](https://github.com/pezhik/skilltotal/blob/main/tests/manual_eval/survey_registry.py).
- **[Detection efficacy](https://github.com/pezhik/skilltotal/blob/main/docs/efficacy-report.md)**:
  recall and precision on a labeled corpus we built and publish (101 malicious and
  70 benign samples), regenerated every release and enforced by CI as a floor. A perfect
  score on our own corpus guards against regressions; it is not a claim about every attack in the
  wild.

The same code scanned by the same engine on the same Python version gives the same findings.
Nothing is executed and no LLM is involved. The survey read each component's latest release or
default branch when it ran, so a re-run today reads newer code.

## Install

Requires **Python 3.10+**. Zero runtime dependencies. `git` is required only for scanning
remote URLs.

For the CLI, [pipx](https://pipx.pypa.io) is recommended. It installs into an isolated environment
and also works on Debian/Ubuntu and Homebrew Python, where PEP 668 blocks a bare `pip install`:

```bash
pipx install skilltotal
```

To install into a virtual environment, or to use it as a library:

```bash
pip install skilltotal
```

You can also run it with npx. The npm package only starts this engine, so it needs uv, pipx, or
Python 3.11+ with `skilltotal` installed:

```bash
npx -y skilltotal scan https://github.com/owner/repo
```

From source (development):

```bash
pip install -e ".[dev]"
```

## Claude Code plugin

Coding agents install packages in the middle of a task, and the permission prompt, if there is
one, shows only the command. The plugin checks each package on your machine, with the same engine
as the CLI, before the install command runs. Its hook recognizes these commands:

- npm packages: `npm`/`pnpm`/`yarn`/`bun` add or install, `npx`, `bunx`, `pnpx`, `npm exec`,
  `pnpm dlx`, `yarn dlx`, `bun x` and `npm create`
- Python packages: `pip` (also as `python -m pip`), `uv`, `uvx`, `pipx`, `poetry add`, `pdm add`
  and `pipenv install`
- MCP servers: `claude mcp add` and `claude mcp add-json`

The hook reads a command the way the shell would, so it finds installs behind `sudo`, `env`,
`timeout`, `nohup`, `bash -c '...'`, `eval '...'`, `cmd /c`, `xargs` and `find -exec`. It also
finds them inside `$(...)`, `if` blocks, loops and functions; in a script piped to a shell or fed
to one through a here-document; and in chains like `cd x && npm i y`. On Windows, Claude Code runs
most commands through its PowerShell tool, and the hook also follows `$r = npm i ...`,
`& { ... }`, `iex '...'`, `Start-Process npm -ArgumentList ...` and `powershell -EncodedCommand`.
Running a program the project already has in `node_modules/.bin` (`npx tsc`) installs nothing, so
the hook does not check it.

What happens to the install:

- **Malicious indicators:** the command is denied, and the agent is told the finding and its
  file:line.
- **High or critical risk:** Claude Code asks you to approve the install and shows the top
  finding.
- **Anything SkillTotal could not check:** Claude Code asks you. This covers:
  - a package from a custom registry or index, set by an option (`--registry`, `--index-url`,
    `--extra-index-url`) or an environment variable (`npm_config_registry`, `PIP_INDEX_URL`)
  - a package name or an install command the shell builds when it runs (`npm i $PKG`)
  - an install inside a `node -e` or `python -c` one-liner
  - a direct archive URL
  - a git ref the scan cannot reproduce exactly
  - a check that failed
  - a check that did not finish within the 60 seconds that all checks of one command share (it
    goes on in the background, so the same command, run again once it is done, gets its verdict)
  - the sixth and later packages in one command
  - a package name a letter or two away from a popular one
  - a package with an install script SkillTotal could not read, or with nothing it could read
  - an error inside the hook: outside CI, SkillTotal never denies an install because of its own
    failure
- **Clean:** the package installs as usual, and the agent gets a one-line note with the version
  that was checked and its score. If part of the package could not be analyzed (code in a
  language SkillTotal does not analyze, a file too large or impossible to parse), the note says
  "partly analyzed" and lists what was left out.
- **Installs with no package name:** installs from a lockfile, manifest or requirements file (`npm ci`,
  `npm install`, `pip install -r`, `uv sync`, `poetry install`, updates such as `npm update`,
  and `uv run` in a project), from a local path (`pip install -e .`, `npm install ./dir`), or a
  script downloaded and run (`curl ... | bash`, `curl -o i.sh ... && bash i.sh`,
  `iex (irm ...)`). Outside CI they run as usual.

Every install command gets one line in the Claude Code console: what was checked and its score,
the decision and why, or what was not checked (for example "SkillTotal did not check this install:
it installs from package-lock.json, and SkillTotal checks only the packages a command names.").

**In CI (strict mode)** nobody is there to answer a question, so everything SkillTotal would ask
about is denied. So is every install it could not check, by kind: an install from a lockfile,
manifest or requirements file (`lockfile`), from a local path (`local`), a downloaded script
(`script`), and a partly analyzed package (`partial`). Strict mode is on when `CI` or one of
`TF_BUILD`, `JENKINS_URL`, `TEAMCITY_VERSION`, `CODEBUILD_BUILD_ID`, `BUILDKITE` and `GITLAB_CI` is
set to anything but empty, `0`, `false`, `no` or `off`. `SKILLTOTAL_STRICT=1` (or `true`, `yes`,
`on`) turns it on anywhere, and `SKILLTOTAL_STRICT=0` turns it off. To let some kinds through, list
them in `SKILLTOTAL_ALLOW_UNCHECKED`, for example `SKILLTOTAL_ALLOW_UNCHECKED=lockfile,local`.
Allowed kinds still get their console line. Malicious indicators are denied in and out of CI.

Packages from GitHub (`github:owner/repo#v1.2.0`, `git+https://github.com/...@ref`) are scanned
at the ref that will be installed. A verdict is reused for the same artifact (an exact npm release
or PyPI file for a week, a git repository for an hour), so repeated `npx prettier` or `uvx ruff`
calls don't trigger a rescan. When the engine version changes, everything is scanned again.

A first check takes a second or two for a small package, about 10 seconds for one the size of
`typescript` or `lodash`, and two to three minutes for the largest common ones, such as `openai`
and `django` (about 2,000 files each). All checks of one command share 60 seconds; to wait longer
before asking, set `SKILLTOTAL_HOOK_BUDGET` (in seconds, up to 100). In CI, where a question
becomes a denial, the hook waits up to 10 minutes for the full check instead (`SKILLTOTAL_HOOK_BUDGET`
goes up to 840 there). Once a package is downloaded,
the hook uses its size to estimate how long the check will take. If that does not fit in the time
left, Claude Code asks you right away instead of waiting it out. A check the hook stops waiting for
goes on in the background (two at a time at most, for up to 20 minutes) and saves its verdict, so
the same command, run again once it is done, gets that verdict at once.

In an unattended run (`claude -p`), Claude Code turns a question nobody can answer into a denial,
so a package that has not been checked yet is not installed there. Once its background check is
done, the same command goes through if the package is clean. The plugin also adds a
`/skilltotal:scan <target>` command and registers the MCP server described below.

The plugin calls the CLI, so install the CLI where Claude Code can find it: `skilltotal --version`
should work in the terminal you start Claude Code from. Outside CI, if the CLI is missing or fails
to start, install commands run unchecked; if it is older than the plugin, it still checks what it
knows. Either way, Claude Code shows a warning on each install command, so you can tell a broken
setup from a clean check. In CI, every command is denied until the CLI works, and the console line
says how to fix it.

The hook loads along with the plugins, so run `/reload-plugins` (or restart Claude Code) after
`/plugin install`. To see it work without touching a real package, ask the agent to run
`npm install --registry https://registry.example.invalid left-pad`. Claude Code should stop and ask
you, with SkillTotal's reason. Nothing is installed unless you approve.

### What the plugin does not check

- **Dependencies.** It scans the package a command names, not the packages it pulls in.
- **Installs that name no package.** `npm install`, `npm ci`, `pip install -r requirements.txt` and
  `uv sync` install from a lockfile or a requirements file, which the hook does not read. The hook
  says so in the console. In CI it denies them unless `SKILLTOTAL_ALLOW_UNCHECKED` includes
  `lockfile`.
- **Scripts and shell-profile definitions.** The hook reads only the command line. It does not
  read a script on disk (`bash install.sh`) or the aliases, functions and variables your shell
  profile defines. It does not read a script the agent downloads and runs (`curl ... | bash`)
  either. It says so in the console, and in CI it denies the command unless
  `SKILLTOTAL_ALLOW_UNCHECKED` includes `script`.
- **Minified bundles.** They are listed in the report but not analyzed. The scripts npm runs at
  install are the exception: they are analyzed even when minified.
- **Platform-specific wheels.** For a PyPI release that ships them, SkillTotal scans the source
  distribution; the wheel pip picks for your machine can differ from it. A release whose only
  wheel is pure Python is scanned as that wheel.
- **Behavior in languages other than Python, JavaScript/TypeScript and shell.** Secrets, sensitive
  paths and hidden Unicode are still checked there. The console line says the package was partly
  analyzed.

It is a static guardrail, not a sandbox. For code you don't trust, run the agent in a container.

## Usage

```bash
# Human-readable report
skilltotal scan ./path/to/component

# Scan a remote repository (shallow git clone)
skilltotal scan https://github.com/owner/repo

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

# SARIF 2.1.0 (GitHub Code Scanning / IDE)
skilltotal scan ./component --sarif --output report.sarif

# Write the report to a file (SARIF if --sarif, else JSON)
skilltotal scan ./component --output report.json

# CI gate: exit code 2 by finding severity or by risk score
skilltotal scan ./component --fail-on-high             # alias for --fail-on high
skilltotal scan ./component --fail-on medium
skilltotal scan ./component --fail-on-score 50
# ...or when part of the component could not be analyzed: unreadable, too large or unparseable
# files, or code in a language SkillTotal does not analyze (binaries and dependency folders don't count)
skilltotal scan ./component --fail-on-unanalyzed

# Skip paths (repeatable; combined with the config file's `exclude`)
skilltotal scan ./component --exclude "vendor/*" --exclude "*.min.js"

# Opt-in provenance for npm:/pypi: sources (registry metadata -> needs_review, never scored)
skilltotal scan npm:some-lib --provenance

# Baseline: snapshot current findings, then suppress them on later scans
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
skilltotal guard --installed            # check every AI component already on this machine
skilltotal guard npm:x --block-on malicious   # block only on malicious indicators

# Inventory: discover AI components already installed on this machine and scan them
# (reads agent configs for Claude Desktop/Code, Cursor, Windsurf, VS Code, Gemini, and
#  local skills; derives an npm:/pypi:/local source per MCP server and runs the engine)
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
`(rule id, file, code snippet)` — independent of line numbers, so it survives edits.
Suppressed findings are removed before scoring and do not affect the risk score.

**Diff** reports new / resolved / changed findings, evidence-level additions and removals
(matched by the same line-independent fingerprint as the baseline, so pure line shifts are
not noise), capability changes, and the risk-score delta. `--fail-on-new LEVEL` gates only
on risk the new version *introduces* — existing accepted findings never trip it, so it fits
upgrade reviews ("is 1.2.4 riskier than the 1.2.3 we already vetted?") without a baseline
file.

**Guard** is the install-time answer to "should I trust this component right now?".
Malicious indicators always block; scored risk at/above `--block-on` blocks;
**capabilities alone never block** — a legitimate MCP server with shell/network access
passes, so the guard stays quiet enough to leave enabled everywhere. Unlike `--fail-on`, it
weighs the aggregate risk level rather than single findings. It also does not block a package for
a secret it ships: that puts the publisher at risk, not the person installing the package.

**Provenance** (`--provenance`, opt-in) adds registry-metadata signals for `npm:` /
`pypi:` sources: *recently published*, *deprecated / yanked*, *no recent releases*, *no
repository link*. Metadata is context about a component, not component content — so these
signals go to `needs_review` and **never** affect the score or verdict, and the default
scan stays component-only.

**Project config** (optional) — commit a `.skilltotal.toml` instead of repeating flags
(CLI flags override it):

```toml
fail_on = "high"           # low | medium | high | critical
fail_on_score = 50         # or gate on the 0-100 risk score
fail_on_unanalyzed = true  # or when part of the component could not be analyzed (true/false)
exclude = ["vendor/*", "*.min.js"]
ignore = ["ST-NET-PY"]     # rule ids to drop
baseline = ".skilltotal-baseline.json"

# Per-rule policy: reviewable gate decisions that live in the repo, not in a dashboard.
[policy]
"ST-SHELL-PIPE-EXEC" = "block"   # gate trips (exit 2) whenever this rule fires,
                                 # even with no fail_on configured
"ST-DESERIALIZE-PY" = "warn"     # explicit accept-but-show: reported, still counts toward
                                 # the risk score, but exempt from the fail_on severity gate
"ST-SENS-WORD" = "ignore"        # suppressed entirely (same effect as `ignore`)
```

To suppress a single finding, put a `# skilltotal:ignore` (or `# skilltotal:ignore[ST-ID]`)
comment on its line. Inline markers count only when you scan a local directory (your own code,
as in CI). In a package or repository that SkillTotal downloads they are ignored, so a package
cannot silence its own findings.

`python -P -m skilltotal ...` (Python 3.11+) works like the `skilltotal` console script. Plain
`python -m` puts the current directory first on the import path, so never run it from inside a
directory you are scanning: a `json.py` there would run instead of the one in the standard library.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Usage or collection error (for example an unknown flag value, a missing path or a failed clone) |
| 2 | A configured gate tripped (`--fail-on`/`--fail-on-high` severity, `--fail-on-score`, `--fail-on-unanalyzed` or `diff --fail-on-new`), or `guard` blocked the component |

> **Gate semantics:** `--fail-on`/`--fail-on-high` trip on the **severity of a single finding**,
> not the aggregate `risk_score`. They count risk findings: a malicious indicator at any severity,
> and a risky construct or a shipped secret at or above the level you set. A *capability*, such as
> shell or network access, is what a component can do. It is reported but never trips the gate on
> its own; to forbid one, give its rule a `block` policy. The gate also fails closed on what the
> scan could not read: an install script it could not analyze, or a component with nothing it
> could read. A component can therefore report `risk_level: low` and still fail the gate on one
> high-severity risky construct. To gate on the score instead, use `--fail-on-score`; to accept
> known findings, use a baseline, an inline `# skilltotal:ignore[ST-ID]`, or a per-rule `[policy]`
> action (`block` / `warn` / `ignore`).

## CI / GitHub Action

Run SkillTotal in CI and surface findings in your repository's **Security → Code scanning** tab.

```yaml
# .github/workflows/skilltotal.yml
name: SkillTotal
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # required to upload SARIF to Code Scanning
  pull-requests: write     # required only for comment-on-pr (optional)
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: pezhik/skilltotal@v0.65.0
        with:
          source: .             # a path, a git URL, or an npm:/pypi:<name> spec
          fail-on: high         # fail on a high/critical risk finding (or 'none')
          fail-on-unanalyzed: 'false' # 'true': also fail when part of it could not be analyzed
          comment-on-pr: 'true' # post a sticky summary comment on pull requests (optional)
```

The action runs the engine that ships with the tag you pin, so nothing is downloaded from PyPI. It
scans `source` and uploads SARIF (so findings appear inline on pull requests and in Code Scanning).
It fails the job on a finding at or above `fail-on` (`low`, `medium`, `high`, `critical`; `none`
never fails). The gate semantics above apply: a malicious indicator fails the job at any severity,
and a capability on its own, such as a shell call or network access, never does. With
`fail-on-unanalyzed: 'true'` it also fails the job when part of the component could not be
analyzed, as `--fail-on-unanalyzed` does.

With `comment-on-pr: 'true'`, the action posts a single summary comment on the pull request (risk
level, score, findings, capabilities) and updates it in place on later runs. The comment is off by
default and needs `pull-requests: write`. Pin the action to a released tag (see
[Releases](https://github.com/pezhik/skilltotal/releases)), or to that release's commit SHA
(`pezhik/skilltotal@<commit> # vX.Y.Z`), which, unlike a tag, cannot be moved. Set the
`version:` input only to run a different engine release from PyPI. Without the action, the same
scan is `skilltotal scan . --sarif --output skilltotal.sarif --fail-on-high`.

### Use as a pre-commit hook

Run SkillTotal on every commit via [pre-commit](https://pre-commit.com):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pezhik/skilltotal
    rev: v0.65.0
    hooks:
      - id: skilltotal
        args: [".", "--fail-on-high"]   # scan the repo; block the commit on a high/critical finding
```

Then `pre-commit install`. The hook installs the CLI in its own environment and scans the repo
on commit; tune the scan with the same flags as the CLI (e.g. `--exclude`, `--fail-on`).

### Use as an MCP server

Let your agent check a component *before* installing it. `skilltotal mcp` runs the engine
as a stdio MCP server (stdlib-only, still zero dependencies) — register it in Claude
Code/Desktop, Cursor, Windsurf, or any MCP client:

```json
{ "mcpServers": { "skilltotal": { "command": "skilltotal", "args": ["mcp"] } } }
```

If you have not installed it locally, use `"command": "npx", "args": ["-y", "skilltotal", "mcp"]`
instead. This needs uv, pipx, or Python 3.11+ with `skilltotal`.

Tools exposed: `scan_component` (full report for a path / git URL / `npm:` / `pypi:`
source), `diff_components` (upgrade review: what changed between two versions), and
`list_rules`. Scans run locally with the same never-execute static engine — the component's
code is not uploaded anywhere.

### Add a status badge

Scan a component on [skilltotal.ai](https://www.skilltotal.ai) and each report offers an
**"Add this badge"** snippet — a small SVG that always reflects the component's latest scan and
links back to the full report. Drop it in your README so visitors see the risk at a glance:

```markdown
[![SkillTotal](https://www.skilltotal.ai/…/badge?source=npm:your-package)](https://www.skilltotal.ai)
```

Copy the exact, ready-to-paste markdown from the report page — it fills in the badge URL for you.

## Methodology

SkillTotal performs **static** security analysis of AI components — MCP servers, agent
skills/plugins, npm and PyPI packages, and AI-generated projects/repositories. The engine
combines capability analysis, dangerous-pattern detection, privilege analysis, supply-chain
(install-time) analysis, prompt-surface analysis, and data-flow correlation (e.g. secret
access combined with network egress). Findings are mapped to risk categories and contribute to
a **0–100 risk score**; capabilities are reported but never inflate the score — capability ≠ risk.
Nothing is executed and no LLM is called, so results are deterministic and reproducible.

## What it detects

| Category | Examples |
|----------|----------|
| Shell execution | `subprocess.*`, `os.system`, `child_process.exec` |
| Filesystem access | `open`, `read_text`/`write_text`, `fs.readFile`/`writeFile` |
| Sensitive paths | `~/.ssh`, `~/.aws`, `.env`, `id_rsa`, `credentials`, `secrets` |
| Network egress | `requests`, `urllib`, `aiohttp`, `fetch`, `axios` |
| Install-time execution | npm `preinstall`/`postinstall`/`prepare`, `setup.py` hooks |
| Dynamic code execution | `eval`, `exec`, `compile`, `new Function`, `vm.runInNewContext` |
| Obfuscation | decode-and-execute chains, base64 blobs, hex escaping, minification |
| MCP risks | manifests, dangerous tools (shell/fs/network/credential), server commands |
| Prompt surface | "ignore previous instructions", "reveal system prompt", exfiltration phrasing |

### Coverage by component type

Legend: **✅** analyzed by default for this component type · **⚠️** the engine detects this, but
that surface is uncommon for this type — so it is flagged only when the component actually contains
it (e.g. prompt-injection text inside an npm/PyPI package) · **❌** not applicable to this type.

Columns are the component types SkillTotal scans. **AI project** = a scanned repository or folder
— an agent skill/plugin, an AI-generated codebase, or a set of prompts/configs — that is not a
published npm/PyPI package.

| Category | MCP | npm | PyPI | AI project |
|---|---|---|---|---|
| Prompt injection / instruction override | ✅ | ⚠️ | ⚠️ | ✅ |
| Tool poisoning (MCP tool and parameter descriptions) | ✅ | ❌ | ❌ | ⚠️ |
| Dangerous capabilities (shell / fs / network) | ✅ | ✅ | ✅ | ⚠️ |
| Data exfiltration (secret access + egress) | ✅ | ✅ | ✅ | ⚠️ |
| Secret theft / sensitive-path access | ✅ | ✅ | ✅ | ⚠️ |
| Dynamic code execution | ✅ | ✅ | ✅ | ⚠️ |
| Obfuscation (decode-and-execute) | ✅ | ✅ | ✅ | ✅ |
| Hidden-Unicode smuggling (tag, bidi control and zero-width characters) | ✅ | ✅ | ✅ | ✅ |
| Embedded secrets (hardcoded keys/tokens) | ✅ | ✅ | ✅ | ✅ |
| Install-time / supply-chain hooks | ⚠️ | ✅ | ✅ | ❌ |
| Overprivileged tools, auto-approve keys in MCP server entries | ✅ | ❌ | ❌ | ⚠️ |

Each row names what the engine checks today. Not checked yet: nested schema fields, prompts,
resources and server instructions; Unicode variation selectors and ANSI terminal escape
sequences; auto-approve settings that agent hosts keep outside MCP server entries.

### Typical findings

- An MCP tool can execute arbitrary shell commands
- A package downloads and runs code from an external URL
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

## Out of scope

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

## Output

A normalized report containing the component identity, a **risk score (0–100)** and
**risk level** (low / medium / high / critical), detected **capabilities** (each
evidence-backed), a behavioral **trait fingerprint** (with a CSA / MAESTRO / MITRE ATLAS
crosswalk), **findings**, **needs_review**, and **metadata**. See
[docs/report-schema.md](https://github.com/pezhik/skilltotal/blob/main/docs/report-schema.md) and [docs/scoring.md](https://github.com/pezhik/skilltotal/blob/main/docs/scoring.md).

Every finding also carries its **OWASP Agentic Skills Top 10** category ids (`owasp`), emitted in
both the JSON report and SARIF (native `taxonomies`/`relationships`);
[docs/owasp-agentic-skills-mapping.md](https://github.com/pezhik/skilltotal/blob/main/docs/owasp-agentic-skills-mapping.md) explains the coverage
(AST01–AST05) and the honest gaps. For MCP servers,
[docs/mcp-owasp-mapping.md](https://github.com/pezhik/skilltotal/blob/main/docs/mcp-owasp-mapping.md) maps SkillTotal's checks to the OWASP MCP
Security Cheat Sheet (and names the runtime controls a static engine can't cover).

The report's **`traits`** array is a behavioral fingerprint — a higher-level projection over the
findings (e.g. `execution_authority`, `embedded_credential`, `untrusted_perception`, and the
*emergent* `exfil_correlation` combination) — each mapped to the Cloud Security Alliance
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

## Accuracy notes

- Python is analyzed via an **AST** (resolves import aliases, tells `open(p,'w')` from a
  read, ignores API names that only appear in strings/comments). Node.js/config use regex.
- **Languages:** shell execution, network access, file access and dynamic code are detected in
  Python and JavaScript/TypeScript. Go, Rust, Java, Ruby, PHP, C/C++, C#, Swift, Kotlin, Scala,
  Dart, Lua, Perl, Elixir, Groovy, Haskell, Clojure, Erlang, R and Zig files still get the secret,
  sensitive-path and hidden-Unicode checks, but their behavior is not analyzed yet. If a component
  ships code in those languages, the report adds a `needs_review` note, and a low verdict reads
  "Partially analyzed" instead of "No significant risks found".
- **Test code** (`__tests__/`, `*.test.*`, `tests/`, `conftest.py`, …) is demoted to
  `needs_review` — it is not executed by consumers, so it does not affect the score.
- Ambiguous signals (bare `secrets`/`credentials` words, lone base64 blobs, "before
  answering" phrasing, minified files) go to `needs_review`, never to `findings`.
- **Hidden Unicode** (ASCII-smuggling tag characters, Trojan-Source bidi overrides,
  zero-width chars) is detected and decoded — a real evasion used to smuggle instructions
  past human review. See `tests/manual_eval/` for calibration against real-world attacks.
- Shell execution covers `subprocess`/`os.system`, `asyncio.create_subprocess_*`, Node
  `child_process`, and common process-spawning libraries (Python `sh`/`plumbum`/`pexpect`/
  `invoke`/`fabric`; Node `zx`/`execa`/`cross-spawn`/`shelljs`/`tinyexec`/`node-pty`).
- MCP dangerous tools are classified by name/description both in JSON manifests **and when
  defined in code** (`server.tool("run_command", …)`, `@mcp.tool` over `def read_file`).
- **Limitations:** detection is at the call/import level. Capability via an *unrecognized*
  higher-level library (e.g. a git library that writes files internally, a browser library)
  may not be flagged as a raw filesystem/shell call. Capabilities indicate *presence*, not
  proven misuse.

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
