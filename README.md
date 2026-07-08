# SkillTotal

[![PyPI](https://img.shields.io/pypi/v/skilltotal)](https://pypi.org/project/skilltotal/)
[![Python](https://img.shields.io/pypi/pyversions/skilltotal)](https://pypi.org/project/skilltotal/)
[![License](https://img.shields.io/pypi/l/skilltotal)](LICENSE)
[![CI](https://github.com/pezhik/skilltotal/actions/workflows/ci.yml/badge.svg)](https://github.com/pezhik/skilltotal/actions/workflows/ci.yml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-SkillTotal-2ea44f?logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/skilltotal-ai-component-security-scan)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/pezhik/skilltotal/badge)](https://scorecard.dev/viewer/?uri=github.com/pezhik/skilltotal)

**AI Component Security Platform — open-source CLI engine.**

SkillTotal statically analyzes AI-related components — agent skills/plugins, MCP servers, npm /
Python packages, repositories, and **AI-generated projects you upload as an archive or file** — to
surface supply-chain risks, dangerous capabilities, prompt-injection surfaces, and data-exfiltration
paths **before** the component is installed or trusted. Point it at a path, a git URL, an
`npm:` / `pypi:` package, or a project archive (`.zip` / `.tar.gz`) / single file.

**Try it online (no install, no account):** [www.skilltotal.ai](https://www.skilltotal.ai) —
the website runs this same engine. Prefer the CLI? `pipx install skilltotal` (below).

It analyzes **only the component itself** — never your user, company, environment,
deployment, or runtime context. Every score and finding is derived exclusively from the
files inside the component.

> Core principle: **every confirmed finding carries evidence** (file, line range, code
> snippet). Anything that cannot be evidenced is placed in `needs_review`, never in
> `findings`, and never affects the score.

## Why SkillTotal

- **100% local & offline** — the component's code **never leaves your machine**. No account,
  no API token, no cloud upload (unlike cloud scanners that send your components to a backend).
- **Safe to point at untrusted components** — the engine analyzes without ever running them on
  your machine. (Optional dynamic analysis is a separate paid service that runs only in our
  isolated sandbox, with your consent.)
- **Zero runtime dependencies**, pure Python stdlib — auditable and easy to vendor/air-gap.
- **Deterministic** — regex + AST, no LLM in the static engine; the same input always yields
  the same report.
- **Evidence-anchored & low false-positive** — every finding points at an exact file:line.
- **Free and open source** (Apache-2.0) — the full static report is free, forever.

## Install

Requires **Python 3.10+**. Zero runtime dependencies. `git` is required only for scanning
remote URLs.

Recommended for the CLI — [pipx](https://pipx.pypa.io) (isolated install; also works on
Debian/Ubuntu where bare `pip install` is blocked by PEP 668):

```bash
pipx install skilltotal
```

Or into a virtual environment / as a library:

```bash
pip install skilltotal
```

From source (development):

```bash
pip install -e ".[dev]"
```

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

# CI gate: exit code 2 by severity level or by risk score
skilltotal scan ./component --fail-on-high             # alias for --fail-on high
skilltotal scan ./component --fail-on medium
skilltotal scan ./component --fail-on-score 50

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
passes, so the guard stays quiet enough to leave enabled everywhere (unlike a raw
`--fail-on high` gate, which would trip on most of the ecosystem's honest capability
findings).

**Provenance** (`--provenance`, opt-in) adds registry-metadata signals for `npm:` /
`pypi:` sources: *recently published*, *deprecated / yanked*, *no recent releases*, *no
repository link*. Metadata is context about a component, not component content — so these
signals go to `needs_review` and **never** affect the score or verdict, and the default
scan stays 100% component-only and offline.

**Project config** (optional) — commit a `.skilltotal.toml` instead of repeating flags
(CLI flags override it):

```toml
fail_on = "high"           # low | medium | high | critical
fail_on_score = 50         # or gate on the 0-100 risk score
exclude = ["vendor/*", "*.min.js"]
ignore = ["ST-NET-PY"]     # rule ids to drop
baseline = ".skilltotal-baseline.json"

# Per-rule policy: reviewable gate decisions that live in the repo, not in a dashboard.
[policy]
"ST-SHELL-PIPE-EXEC" = "block"   # gate trips (exit 2) whenever this rule fires,
                                 # even with no fail_on configured
"ST-DYN-PY" = "warn"             # explicit accept-but-show: reported, still counts toward
                                 # the risk score, but exempt from the fail_on severity gate
"ST-SENS-WORD" = "ignore"        # suppressed entirely (same effect as `ignore`)
```

Suppress a single finding inline with a `# skilltotal:ignore` (or `# skilltotal:ignore[ST-ID]`)
comment on its line.

`python -m skilltotal ...` works identically to the `skilltotal` console script.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Usage / collection error (e.g. path missing, clone failed) |
| 2 | A configured gate tripped (`--fail-on`/`--fail-on-high` severity, `--fail-on-score`, or `diff --fail-on-new`) |

> **Gate semantics:** `--fail-on`/`--fail-on-high` trip on the **severity of any single finding**,
> not the aggregate `risk_score`. A component can report `risk_level: low` (score 0) and still fail
> the gate if it has a high-severity finding — including a powerful *capability* (e.g. shell or
> network access), which is reported but never scored as malicious. To gate on the score instead,
> use `--fail-on-score`; to accept known findings, use a baseline, an inline
> `# skilltotal:ignore[ST-ID]`, or a per-rule `[policy]` action (`block` / `warn` / `ignore`).

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
      - uses: actions/checkout@v4
      - uses: pezhik/skilltotal@v0.36.0
        with:
          source: .             # a path, a git URL, or an npm:/pypi:<name> spec
          fail-on: high         # fail the build on a high/critical finding (or 'none')
          comment-on-pr: 'true' # post a sticky summary comment on pull requests (optional)
```

The action installs the CLI, scans `source`, uploads SARIF (so findings appear inline on pull
requests and in Code Scanning), and fails the job on a high/critical finding unless
`fail-on: none`. On pull requests, `comment-on-pr: 'true'` posts a single summary comment (risk
level, score, findings, capabilities) and updates it in place on later runs — it needs
`pull-requests: write` and is off by default. Pin the action to a released tag (see
[Releases](https://github.com/pezhik/skilltotal/releases)) and, optionally, pin the engine version
with the `version:` input. Prefer plain CLI? It is the same thing:
`skilltotal scan . --sarif --output skilltotal.sarif --fail-on-high`.

### Use as a pre-commit hook

Run SkillTotal on every commit via [pre-commit](https://pre-commit.com):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pezhik/skilltotal
    rev: v0.36.0
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
it (e.g. prompt-injection text inside an npm/PyPI package) · **❌** not applicable to this type ·
**🚧** planned (SkillTotal Cloud).

Columns are the component types SkillTotal scans. **AI project** = a scanned repository or folder
— an agent skill/plugin, an AI-generated codebase, or a set of prompts/configs — that is not a
published npm/PyPI package.

| Category | MCP | npm | PyPI | AI project |
|---|---|---|---|---|
| Prompt injection / instruction override | ✅ | ⚠️ | ⚠️ | ✅ |
| Tool poisoning (MCP tool metadata) | ✅ | ❌ | ❌ | ⚠️ |
| Dangerous capabilities (shell / fs / network) | ✅ | ✅ | ✅ | ⚠️ |
| Data exfiltration (secret access + egress) | ✅ | ✅ | ✅ | ⚠️ |
| Secret theft / sensitive-path access | ✅ | ✅ | ✅ | ⚠️ |
| Dynamic code execution | ✅ | ✅ | ✅ | ⚠️ |
| Obfuscation (decode-and-execute) | ✅ | ✅ | ✅ | ✅ |
| Hidden-Unicode smuggling | ✅ | ✅ | ✅ | ✅ |
| Embedded secrets (hardcoded keys/tokens) | ✅ | ✅ | ✅ | ✅ |
| Install-time / supply-chain hooks | ⚠️ | ✅ | ✅ | ❌ |
| Overprivileged / auto-approved tools | ✅ | ❌ | ❌ | ⚠️ |
| Runtime behavior analysis | 🚧 | 🚧 | 🚧 | 🚧 |
| Sandbox analysis | 🚧 | 🚧 | 🚧 | 🚧 |

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
  shell — a proven injection path, not just a dangerous API in isolation
- An **agent skill** does more than its declared `allowed-tools` allow (undeclared capability /
  least-privilege violation)

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

Runtime behavior and sandbox analysis are planned for **SkillTotal Cloud** (paid).

## Output

A normalized report containing the component identity, a **risk score (0–100)** and
**risk level** (low / medium / high / critical), detected **capabilities** (each
evidence-backed), a behavioral **trait fingerprint** (with a CSA / MAESTRO / MITRE ATLAS
crosswalk), **findings**, **needs_review**, and **metadata**. See
[docs/report-schema.md](docs/report-schema.md) and [docs/scoring.md](docs/scoring.md).

Every finding also carries its **OWASP Agentic Skills Top 10** category ids (`owasp`), emitted in
both the JSON report and SARIF (native `taxonomies`/`relationships`);
[docs/owasp-agentic-skills-mapping.md](docs/owasp-agentic-skills-mapping.md) explains the coverage
(AST01–AST05) and the honest gaps. For MCP servers,
[docs/mcp-owasp-mapping.md](docs/mcp-owasp-mapping.md) maps SkillTotal's checks to the OWASP MCP
Security Cheat Sheet (and names the runtime controls a static engine can't cover).

The report's **`traits`** array is a behavioral fingerprint — a higher-level projection over the
findings (e.g. `execution_authority`, `embedded_credential`, `untrusted_perception`, and the
*emergent* `exfil_correlation` combination) — each mapped to the Cloud Security Alliance
trait-based model, a MAESTRO threat-model layer, and a MITRE ATLAS tactic where there is an honest
fit. It is descriptive and never affects the score; see
[docs/trait-crosswalk.md](docs/trait-crosswalk.md).

## Architecture

The package under `skilltotal/` (except `cli.py`) is a pure, side-effect-free library so the
same engine can power the future web app and enterprise SaaS. See
[docs/architecture.md](docs/architecture.md).

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Accuracy notes

- Python is analyzed via an **AST** (resolves import aliases, tells `open(p,'w')` from a
  read, ignores API names that only appear in strings/comments). Node.js/config use regex.
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

SkillTotal is **open core**. This engine (analysis + all detection rules + CLI) is open source
and **complete on its own** — run it locally or in CI, free, offline, with zero runtime
dependencies. It tells you **what** a component does, with evidence.

Paid features are delivered only via **SkillTotal Cloud** (the website) and explain **why it
matters**: LLM interpretation and prioritization of findings, dynamic sandbox execution,
hosting, scan history, and monitoring. They are server-side services on top of this engine —
their code is not part of this repository. See [docs/open-core.md](docs/open-core.md).

## License

[Apache-2.0](LICENSE). See also [NOTICE](NOTICE).
