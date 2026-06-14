# SkillTotal

[![PyPI](https://img.shields.io/pypi/v/skilltotal)](https://pypi.org/project/skilltotal/)
[![Python](https://img.shields.io/pypi/pyversions/skilltotal)](https://pypi.org/project/skilltotal/)
[![License](https://img.shields.io/pypi/l/skilltotal)](LICENSE)
[![CI](https://github.com/pezhik/skilltotal/actions/workflows/ci.yml/badge.svg)](https://github.com/pezhik/skilltotal/actions/workflows/ci.yml)

**AI Component Security Platform — open-source CLI engine.**

SkillTotal statically analyzes AI-related components (skills, plugins, MCP servers, npm /
Python packages, repositories) to surface supply-chain risks, dangerous capabilities,
prompt-injection surfaces, and data-exfiltration paths **before** the component is installed
or trusted.

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

# CI gate: exit code 2 if any finding is high or critical
skilltotal scan ./component --fail-on-high

# Baseline: snapshot current findings, then suppress them on later scans
skilltotal scan ./component --write-baseline .skilltotal-baseline.json
skilltotal scan ./component --baseline .skilltotal-baseline.json --fail-on-high

# Inventory: discover AI components already installed on this machine and scan them
# (reads agent configs for Claude Desktop/Code, Cursor, Windsurf, VS Code, Gemini, and
#  local skills; derives an npm:/pypi:/local source per MCP server and runs the engine)
skilltotal inventory
skilltotal inventory --json
skilltotal inventory --no-scan          # list only, do not scan
skilltotal inventory --project .        # also include this project's agent configs

# List every detection rule
skilltotal rules list
skilltotal rules list --json
```

**Baseline** suppresses findings by a stable fingerprint of
`(rule id, file, code snippet)` — independent of line numbers, so it survives edits.
Suppressed findings are removed before scoring and do not affect the risk score.

`python -m skilltotal ...` works identically to the `skilltotal` console script.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Usage / collection error (e.g. path missing, clone failed) |
| 2 | `--fail-on-high` set and a finding of severity ≥ high was produced |

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

What the engine surfaces depends on the surfaces a component actually exposes. **✅** native /
primary surface · **⚠️** covered when that surface is present in the component · **❌** not
applicable · **🚧** planned (SkillTotal Cloud).

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
evidence-backed), **findings**, **needs_review**, and **metadata**. See
[docs/report-schema.md](docs/report-schema.md) and [docs/scoring.md](docs/scoring.md).

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
