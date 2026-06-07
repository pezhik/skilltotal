# SkillTotal

**AI Component Security Platform — open-source CLI engine.**

SkillTotal statically analyzes AI-related components (skills, plugins, MCP servers, npm /
Python packages, repositories) to surface supply-chain risks, dangerous capabilities,
prompt-injection surfaces, and data-exfiltration paths **before** the component is installed
or trusted.

It analyzes **only the component itself** — never your user, company, environment,
deployment, or runtime context. Every score and finding is derived exclusively from the
files inside the component.

> Core principle: **every confirmed finding carries evidence** (file, line range, code
> snippet). Anything that cannot be evidenced is placed in `needs_review`, never in
> `findings`, and never affects the score.

## Install

Requires **Python 3.10+**. Zero runtime dependencies. `git` is required only for scanning
remote URLs.

```bash
pip install -e .
```

## Usage

```bash
# Human-readable report
skilltotal scan ./path/to/component

# Scan a remote repository (shallow git clone)
skilltotal scan https://github.com/owner/repo

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
