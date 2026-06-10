# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

SkillTotal is an **AI Component Security Platform** — a CLI engine that statically analyzes
AI-related components (skills, plugins, MCP servers, npm/Python packages, repos) for
supply-chain risks, dangerous capabilities, prompt-injection surfaces, and exfiltration
paths. This phase is **CLI-only**, but the core is built to be reused by future web/SaaS
products.

## Commands

```bash
# Install (editable) + dev deps
pip install -e ".[dev]"

# Run the full test suite (pytest config lives in pyproject.toml; addopts = -q)
pytest

# Run one test file / one test
pytest tests/test_scoring.py
pytest tests/test_scoring.py::test_combo_rule_fires_when_fs_and_network_present

# Security checks (required on every change — see memory + SECURITY.md)
bandit -r skilltotal          # static security scan (clean = exit 0)
pre-commit install            # once: enables gitleaks/detect-secrets/ruff/bandit on commit

# Run the CLI (console script or module form — identical)
skilltotal scan <path-or-url> [--json | --sarif] [--output FILE] [--fail-on-high]
skilltotal scan <path-or-url> [--baseline FILE | --write-baseline FILE]
skilltotal rules list [--json]
python -m skilltotal scan <path-or-url>
```

**Zero runtime dependencies** (Python stdlib only); dev deps (`pip install -e ".[dev]"`)
cover testing/lint/security/build. Requires Python 3.10+. `git` is required only for scanning
remote URLs. Secret-leak defense is layered: pre-commit (gitleaks/detect-secrets) → CI
`secrets` job (gitleaks) → GitHub push protection → OIDC publishing (no stored tokens); see
`SECURITY.md`.

On Windows PowerShell, do **not** pipe between two `python` processes (encoding corruption);
use a script file or one process.

## Non-negotiable invariants

These define the product and are enforced in code — preserve them in any change:

1. **Every confirmed `Finding` carries evidence.** `Finding.__post_init__` (models.py)
   raises if `evidence` is empty. Signals that cannot be anchored to a file/line/snippet
   must be emitted as `NeedsReview`, never as `Finding`, and `NeedsReview` **never affects
   the score**.
2. **Component-only analysis.** Derive everything from files inside the component — never
   from user/company/environment/deployment/runtime context.
3. **Never execute analyzed code, never call an LLM.** Detection is deterministic regex +
   targeted JSON/markdown parsing. (Security hooks may flag `eval`/`os.system` in scanner
   regexes — those are *detection string literals*, not calls.)
4. **Interpret evidence only.** Descriptions may explain what a matched API does
   ("child_process.exec enables shell execution"); they must not assert unproven intent
   ("this steals secrets").

## Architecture (the big picture)

Pipeline: **Discover → Detect → Normalize → Report**, wired in `engine.py`.

```
collector.py → file_index.py → scanners/* → capabilities.py + scoring.py → engine.Report → report.py / cli.py
```

- **Reuse boundary:** everything under `skilltotal/` is a pure library (no `print`, no
  `sys.exit`) **except `cli.py`**, which is the only I/O shell. Web/SaaS should import
  `engine.analyze_directory(root, component)` and serialize `Report.to_dict()`.
- **`collector.py`** resolves a local dir or git URL (shallow clone to a temp dir,
  auto-cleaned via `SourceContext` context manager) and derives `Component` identity.
- **`file_index.py`** walks once (skips VCS/dependency dirs + binaries), caches text, and
  precomputes line-start offsets. `IndexedFile.evidence_for_span()` is the single place that
  maps a regex match offset → exact `Evidence(file, line_start, line_end, snippet)`. All
  evidence flows through here.
- **`scanners/`** — each scanner returns `ScanResult(findings, needs_review)` and is
  registered in `scanners/__init__.py` (`SCANNERS`). Three flavors:
  - **AST** (`python_ast.py`): owns **all Python detection** (shell/fs/network/dynamic).
    It walks `ast`, resolves `import ... as` aliases and `from ... import` names, and tells
    `open(p,'w')` (write) from `open(p)` (read). Files that fail `ast.parse` fall back to the
    regex on each `RuleSpec` and are flagged in `needs_review`.
  - **Declarative regex** (shell_exec, filesystem, network, dynamic_code — **Node.js only**;
    sensitive_paths, install_scripts): subclass `PatternScanner`, declare `RuleSpec`;
    matching is done generically by `findings_from_rules`.
  - **Custom** (mcp, obfuscation, prompt_surface): subclass `Scanner`, implement `scan()`,
    but still declare `RuleSpec` metadata so `rules list` and capability extraction see them.
  - Python rule ids (`ST-SHELL-PY`, `ST-FS-PY-READ/WRITE`, `ST-NET-PY`, `ST-DYN-PY`) live in
    `python_ast.py`; the Node regex scanners use `-NODE` ids. Obfuscation `ST-OBF-DECODE-EXEC`
    covers both languages across all files.
  - `mcp.py` classifies dangerous tools (shell/fs/network/browser/credential) in JSON
    manifests *and* in code (`server.tool("name",…)`, `@mcp.tool` over `def name`).
  - `invisible_unicode.py` flags hidden Unicode (tag chars / bidi / zero-width), renders it
    as `<U+XXXX>`, and decodes smuggled ASCII into the evidence.
- **`RuleSpec` (scanners/base.py) is the single source of truth** for a rule: id, severity,
  text, the `Capability` it implies, and (optionally) the regex + file selection.
- **`capabilities.py`** is a pure projection over findings — it regroups finding evidence by
  each rule's declared `capability`; it never re-scans files.
- **Test-code demotion** — `engine._split_test_evidence` (using `file_index.is_test_path`)
  moves evidence found only in test code (`__tests__/`, `*.test.*`, `tests/`, `conftest.py`,
  …) into `needs_review`, so test code never drives capabilities or the score. Findings with
  both prod and test evidence keep only the prod evidence.
- **`baseline.py`** — fingerprints `(rule id, file, snippet)` (line-independent) to suppress
  accepted findings; `engine.analyze_directory(..., suppress=set)` drops them before scoring.
- **`sarif.py`** — renders SARIF 2.1.0 (one result per evidence; severity → level +
  `security-severity`). Driven off the same `rules.get_rules()` registry as `rules list`.
- **`scoring.py`** — score = `min(100, Σ severity weight)` (one finding per rule, so score
  reflects distinct risks, not match counts). Severity weights and risk-level bands live on
  the `Severity`/`RiskLevel` enums in `models.py`. The **filesystem + network ⇒ critical**
  rule is a *synthesized finding* (`ST-COMBO-FS-NET`) with merged evidence, added in
  `engine.py` after capabilities are computed.

## Conventions

- Strongly-typed `@dataclass` models (models.py); enums subclass `str` so they serialize to
  JSON directly. Use `pathlib` throughout.
- Rule ids are `ST-<AREA>-<...>` (e.g. `ST-SHELL-PY`, `ST-MCP-DANGEROUS-TOOL`).
- One `Finding` per rule aggregates all matches as capped evidence
  (`MAX_EVIDENCE_PER_FINDING`).

## Versioned contract (engine ↔ consumers)

The engine is meant to be consumed by a separate web/SaaS product (private repo) that pins it
as a PyPI dependency. The contract is three independent versions in `skilltotal/__init__.py`:
`ENGINE_VERSION` (code/API, semver), `REPORT_SCHEMA_VERSION` (shape of `Report.to_dict()`),
`RULESET_VERSION` (detection set, integer). All three appear in report `metadata`.

`docs/report.schema.json` is the formal JSON Schema contract; `tests/test_report_schema.py`
validates every fixture report against it and **fails if the report shape changes without a
schema update** — so a contract change is always deliberate. Version-bump rules:
`docs/releasing.md`. Never make the runtime engine depend on third-party packages (zero-dep);
`jsonschema` is dev-only.

**Docs ship with releases.** The package is public on PyPI (`skilltotal`, OIDC release on
`v*` tags). `README.md` is the PyPI long description — frozen into the artifact at tag time,
so review Install/Usage before tagging. The version lives ONLY in
`skilltotal/__init__.py::__version__` (pyproject reads it dynamically).
`tests/test_release_hygiene.py` blocks a release with a stale CHANGELOG/README/schema-id;
update docs in the same commit as the change they describe, not "later".

## Open-core boundary (what belongs here vs the private web app)

This repo is the **open-source engine** (Apache-2.0). It is the full, free, offline,
zero-dep static analyzer + CLI + **all** detection rules — it answers *what* a component does.
Paid features live only in the private `skilltotal-web` repo (server-side services on top of
the engine) and answer *why it matters*. See `docs/open-core.md`.

**Never add to this repo:** LLM prompts / finding-verification pipeline, sandbox orchestration,
billing, server secrets, private premium datasets, or website code. The optional `skilltotal/
cloud/` client (thin `login` / `scan --deep` over `urllib`) is the only bridge to the paid API
and contains no premium logic; it is implemented alongside the website API, not before it.

## Adding a scanner / detection rule

Full process: `docs/contributing-rules.md` (corpus-driven: sanitized fixture → confirm gap →
rule → unit test → FP calibration on the trusted corpus → bump `RULESET_VERSION` +
`RULES_CHANGELOG.md`). In short: create `skilltotal/scanners/<name>.py` (extend
`PatternScanner` with `rules`, or `Scanner` with a custom `scan`), register it in
`SCANNERS` (`scanners/__init__.py`), set each rule's `capability`, and add a fixture + test.

## Docs

`docs/architecture.md`, `docs/report-schema.md` + `docs/report.schema.json`,
`docs/scoring.md`, `docs/contributing-rules.md`, `docs/releasing.md`, `docs/open-core.md`.
`CHANGELOG.md` / `RULES_CHANGELOG.md` track engine and ruleset changes.
