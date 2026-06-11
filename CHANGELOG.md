# Changelog

All notable changes to the SkillTotal engine. Format loosely follows
[Keep a Changelog](https://keepachangelog.com); the project uses
[SemVer](https://semver.org). See `RULES_CHANGELOG.md` for detection-rule changes.

## [0.7.0]

### Added
- **MCP detectors (ruleset 7)** closing gaps from agent-scan / agent-audit:
  - `ST-MCP-TOOL-SHADOWING` (`malicious_indicator`) — a tool description steering the agent
    to prefer/override/avoid *other* tools (tool shadowing).
  - `ST-MCP-AUTO-APPROVE` (`risky_construct`) — an `mcpServers` entry pre-authorizing tool
    calls (`autoApprove` / `alwaysAllow` / `trust`), removing the human confirmation gate.
  - `ST-PROMPT-EXFIL-MD` (`malicious_indicator`) — a markdown image/link whose URL embeds a
    template placeholder (an exfiltration sink; cf. the Invariant Labs GitHub-MCP attack).
- **Version pinning** for package sources: `npm:name@1.2.3` and `pypi:name==1.2.3`
  (`pypi:name@1.2.3` accepted too) download that exact release instead of latest.
- **Calibration harness** (`tests/manual_eval/calibrate.py`): run the engine over a labeled
  CSV and report benign false-positive rate, detection rate, and `needs_review` noise.

### Changed
- **Minified-line noise** (`ST-OBF-MINIFIED`) no longer floods reports: build artifacts that
  are long-line by design (`.map`, `.d.ts`/`.d.mts`/`.d.cts`, `*.min.*`, `package-lock.json`)
  are skipped, and the remaining minified files collapse into a single aggregated
  `needs_review` entry instead of one per file.

## [0.6.0]

### Added
- **Threat-class axis** on findings (`malicious_indicator` | `risky_construct` |
  `capability`) and a top-level **`verdict`** (fast "is this likely malware?" read,
  independent of `risk_score`). Lets consumers separate a malware verdict from code-safety
  hygiene. Existing rules tagged: prompt-injection, MCP tool-poisoning, decode-and-exec, and
  hidden-unicode are `malicious_indicator`; sensitive-path is `risky_construct`; capability
  rules (shell/fs/network/dynamic/MCP/combo) stay `capability`. Report schema **1.3**
  (finding.threat_class + verdict; additive).
- **Risky-construct detectors** (ruleset 6) covering the unintentional-mistake classes from
  vulnerablemcp.info, all `risky_construct`:
  - `ST-SECRET-EMBEDDED` — hardcoded credentials/keys shipped in the component (known-prefix
    tokens + private keys + secret-variable assignment); values redacted in evidence.
  - `ST-CMDI-PY` / `ST-CMDI-NODE` — command injection: a shell sink fed a dynamically built
    command (excludes safe argv-without-shell).
  - `ST-DESERIALIZE-PY` — unsafe deserialization (pickle/marshal/jsonpickle, yaml.load
    without SafeLoader).
  - `ST-EXPOSE-BIND` / `ST-EXPOSE-DEBUG` — network exposure (bind 0.0.0.0, debug server).
  Corpus-calibrated (no false positives on the trusted real-world corpus).
- **`skilltotal inventory`** — discover AI components already installed on this machine
  (MCP servers + skills from Claude Desktop/Code, Cursor, Windsurf, VS Code, Gemini configs),
  derive an `npm:`/`pypi:`/local source for each, and scan them. Pure local discovery (reads
  config files only, never launches). `--json`, `--no-scan`, `--project DIR`. No change to the
  report schema or the `analyze`/`analyze_directory` API.

## [0.5.1]

### Fixed
- MCP exfiltration-surface signal now treats **browser** as an off-host channel (web
  automation can ingest untrusted content and exfiltrate), so a browser+credential or
  browser+filesystem server is flagged even without a `network` tool. The 0.5.0 logic
  anchored only on `network` and missed this (e.g. the `mcp` package itself).

## [0.5.0]

### Added
- MCP **exfiltration-surface** signal (ruleset 5): when one component's MCP tools span a
  network channel AND data access (filesystem/browser/credential), emit a `needs_review`
  note — the capability surface a "toxic agent flow" (lethal trifecta) needs. Emitted as
  needs_review, never scored: legitimate servers have this surface too; the real risk is
  architectural (runtime agent permissions). Inspired by the Invariant Labs GitHub MCP
  toxic-flow writeup. See `RULES_CHANGELOG.md`.

## [0.4.0]

### Added
- `Component.download_url`: for npm/PyPI sources, the exact distribution artifact that was
  fetched and analyzed (null for git/local). Lets consumers deep-link evidence to the
  published artifact — e.g. a PyPI `files.pythonhosted.org` URL maps to inspector.pypi.io.
  Report schema **1.2** (additive; 1.1 readers unaffected).

## [0.3.1]

### Fixed
- PyPI page (long description) shipped with 0.3.0 still showed pre-PyPI install
  instructions; README now leads with `pipx install skilltotal` (PEP 668-safe) and the
  page is refreshed by this release. Added `tests/test_release_hygiene.py` so the release
  gate mechanically blocks tagging with a stale CHANGELOG/README/schema-id.

## [0.3.0]

### Added
- `NeedsReview.line` (optional, 1-based): heuristics now record the exact line when they
  know it (ambiguous words/phrases, zero-width unicode, obfuscation hints, dynamic imports,
  unparseable Python/JSON, test-only demotions), so consumers can deep-link straight to the
  location. Report schema **1.1** (additive; 1.0 reports remain valid for readers).

## [0.2.0]

### Added
- **npm / PyPI package collection** (`collector.py`): `collect()` now resolves `npm:<name>`
  and `pypi:<name>` specs (and `npmjs.com` / `pypi.org` URLs) by downloading the latest
  published release from the registry and extracting it safely (path-traversal and
  decompression-bomb guards; links skipped). New helpers `classify_source`,
  `npm_package_name`, `pypi_package_name`.
- Versioned engine contract: `ENGINE_VERSION`, `REPORT_SCHEMA_VERSION`, `RULESET_VERSION`
  (`skilltotal/__init__.py`); `schema_version` and `ruleset_version` in report `metadata`.
- Formal report contract `docs/report.schema.json` (schema version 1.0) and a contract-guard
  test (`tests/test_report_schema.py`) that validates every fixture report against it.
- Process docs: `docs/contributing-rules.md`, `docs/releasing.md`.

## [0.1.0]

### Added
- Initial CLI engine: collector, file index/evidence engine, 11 scanners, capability
  extraction, scoring (filesystem+network combo critical), text/JSON/SARIF reports, baseline
  suppression, AST-based Python analysis, hidden-Unicode detection, MCP tool classification
  (JSON + code). Zero runtime dependencies.
