# Changelog

All notable changes to the SkillTotal engine. Format loosely follows
[Keep a Changelog](https://keepachangelog.com); the project uses
[SemVer](https://semver.org). See `RULES_CHANGELOG.md` for detection-rule changes.

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
