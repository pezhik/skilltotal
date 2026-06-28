# SkillTotal Architecture

## Goals

- **CLI-first**, but with a **reusable core engine** so the future web app and enterprise
  SaaS can import the same analysis logic.
- **Component-only analysis**: no user/company/environment/deployment/runtime context.
- **Evidence-backed**: every confirmed finding has a file/line/snippet anchor.
- **Zero runtime dependencies** (Python standard library only).

## Module boundary (reuse contract)

Everything under `skilltotal/` is a pure library — no `print`, no `sys.exit` — **except**
`cli.py`, which is the only I/O shell. A web/SaaS backend imports
`skilltotal.engine.analyze_directory(root, component)` and serializes the returned
`Report`; it never touches `cli.py`.

```
                ┌──────────────┐
   path / URL → │ collector.py │ → local dir + Component identity
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │ file_index.py│ walk + cache text, offset→line evidence
                └──────┬───────┘
                       ▼
         ┌──────────────────────────┐
         │ scanners/* (registry)    │ regex + targeted parsing → Findings / NeedsReview
         └──────┬───────────────────┘
                ▼
        ┌─────────────────┐    ┌────────────┐
        │ capabilities.py │ →  │ scoring.py │ score + level + combo rule
        └────────┬────────┘    └─────┬──────┘
                 ▼                    ▼
                ┌──────────────────────┐
                │ engine.py → Report   │
                └──────────┬───────────┘
                           ▼
                ┌────────────┐   ┌────────┐
                │ report.py  │ → │ cli.py │  (text / JSON; exit codes)
                └────────────┘   └────────┘
```

## Pipeline (Discover → Detect → Normalize → Report)

1. **Collect** (`collector.py`): resolve a local directory or a git URL (shallow clone into
   a temp dir, auto-cleaned). Derive `Component` (name/type/version) solely from files in
   the component (`package.json`, `pyproject.toml`/`setup.py`, MCP manifests, `SKILL.md`).
2. **Index** (`file_index.py`): walk once, skipping VCS/dependency dirs and binaries; cache
   each file's text and precompute line-start offsets. `evidence_for_span()` maps any match
   offset to an exact `Evidence(file, line_start, line_end, snippet)`.
3. **Scan** (`scanners/`): each scanner returns `ScanResult(findings, needs_review)`.
   **Python** is analyzed by an AST scanner (`python_ast.py`) — it resolves import aliases,
   distinguishes `open()` read vs write, and ignores API names that only appear in strings or
   comments (regex fallback for unparseable files). **Node.js** and config/text surfaces use
   declarative `RuleSpec` regex run by `findings_from_rules`; complex scanners (MCP, install,
   obfuscation, prompt surface) add custom parsing. One finding per rule aggregates all
   matches as capped evidence.
4. **Normalize** (`engine`): baseline suppression drops accepted fingerprints; test-only
   evidence (`is_test_path`, plus inline Rust `#[cfg(test)]`/`#[test]` blocks via
   `in_rust_test`) is demoted to `needs_review`. Both happen *before* capabilities
   and scoring, so neither test code nor suppressed findings affect the result.
5. **Capabilities** (`capabilities.py`): a pure projection over findings — each `RuleSpec`
   declares the `Capability` it implies, so capabilities are regrouped finding-evidence.
6. **Score** (`scoring.py`): sum of severity weights of risk-bearing findings (malicious +
   risky_construct; capability findings score 0), cap 100 → risk level. A synthesized *critical*
   `risky_construct` finding (`ST-COMBO-EXFIL`) is added when sensitive-data access (credential
   path / embedded secret) co-occurs with network egress.
7. **Report** (`report.py` / `sarif.py`): render `Report` as human text, JSON, or SARIF.

## Key design decisions

- **Evidence as a hard invariant.** `Finding.__post_init__` raises if evidence is empty, so
  an un-evidenced finding cannot be constructed. Low-confidence signals are emitted as
  `NeedsReview` and excluded from scoring.
- **One finding per rule.** Clustering keeps reports readable and makes the score a function
  of *distinct risks*, not match counts.
- **RuleSpec single source of truth.** Identity, severity, text, implied capability, and the
  regex all live in one place — shared by scanners, the capability engine, and `rules list`.
- **Static, deterministic, offline.** No code from the analyzed component is executed; no LLM
  is consulted. Results are reproducible.

## Extending

Add a scanner by creating `skilltotal/scanners/<name>.py` with either a `PatternScanner`
(declare `rules`) or a custom `Scanner` subclass, then register it in
`skilltotal/scanners/__init__.py`. Declaring each rule's `capability` automatically wires it
into capability extraction and `rules list`.

## Future web / SaaS reuse

- Web: a request handler accepts an upload/URL, calls `collect` + `analyze_directory`, and
  returns `report.to_dict()` as JSON.
- SaaS gate: reuse `--fail-on-high` semantics (`Severity.rank`) inside an approval workflow.
- Nothing in the core reads global state, so it is safe to run concurrently per request.
