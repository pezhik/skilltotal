# SkillTotal Architecture

## Goals

- **CLI-first**, but with a **reusable core engine**: the website's scanner imports the same
  analysis logic, and so can any other service.
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

1. **Collect** (`collector.py`): resolve the source into a local folder. A local directory is
   read in place; a single file is copied into a temp dir; an archive (`.zip`, `.tar.gz`,
   `.tgz`, `.tar`, ...) is extracted into one (links, devices and path escapes are refused, sizes
   and entry counts are capped); a git URL is shallow-cloned; an `npm:` / `pypi:` spec is fetched
   from the registry as the package archive and extracted. Temp dirs are removed when the
   `SourceContext` closes. `Component` (name/type/version) is derived solely from files in the
   component (`package.json`, `pyproject.toml`/`setup.py`, MCP manifests, `SKILL.md`).
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
4. **Normalize** (`engine`): baseline suppression and inline `skilltotal:ignore` markers drop
   accepted evidence; evidence that is not executed, agent-facing behavior is demoted to
   `needs_review` by the `_split_*` layers (see [Evidence-context demotion](#evidence-context-demotion)).
   Both happen *before* capabilities and scoring, so neither affects the result.
5. **Capabilities** (`capabilities.py`): a pure projection over findings — each `RuleSpec`
   declares the `Capability` it implies, so capabilities are regrouped finding-evidence.
6. **Score** (`scoring.py`): sum of severity weights of risk-bearing findings (malicious +
   risky_construct; capability findings score 0), cap 100, and at least 50 when any malicious
   indicator is present → risk level. Synthesized findings for combinations of base findings
   (`ST-COMBO-EXFIL`, `ST-FLOW-TRIFECTA`, `ST-INSTALL-DROPPER`, `ST-CONVERGENCE`) are added in the
   order and phase that `combinations.py` declares; their detection logic lives in `scoring.py`.
   Embedded secrets are `exposure` findings: reported, never scored. See [scoring.md](scoring.md).
7. **Report** (`report.py` / `sarif.py`): render `Report` as human text, JSON, or SARIF.

## Key design decisions

- **Evidence as a hard invariant.** `Finding.__post_init__` raises if evidence is empty, so
  an un-evidenced finding cannot be constructed. Low-confidence signals are emitted as
  `NeedsReview` and excluded from scoring.
- **One finding per rule.** Clustering keeps reports readable and makes the score a function
  of *distinct risks*, not match counts.
- **RuleSpec single source of truth.** Identity, severity, text, implied capability, and the
  regex all live in one place — shared by scanners, the capability engine, and `rules list`.
- **Static and deterministic.** No code from the analyzed component is executed; no LLM
  is consulted. Results are reproducible. Analysis of a local folder, archive or file is
  offline; fetching a remote source (a git clone, the GitHub API size pre-check, the npm or PyPI
  registry, `--provenance` metadata, and the packages `inventory` and the plugin hook check) is
  the only network use, and it happens in `collector.py` / `provenance.py`, before analysis.

## Extending

Add a scanner by creating `skilltotal/scanners/<name>.py` with either a `PatternScanner`
(declare `rules`) or a custom `Scanner` subclass, then register it in
`skilltotal/scanners/__init__.py`. Declaring each rule's `capability` automatically wires it
into capability extraction and `rules list`.

## Reuse as a library

- A service accepts an upload or URL, calls `collect` + `analyze_directory`, and returns
  `report.to_dict()` as JSON. The website's scanner works this way.
- An approval workflow can reuse the install decision, `skilltotal.guard.evaluate(report,
  block_on)`: malicious indicators always block, capabilities alone never do.
- The core keeps no mutable state between calls, so it is safe to run concurrently per request.
  It does read its limits from the environment: the `SKILLTOTAL_MAX_*` sizes and
  `SKILLTOTAL_CLONE_TIMEOUT` when `collector.py` is imported, and `SKILLTOTAL_WORKERS` for
  parallel scans. Set them before importing the engine.

## Evidence-context demotion

Besides test code, `engine.py` moves evidence that is not executed or agent-facing behavior to
`needs_review` before scoring, so the engine does not flag descriptions of attacks or its own
detection patterns. There are ten `_split_*` layers (`grep '^def _split_' skilltotal/engine.py`):

- `_split_test_evidence`: test code by path (`file_index.is_test_path`) and inline Rust
  `#[cfg(test)]`/`#[test]` blocks (`IndexedFile.in_rust_test`).
- `_split_doc_evidence`: human-facing docs and prose (`file_index.is_doc_path`); AI-instruction
  surfaces stay in scope.
- `_split_data_corpus_evidence`: inert data/eval/benchmark corpora
  (`file_index.is_data_corpus_path`), restricted to non-code suffixes.
- `_split_code_context_evidence`: matches inside comments or string literals, per each rule's
  `RuleSpec.code_context` (`strings_and_comments`, `comments`, `comments_and_docstrings`).
- `_split_own_provider_reads`: a provider SDK reading its own provider's credential path, for the
  curated, exactly named registry packages listed in `scoring.py`.
- `_split_unpublished_env_evidence`: `ST-ENV-SHIPPED` outside a published package (a `.env` in a
  working tree or checkout is how the file is meant to be used).
- `_split_build_output_evidence`: in a published package's build output, capability findings stay
  and risk claims are demoted, because bundling erases the paths the other layers rely on.
- `_split_structured_data_evidence`: code-pattern and injection matches in JSON/YAML/TOML data
  files; MCP manifests and other agent-instruction surfaces are excluded.
- `_split_example_evidence`: example, demo and benchmark scaffolding.
- `_split_ci_evidence`: CI/CD pipeline configuration, which runs on the project's build service,
  not on the consumer's machine.

At the scanner level, `sensitive_paths.py` and `secrets.py` route deny-list/guardrail credential
paths and public Algolia DocSearch keys to `needs_review`, `ST-SHELL-EVASION` sets aside a
PowerShell `-EncodedCommand` of the file's own spelled-out script, and the prompt-surface scanner
demotes quoted, defensively framed or third-party-attributed attack phrases. The user-facing
summary is in [scoring.md](scoring.md#evidence-context-demotion-what-does-not-score).

Every demotion trades recall for precision, so each layer needs a positive eval-corpus sample
that must stay flagged.
