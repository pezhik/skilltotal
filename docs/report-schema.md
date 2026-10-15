# SkillTotal Report Schema

The JSON report (`--json` / `--output`) is the serialization of the core `Report` model.
It is the stable, machine-readable contract for any consumer: CI scripts, dashboards, or a service
that imports the engine and returns `Report.to_dict()`.

> **Formal contract:** [`report.schema.json`](report.schema.json) (JSON Schema, report
> schema version **1.9**) is the machine-readable source of truth. Consumers should validate
> against it. `tests/test_report_schema.py` guards it: any change to the report shape that is
> not reflected in the schema fails CI, forcing a deliberate `REPORT_SCHEMA_VERSION` bump.
> See [releasing.md](releasing.md) for version-bump rules.

## Top-level shape

```json
{
  "component": {
    "name": "evil-npm-pkg",
    "type": "npm_package",
    "source": "/abs/path/or/url",
    "version": "0.0.1",
    "download_url": "https://registry.npmjs.org/evil-npm-pkg/-/evil-npm-pkg-0.0.1.tgz"
  },
  "risk_score": 100,
  "risk_level": "critical",
  "summary": "Risk level CRITICAL (score 100/100). 5 risk finding(s), 2 capability finding(s) (not scored); capabilities: ...",
  "verdict": { /* the plain-language answer; see below */ },
  "capabilities": {
    "shell_execution": [ { "file": "...", "line_start": 10, "line_end": 10, "snippet": "..." } ]
  },
  "traits": [ /* behavioral fingerprint + standards crosswalk; see below */ ],
  "findings": [ /* see below */ ],
  "needs_review": [ /* see below */ ],
  "metadata": { /* see below */ }
}
```

## Fields

### `component`
| Field | Type | Notes |
|-------|------|-------|
| `name` | string | From `package.json`/`pyproject` or directory name |
| `type` | string | `npm_package`, `python_package`, `mcp_server`, `agent_skill` (a folder with a `SKILL.md`), `ai_component` (a folder with an `AGENTS.md` or `CLAUDE.md`), `go_project`, `java_project`, `directory` (a local folder or clone with none of these), or `project` (an archive or single file with none of these). Treat an unknown value as `directory`: new types can be added |
| `source` | string | Resolved local path or the original URL |
| `version` | string | From manifest if available, else `""` |
| `download_url` | string \| null | The distribution artifact fetched for an npm/PyPI source; `null` for git and local sources (added in 1.2) |

### `risk_score` / `risk_level`
- `risk_score`: integer 0–100.
- `risk_level`: `low` (0–24), `medium` (25–49), `high` (50–74), `critical` (75–100).

### `verdict`
The plain-language answer, read next to the score rather than derived from it (added in 1.3).
What the plugin and `guard` act on: malicious indicators block whatever the score.

| Field | Type | Notes |
|-------|------|-------|
| `level` | string | `malicious` when any malicious indicator fired, else the risk level |
| `headline` | string | One line for a person, e.g. `Malicious indicators found` |
| `has_malicious_indicators` | boolean | `true` when a `malicious_indicator` finding fired |
| `reasons` | array | Up to three strings naming the findings that explain the verdict |
| `malicious_indicators` / `risky_constructs` / `exposed_secrets` / `capabilities` | integer | Findings per threat class (`exposed_secrets` counts the `exposure` class, added in 1.6) |
| `unanalyzed_code` | object | Present only when the component ships source in a language whose behavior is not analyzed yet, e.g. `{"Go": 12}`; a low verdict then says the analysis was partial (added in 1.7) |
| `unanalyzed_files` | object | Present only when shipped (non-test) code files were not read at all, counted by reason: `too_large` (over the 2 MiB cap, or a too-large script npm runs at install) and `minified` (a bundle; a `.min` copy next to its readable source is not counted), e.g. `{"minified": 2}`. Data files and assets are not counted. A low verdict then says the analysis was partial; the score is unchanged (added in 1.8) |

### `capabilities`
Object keyed by capability name; each value is a list of **evidence** objects.
Possible keys: `filesystem_read`, `filesystem_write`, `shell_execution`, `network_egress`,
`install_time_execution`, `dynamic_code_execution`, `mcp_tools_detected`,
`prompt_surface_risk`, `delegated_authentication`, `scoped_identity`. A capability is present
only if at least one finding evidences it.

### `traits[]`
A behavioral **fingerprint**: a higher-level projection over findings that names the traits a
component exhibits, each with a machine-readable crosswalk to industry standards. **Descriptive
only — never affects the score** (like `capabilities`). Added in schema 1.5. Full taxonomy and
mapping rationale: [`trait-crosswalk.md`](trait-crosswalk.md).

| Field | Type | Notes |
|-------|------|-------|
| `trait` | string | Trait id (e.g. `execution_authority`, `embedded_credential`) |
| `title` / `description` | string | Human-readable name and explanation |
| `emergent` | boolean | `true` for combination traits backed by a synthesized risky-construct (`exfil_correlation`, `instruction_exfil_flow`, `malware_convergence`) |
| `crosswalk.csa_trait` | string | Cloud Security Alliance trait/pattern |
| `crosswalk.csa_risk` | string | The CSA named risk for that trait |
| `crosswalk.maestro_layers` | array | MAESTRO layer objects `{ id, name }` (empty where none) |
| `crosswalk.atlas_tactics` | array | MITRE ATLAS tactic names (empty where no honest fit) |
| `evidence` | array | **Non-empty** evidence objects proving the trait |

### `findings[]`
| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Stable rule id (e.g. `ST-SHELL-PY`) |
| `severity` | string | `critical` / `high` / `medium` / `low` |
| `category` | string | e.g. `shell_execution`, `mcp`, `exfiltration_path` |
| `title` | string | Short human title |
| `description` | string | What was detected (interprets evidence only) |
| `evidence` | array | **Non-empty** list of evidence objects (invariant) |
| `recommendation` | string | Actionable guidance |
| `threat_class` | string | `malicious_indicator` (drives the malicious verdict), `risky_construct` (scored), `exposure` (a shipped credential: reported, not scored; added in 1.6), `capability` (informational) |
| `owasp` | array | OWASP Agentic Skills Top 10 ids (`AST01`–`AST10`) for the rule; empty when there is no honest static fit; never scored (added in 1.4) |

### `evidence[]` (inside findings and capabilities)
| Field | Type | Notes |
|-------|------|-------|
| `file` | string | Path relative to the component root (POSIX style) |
| `line_start` | integer | 1-based, inclusive |
| `line_end` | integer | 1-based, inclusive, `>= line_start` |
| `snippet` | string | The matched source line(s), truncated if very long |

### `needs_review[]`
Low-confidence or un-evidenced signals. **Never affects the score.**
| Field | Type | Notes |
|-------|------|-------|
| `category` | string | Source category |
| `title` | string | Short title |
| `reason` | string | Why it could not be confirmed as a finding |
| `file` | string \| null | File if known, else `null` |
| `line` | integer \| null | 1-based line when the heuristic knows it (added in 1.1) |

### `metadata`
| Field | Type | Notes |
|-------|------|-------|
| `skilltotal_version` | string | Engine version (= `ENGINE_VERSION`) |
| `schema_version` | string | Report schema version (= `REPORT_SCHEMA_VERSION`) |
| `ruleset_version` | integer | Detection ruleset version (= `RULESET_VERSION`) |
| `generated_at` | string | ISO-8601 UTC timestamp |
| `files_indexed` | integer | Files analyzed |
| `files_skipped_binary` | integer | Binary files skipped |
| `files_skipped_large` | integer | Files over the size cap skipped |
| `scanners_run` | array | Scanner names that ran |
| `findings_by_severity` | object | Counts per severity |
| `suppressed_count` | integer | Evidence occurrences removed via `--baseline` or an inline `skilltotal:ignore` marker (honored only for `scan` of a local directory; a marker never removes a malicious indicator) |
| `baseline` | string | Optional; present only when `scan` applied a baseline file (`--baseline`, or `baseline` in `.skilltotal.toml`): its path (added in 1.9) |
| `baseline_suppressed_count` | integer | Optional; present only when a baseline was applied: how many of the `suppressed_count` occurrences the baseline removed. The rest were inline markers (added in 1.9) |
| `config_applied` | object | Optional; present only when `scan` applied a `.skilltotal.toml`: `path`, and the number of `exclude` globs, `ignore` rule ids and `policy` entries it set, plus `fail_on` / `fail_on_score` when it sets them (added in 1.8), and `baseline`, the path as the config writes it (added in 1.9) |

## Alternative format: SARIF

`--sarif` emits a SARIF 2.1.0 document instead of the native JSON (for GitHub Code Scanning
/ IDEs). The driver lists every rule. Each evidence occurrence of a finding becomes one SARIF
result anchored to its file/line; `needs_review` items are not included.

| Finding | SARIF `level` | `security-severity` |
|---------|---------------|---------------------|
| `capability` (any severity) | `note` | none (tagged `capability`, so Code Scanning does not rank it as a security alert) |
| any other threat class, `critical` | `error` | 9.0 |
| any other threat class, `high` | `error` | 7.0 |
| any other threat class, `medium` | `warning` | 4.0 |
| any other threat class, `low` | `note` | 2.0 |

A malicious indicator keeps its own severity's level, so a medium one (such as
`ST-PROMPT-INJECTION`) is a `warning`. Rules carry their OWASP Agentic Skills ids as tags and
`relationships`. A location's `uri` is the evidence path, percent-encoded as a relative URI
reference. `--sarif-uri-prefix PATH` puts the scanned folder in front of it (paths relative to
the repository root, for Code Scanning), and `--sarif-category NAME` sets
`runs[0].automationDetails.id` to `NAME/`.

## Invariants (guaranteed by the engine)

1. Every object in `findings[]` has a non-empty `evidence[]`.
2. Every evidence object has all four fields with valid line numbers.
3. Items that cannot be evidenced appear only in `needs_review[]`.
4. `risk_score` is the capped sum of the severity weights of `malicious_indicator` and
   `risky_construct` findings, and at least 50 when any `malicious_indicator` is present;
   `risk_level` is derived from it. `exposure` and `capability`
   findings never change it.
