# SkillTotal Report Schema

The JSON report (`--json` / `--output`) is the serialization of the core `Report` model.
It is the stable contract intended for the web and SaaS products.

> **Formal contract:** [`report.schema.json`](report.schema.json) (JSON Schema, report
> schema version **1.0**) is the machine-readable source of truth. Consumers should validate
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
    "version": "0.0.1"
  },
  "risk_score": 100,
  "risk_level": "critical",
  "summary": "Risk level CRITICAL (score 100/100). 7 finding(s); capabilities: ...",
  "capabilities": {
    "shell_execution": [ { "file": "...", "line_start": 10, "line_end": 10, "snippet": "..." } ]
  },
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
| `type` | string | `npm_package`, `python_package`, `mcp_server`, `ai_component`, `directory` |
| `source` | string | Resolved local path or the original URL |
| `version` | string | From manifest if available, else `""` |

### `risk_score` / `risk_level`
- `risk_score`: integer 0–100.
- `risk_level`: `low` (0–24), `medium` (25–49), `high` (50–74), `critical` (75–100).

### `capabilities`
Object keyed by capability name; each value is a list of **evidence** objects.
Possible keys: `filesystem_read`, `filesystem_write`, `shell_execution`, `network_egress`,
`install_time_execution`, `dynamic_code_execution`, `mcp_tools_detected`,
`prompt_surface_risk`. A capability is present only if at least one finding evidences it.

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
| `suppressed_count` | integer | Evidence occurrences removed via `--baseline` |

## Alternative format: SARIF

`--sarif` emits a SARIF 2.1.0 document instead of the native JSON (for GitHub Code Scanning
/ IDEs). Severity maps to SARIF `level` (`critical`/`high` → `error`, `medium` → `warning`,
`low` → `note`) plus a numeric `security-severity` property. Each evidence occurrence becomes
one SARIF result anchored to its file/line.

## Invariants (guaranteed by the engine)

1. Every object in `findings[]` has a non-empty `evidence[]`.
2. Every evidence object has all four fields with valid line numbers.
3. Items that cannot be evidenced appear only in `needs_review[]`.
4. `risk_score` is the capped sum of finding severity weights; `risk_level` is derived from
   it.
