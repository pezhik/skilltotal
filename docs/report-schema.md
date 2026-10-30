# Output formats

What each command prints with `--json` (and `--sarif`, `--sbom`), field by field:

| Output | Command |
|---|---|
| [Scan report (JSON)](#scan-report-json) | `scan --json`, `scan --output FILE`, the MCP server's `scan_component` with `detail: "full"` |
| [SARIF](#sarif) | `scan --sarif` |
| [Diff (JSON)](#diff-json) | `diff --json`, `diff --output FILE` |
| [Guard (JSON)](#guard-json) | `guard <source> --json` |
| [Installed components (JSON)](#inventory-and-guard---installed-json) | `inventory --json`, `guard --installed --json` |
| [AI-BOM](#ai-bom-properties) | `inventory --sbom` |
| [Rules (JSON)](#rules-json) | `rules list --json` |

Only the scan report has a formal schema and a version of its own. The other outputs are built
from it and change with the engine version: a field may be added in a minor release, and none is
removed or renamed without a note in the [changelog](../CHANGELOG.md).

## Scan report (JSON)

The JSON report (`--json` / `--output`) is the serialization of the core `Report` model.
It is the stable, machine-readable contract for any consumer: CI scripts, dashboards, or a service
that imports the engine and returns `Report.to_dict()`.

> **Formal contract:** [`report.schema.json`](report.schema.json) (JSON Schema, report
> schema version **1.10**) is the machine-readable source of truth. Consumers should validate
> against it. `tests/test_report_schema.py` guards it: any change to the report shape that is
> not reflected in the schema fails CI, forcing a deliberate `REPORT_SCHEMA_VERSION` bump.
> See [releasing.md](releasing.md) for version-bump rules.

### What a report contains

A normalized report containing the component identity, a **risk score (0–100)** and
**risk level** (low / medium / high / critical), a plain-language **verdict**, detected
**capabilities** (each evidence-backed), a behavioral **trait fingerprint** (with a CSA / MAESTRO /
MITRE ATLAS crosswalk), **findings**, **needs_review**, and **metadata**. The shape is below; the score is explained in [scoring.md](scoring.md).

Every finding also carries its **OWASP Agentic Skills Top 10** category ids (`owasp`), emitted in
both the JSON report and SARIF (native `taxonomies`/`relationships`);
[docs/owasp-agentic-skills-mapping.md](https://github.com/pezhik/skilltotal/blob/main/docs/owasp-agentic-skills-mapping.md) explains the coverage
(AST01–AST05) and the honest gaps. For MCP servers,
[docs/mcp-owasp-mapping.md](https://github.com/pezhik/skilltotal/blob/main/docs/mcp-owasp-mapping.md) maps SkillTotal's checks to the OWASP MCP
Security Cheat Sheet (and names the runtime controls a static engine can't cover).

The report's **`traits`** array is a behavioral fingerprint: a higher-level projection over the
findings (e.g. `execution_authority`, `embedded_credential`, `untrusted_perception`, and the
*emergent* `exfil_correlation` combination), each mapped to the Cloud Security Alliance
trait-based model, a MAESTRO threat-model layer, and a MITRE ATLAS tactic where there is an honest
fit. It is descriptive and never affects the score; see
[docs/trait-crosswalk.md](https://github.com/pezhik/skilltotal/blob/main/docs/trait-crosswalk.md).
Three of the traits record how the component authenticates its tool calls (an embedded static
credential, delegated OAuth/OIDC or a least-privilege scoped identity), which shows the blast
radius of a compromise, not only whether a secret exists.

### Top-level shape

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

### `component`
| Field | Type | Notes |
|-------|------|-------|
| `name` | string | From `package.json`/`pyproject` or directory name |
| `type` | string | `npm_package`, `python_package`, `vscode_extension` (a `package.json` declaring `engines.vscode`, at the root or in the `extension/` folder of an unpacked `.vsix`), `mcp_server`, `agent_skill` (a folder with a `SKILL.md`), `ai_component` (a folder with an `AGENTS.md` or `CLAUDE.md`), `go_project`, `java_project`, `directory` (a local folder or clone with none of these), or `project` (an archive or single file with none of these). Treat an unknown value as `directory`: new types can be added |
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
| `evidence` | array | **Non-empty** list of evidence objects (invariant), at most 25 per finding |
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
| `baseline_suppressed_malicious` | array of string | Optional; present only when the baseline removed evidence of a malicious-indicator rule: those rule ids, sorted. The verdict and the gates no longer see them; the text report names them on its `Baseline` line and the CLI warns on stderr (added in 1.10) |
| `config_applied` | object | Optional; present only when `scan` applied a `.skilltotal.toml`: `path`, and the number of `exclude` globs, `ignore` rule ids and `policy` entries it set, plus `fail_on` / `fail_on_score` when it sets them (added in 1.8), and `baseline`, the path as the config writes it (added in 1.9) |

### Invariants (guaranteed by the engine)

1. Every object in `findings[]` has a non-empty `evidence[]`.
2. Every evidence object has all four fields with valid line numbers.
3. Items that cannot be evidenced appear only in `needs_review[]`.
4. `risk_score` is the capped sum of the severity weights of `malicious_indicator` and
   `risky_construct` findings, and at least 50 when any `malicious_indicator` is present;
   `risk_level` is derived from it. `exposure` and `capability`
   findings never change it.

## SARIF

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

## Diff (JSON)

`diff --json` prints one object:

| Field | Type | Notes |
|-------|------|-------|
| `old`, `new` | object | Each side: `component` (`name`, `version`, `type`, `source`), `risk_score`, `risk_level`, `verdict_level`, `engine_version`, `ruleset_version` |
| `risk_score_delta` | integer | New score minus old score |
| `verdict_changed` | boolean | `true` when the verdict level differs |
| `new_findings` | array | Findings whose rule fires only in the new version, as full finding objects, most severe first |
| `resolved_findings` | array | Findings whose rule fires only in the old version |
| `changed_findings` | array | Rules in both whose evidence changed: `id`, `severity`, `title`, `threat_class`, `added_evidence`, `removed_evidence` (evidence objects matched by the baseline fingerprint, so moved lines are not changes) |
| `capabilities_added`, `capabilities_removed` | array of string | Capability names |
| `ruleset_mismatch` | boolean | `true` when the two sides were scanned with different rulesets, so some changes may come from the rules rather than the component |
| `coverage_gaps_added` | array | `needs_review` notes that say part of the new version was not analyzed, which the old version did not have. A finding that disappeared with such a part may only be out of view |
| `summary` | string | One line for a person |

`--fail-on-new` counts `new_findings` and the entries of `changed_findings` that have
`added_evidence`, skipping capabilities.

## Guard (JSON)

`guard <source> --json` prints one object:

| Field | Type | Notes |
|-------|------|-------|
| `source` | string | The source as given |
| `decision` | string | `allow` or `block` (exit code 0 or 2) |
| `block_on` | string | The block level applied: `malicious`, `high` or `medium` |
| `reasons` | array of string | Why it blocks, one sentence each; empty when allowed |
| `risk_score`, `risk_level` | integer, string | As in the scan report |
| `verdict` | object | The scan report's [`verdict`](#verdict) |
| `capabilities` | array of string | Capability names |
| `accepted` | object | Present only when an accept file removed findings ([below](#accepted)) |

## `inventory` and `guard --installed` JSON

Both print an array with one object per installed component. Every object has:

| Field | Type | Notes |
|-------|------|-------|
| `host` | string | Where it was found, such as `Claude Code`, `Claude Desktop`, `Cursor`, `VS Code`, `Claude Code plugins`, `Claude skills` or `Cursor Server` |
| `name` | string | The configured name; for an editor extension `publisher.name@version` |
| `kind` | string | `mcp_server`, `plugin`, `skill` or `editor_extension` |
| `source` | string \| null | What was scanned: an `npm:` or `pypi:` spec, a git URL or a local path; `null` when nothing could be derived |

`guard --installed` adds:

| Field | Type | Notes |
|-------|------|-------|
| `decision` | string | `allow`, `block`, or why it was not checked: `remote`, `risky`, `not scanned`, `error`, `this scanner` (SkillTotal's own MCP server) |
| `risk_level` | string | For a scanned component |
| `reasons` | array of string | For a scanned component: why it blocks; empty when allowed |
| `note` | string | For a component that was not checked: why |
| `secrets` | array of string | Present when its config entry holds inline secrets, redacted |
| `drift`, `accepted` | object | Present when they apply ([below](#drift)) |

`inventory` adds:

| Field | Type | Notes |
|-------|------|-------|
| `scannable` | boolean | Whether a source could be derived |
| `note` | string | Why it is not scannable, or extra context |
| `config` | string | The config file or folder it came from |
| `risky`, `remote`, `this_tool` | boolean | Its launcher runs a downloaded script; it is reached at a URL; it is SkillTotal's own MCP server |
| `secrets` | array of string | Inline secrets in its config entry, redacted |
| `version` | string | Present when discovery read a version from the component's manifest (editor extensions) |
| `verdict`, `risk_level`, `risk_score`, `has_malicious_indicators` | | From the scan, when it ran |
| `guard`, `guard_reasons` | string, array | What `guard --installed` would decide at its default level, and why |
| `error` | string | Present when the scan failed |
| `drift`, `accepted` | object | Present when they apply |

### `drift`

Present with `--state` when the component's version changed and it gained risk findings
([drift](installed-components.md#catching-a-malicious-update)):

| Field | Type | Notes |
|-------|------|-------|
| `from`, `to` | string | The previous and the current version |
| `rules` | array of string | Rule ids with risk findings the previous version did not have |
| `blocks` | boolean | `true` when one of them is a malicious indicator or a high or critical risky construct; the component then blocks, with the reason in `reasons` (`guard_reasons` in `inventory`) |

### `accepted`

Present when an accept file removed findings from the component's scan
([accept file](accepting-findings.md#accept-file)):

| Field | Type | Notes |
|-------|------|-------|
| `rules` | array of string | Rule ids of the removed findings |
| `count` | integer | Evidence occurrences removed |
| `reason` | string | The entry's reason (the reasons of several entries are joined with `; `) |
| `expires` | string | Optional; the earliest `expires` date of the entries used |
| `accepted_by` | string | Optional |

## AI-BOM properties

`inventory --sbom` prints a CycloneDX 1.6 JSON document. `metadata.tools` names SkillTotal and its
version. Each installed component is an `application` component with its `name`, a `purl`
(`pkg:npm/...`, `pkg:pypi/...`) for `npm:` and `pypi:` sources, a `version` when the source pins
one or the extension's manifest names one, and these properties when they have a value:

| Property | Value |
|---|---|
| `skilltotal:host` | As `host` above |
| `skilltotal:kind` | As `kind` above |
| `skilltotal:source` | What was scanned |
| `skilltotal:config` | The config file or folder it came from |
| `skilltotal:verdict` | `malicious`, `critical`, `high`, `medium` or `low` |
| `skilltotal:risk_level`, `skilltotal:risk_score` | From the scan |
| `skilltotal:has_malicious_indicators` | `true` or `false` |
| `skilltotal:scan_error` | Why the scan failed |
| `skilltotal:drift` | `<from> -> <to>: <rule ids>` |
| `skilltotal:accepted` | `<rule ids> (<count>) until <date>: <reason>` (without `until` when no entry expires) |

## Rules (JSON)

`rules list --json` prints an array with one object per rule: `id`, `category`, `severity`,
`title`, `description`, `recommendation`, `capability` (empty for a rule that implies none) and
`threat_class`.

## Files SkillTotal keeps

The baseline, the accept file and the `--state` file are JSON files SkillTotal reads and writes.
The accept file is meant to be reviewed and edited; its format is in
[Accepting findings](accepting-findings.md#accept-file). Write the baseline with
`--write-baseline` and the state file with `--state`, and treat both as opaque.
