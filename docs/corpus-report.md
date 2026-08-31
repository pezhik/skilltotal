# SkillTotal corpus report

Deterministic static scan of **57** AI components (engine v0.43.0, ruleset 47, schema 1.5, generated 2026-08-31).

Manifest sha256 `259703def233c6754dcaff6d7b9979c7430b63cb457e1ca0f88cde9a16837f7e` · components listed: 57 (scanned 57, skipped 0, errors 0).

## Risk level distribution

| level | count | % of scanned |
|---|---|---|
| low | 56 | 98.2% |
| medium | 0 | 0.0% |
| high | 0 | 0.0% |
| critical | 1 | 1.8% |

**Malicious indicators:** 0 / 57 components (0.0%) carry at least one deliberate malicious-indicator finding.

## OWASP Agentic Skills Top 10

Components with at least one finding mapped to each category (see `docs/owasp-agentic-skills-mapping.md`). AST06-AST10 are runtime/governance and not statically checkable, so they read 0 here by construction.

| category | count | % |
|---|---|---|
| AST01 | 2 | 3.5% |
| AST02 | 10 | 17.5% |
| AST03 | 6 | 10.5% |
| AST04 | 0 | 0.0% |
| AST05 | 2 | 3.5% |
| AST06 | 0 | 0.0% |
| AST07 | 0 | 0.0% |
| AST08 | 0 | 0.0% |
| AST09 | 0 | 0.0% |
| AST10 | 0 | 0.0% |

## Capability prevalence

| capability | count | % |
|---|---|---|
| delegated_authentication | 14 | 24.6% |
| dynamic_code_execution | 5 | 8.8% |
| filesystem_read | 23 | 40.4% |
| filesystem_write | 19 | 33.3% |
| install_time_execution | 10 | 17.5% |
| mcp_tools_detected | 33 | 57.9% |
| network_egress | 31 | 54.4% |
| scoped_identity | 5 | 8.8% |
| shell_execution | 21 | 36.8% |

## Top rules

| rule | components |
|---|---|
| ST-MCP-DETECTED | 33 |
| ST-NET-PY | 17 |
| ST-NET-NODE | 15 |
| ST-SHELL-NODE | 14 |
| ST-AUTH-DELEGATED | 14 |
| ST-FS-PY-READ | 14 |
| ST-FS-PY-WRITE | 12 |
| ST-FS-NODE-READ | 11 |
| ST-SHELL-PY | 10 |
| ST-INSTALL-NPM-PREPARE | 8 |
| ST-FS-NODE-WRITE | 8 |
| ST-EXPOSE-BIND | 6 |
| ST-AUTH-SCOPED | 5 |
| ST-MCP-SERVER-EXEC | 4 |
| ST-DYN-NODE | 3 |

## Reproduce

Every number above is re-derivable: run the same manifest through the same engine.

```bash
pip install -e .
python tests/manual_eval/corpus_report.py  # default manifest: report_manifest.csv
```

The manifest auto-grows from the official MCP registry (append-only, with resolvability and public-hygiene gates and a per-run cap), so the corpus expands over time without manual curation.

Unreachable/private components are skipped (listed in the JSON), never silently dropped; results characterize the manifest, not a claim of statistical representativeness.

This report is aggregate-only. The JSON lists each component's source and scan status but **not** a per-component risk verdict, so it never publishes a risk label against a named third-party project — scan any component yourself with the command above.
