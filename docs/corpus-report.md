# SkillTotal corpus report

Deterministic static scan of **62** AI components (engine v0.43.1, ruleset 47, schema 1.5, generated 2026-09-07).

Manifest sha256 `e5aa04b9af643727368201a2b1144641eeee22b0b168512dae10aa63eefa332e` · components listed: 62 (scanned 62, skipped 0, errors 0).

## Risk level distribution

| level | count | % of scanned |
|---|---|---|
| low | 61 | 98.4% |
| medium | 0 | 0.0% |
| high | 0 | 0.0% |
| critical | 1 | 1.6% |

**Malicious indicators:** 0 / 62 components (0.0%) carry at least one deliberate malicious-indicator finding.

## OWASP Agentic Skills Top 10

Components with at least one finding mapped to each category (see `docs/owasp-agentic-skills-mapping.md`). AST06-AST10 are runtime/governance and not statically checkable, so they read 0 here by construction.

| category | count | % |
|---|---|---|
| AST01 | 2 | 3.2% |
| AST02 | 11 | 17.7% |
| AST03 | 7 | 11.3% |
| AST04 | 0 | 0.0% |
| AST05 | 2 | 3.2% |
| AST06 | 0 | 0.0% |
| AST07 | 0 | 0.0% |
| AST08 | 0 | 0.0% |
| AST09 | 0 | 0.0% |
| AST10 | 0 | 0.0% |

## Capability prevalence

| capability | count | % |
|---|---|---|
| delegated_authentication | 14 | 22.6% |
| dynamic_code_execution | 5 | 8.1% |
| filesystem_read | 24 | 38.7% |
| filesystem_write | 20 | 32.3% |
| install_time_execution | 11 | 17.7% |
| mcp_tools_detected | 36 | 58.1% |
| network_egress | 33 | 53.2% |
| scoped_identity | 5 | 8.1% |
| shell_execution | 23 | 37.1% |

## Top rules

| rule | components |
|---|---|
| ST-MCP-DETECTED | 36 |
| ST-NET-PY | 18 |
| ST-NET-NODE | 16 |
| ST-SHELL-NODE | 15 |
| ST-FS-PY-READ | 15 |
| ST-AUTH-DELEGATED | 14 |
| ST-FS-PY-WRITE | 13 |
| ST-FS-NODE-READ | 11 |
| ST-SHELL-PY | 11 |
| ST-INSTALL-NPM-PREPARE | 8 |
| ST-FS-NODE-WRITE | 8 |
| ST-EXPOSE-BIND | 7 |
| ST-AUTH-SCOPED | 5 |
| ST-MCP-SERVER-EXEC | 5 |
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
