# SkillTotal corpus report

Deterministic static scan of **66** AI components (engine v0.47.0, ruleset 51, schema 1.5, generated 2026-09-14).

Manifest sha256 `c80ab003494146507ae0ee7b2c508c8aa87a058cb0372ad9f2069eef4212e0d6` · components listed: 67 (scanned 66, skipped 1, errors 0).

## Risk level distribution

| level | count | % of scanned |
|---|---|---|
| low | 66 | 100.0% |
| medium | 0 | 0.0% |
| high | 0 | 0.0% |
| critical | 0 | 0.0% |

**Malicious indicators:** 0 / 66 components (0.0%) carry at least one deliberate malicious-indicator finding.

## OWASP Agentic Skills Top 10

Components with at least one finding mapped to each category (see `docs/owasp-agentic-skills-mapping.md`). AST06-AST10 are runtime/governance and not statically checkable, so they read 0 here by construction.

| category | count | % |
|---|---|---|
| AST01 | 2 | 3.0% |
| AST02 | 11 | 16.7% |
| AST03 | 7 | 10.6% |
| AST04 | 0 | 0.0% |
| AST05 | 1 | 1.5% |
| AST06 | 0 | 0.0% |
| AST07 | 0 | 0.0% |
| AST08 | 0 | 0.0% |
| AST09 | 0 | 0.0% |
| AST10 | 0 | 0.0% |

## Capability prevalence

| capability | count | % |
|---|---|---|
| delegated_authentication | 13 | 19.7% |
| dynamic_code_execution | 4 | 6.1% |
| filesystem_read | 24 | 36.4% |
| filesystem_write | 20 | 30.3% |
| install_time_execution | 10 | 15.2% |
| mcp_tools_detected | 41 | 62.1% |
| network_egress | 35 | 53.0% |
| scoped_identity | 4 | 6.1% |
| shell_execution | 23 | 34.8% |

## Top rules

| rule | components |
|---|---|
| ST-MCP-DETECTED | 41 |
| ST-NET-PY | 18 |
| ST-NET-NODE | 18 |
| ST-SHELL-NODE | 15 |
| ST-FS-PY-READ | 15 |
| ST-AUTH-DELEGATED | 13 |
| ST-FS-PY-WRITE | 13 |
| ST-FS-NODE-READ | 11 |
| ST-SHELL-PY | 10 |
| ST-FS-NODE-WRITE | 9 |
| ST-INSTALL-NPM-PREPARE | 7 |
| ST-EXPOSE-BIND | 6 |
| ST-AUTH-SCOPED | 4 |
| ST-MCP-SERVER-EXEC | 4 |
| ST-MCP-DANGEROUS-TOOL | 3 |

## Reproduce

Every number above is re-derivable: run the same manifest through the same engine.

```bash
pip install -e .
python tests/manual_eval/corpus_report.py  # default manifest: report_manifest.csv
```

The manifest auto-grows from the official MCP registry (append-only, with resolvability and public-hygiene gates and a per-run cap), so the corpus expands over time without manual curation.

Unreachable/private components are skipped (listed in the JSON), never silently dropped; results characterize the manifest, not a claim of statistical representativeness.

This report is aggregate-only. The JSON lists each component's source and scan status but **not** a per-component risk verdict, so it never publishes a risk label against a named third-party project — scan any component yourself with the command above.
