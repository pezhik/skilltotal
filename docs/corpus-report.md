# SkillTotal corpus report

Deterministic static scan of **42** AI components (engine v0.39.0, ruleset 43, schema 1.5, generated 2026-08-17).

Manifest sha256 `34fc163fb1b7a21c7e4d0144a7ee71e550f606a67f680960c0cbe596e1316fdb` · components listed: 42 (scanned 42, skipped 0, errors 0).

## Risk level distribution

| level | count | % of scanned |
|---|---|---|
| low | 42 | 100.0% |
| medium | 0 | 0.0% |
| high | 0 | 0.0% |
| critical | 0 | 0.0% |

**Malicious indicators:** 0 / 42 components (0.0%) carry at least one deliberate malicious-indicator finding.

## OWASP Agentic Skills Top 10

Components with at least one finding mapped to each category (see `docs/owasp-agentic-skills-mapping.md`). AST06-AST10 are runtime/governance and not statically checkable, so they read 0 here by construction.

| category | count | % |
|---|---|---|
| AST01 | 2 | 4.8% |
| AST02 | 8 | 19.0% |
| AST03 | 4 | 9.5% |
| AST04 | 0 | 0.0% |
| AST05 | 1 | 2.4% |
| AST06 | 0 | 0.0% |
| AST07 | 0 | 0.0% |
| AST08 | 0 | 0.0% |
| AST09 | 0 | 0.0% |
| AST10 | 0 | 0.0% |

## Capability prevalence

| capability | count | % |
|---|---|---|
| delegated_authentication | 11 | 26.2% |
| dynamic_code_execution | 4 | 9.5% |
| filesystem_read | 21 | 50.0% |
| filesystem_write | 16 | 38.1% |
| install_time_execution | 8 | 19.0% |
| mcp_tools_detected | 20 | 47.6% |
| network_egress | 27 | 64.3% |
| scoped_identity | 4 | 9.5% |
| shell_execution | 18 | 42.9% |

## Top rules

| rule | components |
|---|---|
| ST-MCP-DETECTED | 20 |
| ST-NET-PY | 14 |
| ST-NET-NODE | 13 |
| ST-SHELL-NODE | 12 |
| ST-FS-PY-READ | 12 |
| ST-AUTH-DELEGATED | 11 |
| ST-FS-NODE-READ | 9 |
| ST-FS-PY-WRITE | 9 |
| ST-FS-NODE-WRITE | 7 |
| ST-SHELL-PY | 7 |
| ST-INSTALL-NPM-PREPARE | 6 |
| ST-AUTH-SCOPED | 4 |
| ST-EXPOSE-BIND | 3 |
| ST-MCP-DANGEROUS-TOOL | 2 |
| ST-DYN-NODE | 2 |

## Reproduce

Every number above is re-derivable: run the same manifest through the same engine.

```bash
pip install -e .
python tests/manual_eval/corpus_report.py  # default manifest: report_manifest.csv
```

The manifest auto-grows from the official MCP registry (append-only, with resolvability and public-hygiene gates and a per-run cap), so the corpus expands over time without manual curation.

Unreachable/private components are skipped (listed in the JSON), never silently dropped; results characterize the manifest, not a claim of statistical representativeness.

This report is aggregate-only. The JSON lists each component's source and scan status but **not** a per-component risk verdict, so it never publishes a risk label against a named third-party project — scan any component yourself with the command above.
