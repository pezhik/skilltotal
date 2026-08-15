# SkillTotal corpus report

Deterministic static scan of **37** AI components (engine v0.38.1, ruleset 42, schema 1.5, generated 2026-08-10).

Manifest sha256 `c411ee1b829a75517832c235311647dcb7b6c11108d2e26f5325f7dc72e7306c` · components listed: 37 (scanned 37, skipped 0, errors 0).

## Risk level distribution

| level | count | % of scanned |
|---|---|---|
| low | 37 | 100.0% |
| medium | 0 | 0.0% |
| high | 0 | 0.0% |
| critical | 0 | 0.0% |

**Malicious indicators:** 0 / 37 components (0.0%) carry at least one deliberate malicious-indicator finding.

## OWASP Agentic Skills Top 10

Components with at least one finding mapped to each category (see `docs/owasp-agentic-skills-mapping.md`). AST06-AST10 are runtime/governance and not statically checkable, so they read 0 here by construction.

| category | count | % |
|---|---|---|
| AST01 | 1 | 2.7% |
| AST02 | 7 | 18.9% |
| AST03 | 3 | 8.1% |
| AST04 | 0 | 0.0% |
| AST05 | 1 | 2.7% |
| AST06 | 0 | 0.0% |
| AST07 | 0 | 0.0% |
| AST08 | 0 | 0.0% |
| AST09 | 0 | 0.0% |
| AST10 | 0 | 0.0% |

## Capability prevalence

| capability | count | % |
|---|---|---|
| delegated_authentication | 6 | 16.2% |
| dynamic_code_execution | 3 | 8.1% |
| filesystem_read | 15 | 40.5% |
| filesystem_write | 12 | 32.4% |
| install_time_execution | 7 | 18.9% |
| mcp_tools_detected | 14 | 37.8% |
| network_egress | 19 | 51.4% |
| scoped_identity | 4 | 10.8% |
| shell_execution | 11 | 29.7% |

## Top rules

| rule | components |
|---|---|
| ST-MCP-DETECTED | 14 |
| ST-NET-PY | 12 |
| ST-FS-PY-READ | 10 |
| ST-FS-PY-WRITE | 8 |
| ST-NET-NODE | 7 |
| ST-SHELL-NODE | 7 |
| ST-SHELL-PY | 6 |
| ST-AUTH-DELEGATED | 6 |
| ST-FS-NODE-READ | 5 |
| ST-INSTALL-NPM-PREPARE | 5 |
| ST-FS-NODE-WRITE | 4 |
| ST-AUTH-SCOPED | 4 |
| ST-MCP-DANGEROUS-TOOL | 2 |
| ST-EXPOSE-BIND | 2 |
| ST-DYN-PY | 2 |

## Reproduce

Every number above is re-derivable: run the same manifest through the same engine.

```bash
pip install -e .
python tests/manual_eval/corpus_report.py  # default manifest: report_manifest.csv
```

The manifest auto-grows from the official MCP registry (append-only, with resolvability and public-hygiene gates and a per-run cap), so the corpus expands over time without manual curation.

Unreachable/private components are skipped (listed in the JSON), never silently dropped; results characterize the manifest, not a claim of statistical representativeness.

This report is aggregate-only. The JSON lists each component's source and scan status but **not** a per-component risk verdict, so it never publishes a risk label against a named third-party project — scan any component yourself with the command above.
