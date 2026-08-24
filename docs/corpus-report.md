# SkillTotal corpus report

Deterministic static scan of **52** AI components (engine v0.42.0, ruleset 46, schema 1.5, generated 2026-08-24).

Manifest sha256 `4259aed7ced6f1fc2942d19f39a1885e8a4161de62bded376a46876064b66e57` · components listed: 52 (scanned 52, skipped 0, errors 0).

## Risk level distribution

| level | count | % of scanned |
|---|---|---|
| low | 52 | 100.0% |
| medium | 0 | 0.0% |
| high | 0 | 0.0% |
| critical | 0 | 0.0% |

**Malicious indicators:** 0 / 52 components (0.0%) carry at least one deliberate malicious-indicator finding.

## OWASP Agentic Skills Top 10

Components with at least one finding mapped to each category (see `docs/owasp-agentic-skills-mapping.md`). AST06-AST10 are runtime/governance and not statically checkable, so they read 0 here by construction.

| category | count | % |
|---|---|---|
| AST01 | 2 | 3.8% |
| AST02 | 8 | 15.4% |
| AST03 | 4 | 7.7% |
| AST04 | 0 | 0.0% |
| AST05 | 1 | 1.9% |
| AST06 | 0 | 0.0% |
| AST07 | 0 | 0.0% |
| AST08 | 0 | 0.0% |
| AST09 | 0 | 0.0% |
| AST10 | 0 | 0.0% |

## Capability prevalence

| capability | count | % |
|---|---|---|
| delegated_authentication | 13 | 25.0% |
| dynamic_code_execution | 4 | 7.7% |
| filesystem_read | 22 | 42.3% |
| filesystem_write | 17 | 32.7% |
| install_time_execution | 8 | 15.4% |
| mcp_tools_detected | 29 | 55.8% |
| network_egress | 28 | 53.8% |
| scoped_identity | 4 | 7.7% |
| shell_execution | 19 | 36.5% |

## Top rules

| rule | components |
|---|---|
| ST-MCP-DETECTED | 29 |
| ST-NET-PY | 15 |
| ST-NET-NODE | 13 |
| ST-SHELL-NODE | 13 |
| ST-AUTH-DELEGATED | 13 |
| ST-FS-PY-READ | 13 |
| ST-FS-NODE-READ | 10 |
| ST-FS-PY-WRITE | 10 |
| ST-SHELL-PY | 8 |
| ST-FS-NODE-WRITE | 7 |
| ST-INSTALL-NPM-PREPARE | 6 |
| ST-EXPOSE-BIND | 4 |
| ST-AUTH-SCOPED | 4 |
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
