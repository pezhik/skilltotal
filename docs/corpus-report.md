# SkillTotal corpus report

Deterministic static scan of **47** AI components (engine v0.42.0, ruleset 46, schema 1.5, generated 2026-08-22).

Manifest sha256 `0fa2b1a24935e5c3615aee6a4f43c8efe1657443c4ab4684f6a6ee0186266b45` · components listed: 47 (scanned 47, skipped 0, errors 0).

## Risk level distribution

| level | count | % of scanned |
|---|---|---|
| low | 47 | 100.0% |
| medium | 0 | 0.0% |
| high | 0 | 0.0% |
| critical | 0 | 0.0% |

**Malicious indicators:** 0 / 47 components (0.0%) carry at least one deliberate malicious-indicator finding.

## OWASP Agentic Skills Top 10

Components with at least one finding mapped to each category (see `docs/owasp-agentic-skills-mapping.md`). AST06-AST10 are runtime/governance and not statically checkable, so they read 0 here by construction.

| category | count | % |
|---|---|---|
| AST01 | 2 | 4.3% |
| AST02 | 8 | 17.0% |
| AST03 | 4 | 8.5% |
| AST04 | 0 | 0.0% |
| AST05 | 1 | 2.1% |
| AST06 | 0 | 0.0% |
| AST07 | 0 | 0.0% |
| AST08 | 0 | 0.0% |
| AST09 | 0 | 0.0% |
| AST10 | 0 | 0.0% |

## Capability prevalence

| capability | count | % |
|---|---|---|
| delegated_authentication | 13 | 27.7% |
| dynamic_code_execution | 4 | 8.5% |
| filesystem_read | 21 | 44.7% |
| filesystem_write | 16 | 34.0% |
| install_time_execution | 8 | 17.0% |
| mcp_tools_detected | 24 | 51.1% |
| network_egress | 27 | 57.4% |
| scoped_identity | 4 | 8.5% |
| shell_execution | 19 | 40.4% |

## Top rules

| rule | components |
|---|---|
| ST-MCP-DETECTED | 24 |
| ST-NET-PY | 14 |
| ST-NET-NODE | 13 |
| ST-SHELL-NODE | 13 |
| ST-AUTH-DELEGATED | 13 |
| ST-FS-PY-READ | 12 |
| ST-FS-NODE-READ | 10 |
| ST-FS-PY-WRITE | 9 |
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
