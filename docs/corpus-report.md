# SkillTotal corpus report

Deterministic static scan of **32** AI components (engine v0.22.0, ruleset 23, schema 1.4, generated 2026-06-30).

Manifest sha256 `206779188897f83706423fea7eb19141ddf6bb3b7488696bc51c8be5a7b8c2a2` · components listed: 32 (scanned 32, skipped 0, errors 0).

## Risk level distribution

| level | count | % of scanned |
|---|---|---|
| low | 31 | 96.9% |
| medium | 0 | 0.0% |
| high | 1 | 3.1% |
| critical | 0 | 0.0% |

**Malicious indicators:** 0 / 32 components (0.0%) carry at least one deliberate malicious-indicator finding.

## OWASP Agentic Skills Top 10

Components with at least one finding mapped to each category (see `docs/owasp-agentic-skills-mapping.md`). AST06-AST10 are runtime/governance and not statically checkable, so they read 0 here by construction.

| category | count | % |
|---|---|---|
| AST01 | 1 | 3.1% |
| AST02 | 7 | 21.9% |
| AST03 | 4 | 12.5% |
| AST04 | 0 | 0.0% |
| AST05 | 1 | 3.1% |
| AST06 | 0 | 0.0% |
| AST07 | 0 | 0.0% |
| AST08 | 0 | 0.0% |
| AST09 | 0 | 0.0% |
| AST10 | 0 | 0.0% |

## Capability prevalence

| capability | count | % |
|---|---|---|
| dynamic_code_execution | 2 | 6.2% |
| filesystem_read | 13 | 40.6% |
| filesystem_write | 9 | 28.1% |
| install_time_execution | 7 | 21.9% |
| mcp_tools_detected | 10 | 31.2% |
| network_egress | 16 | 50.0% |
| shell_execution | 8 | 25.0% |

## Top rules

| rule | components |
|---|---|
| ST-MCP-DETECTED | 10 |
| ST-NET-PY | 10 |
| ST-FS-PY-READ | 8 |
| ST-NET-NODE | 6 |
| ST-FS-PY-WRITE | 6 |
| ST-FS-NODE-READ | 5 |
| ST-INSTALL-NPM-PREPARE | 5 |
| ST-MCP-DANGEROUS-TOOL | 4 |
| ST-SHELL-PY | 4 |
| ST-SHELL-NODE | 4 |
| ST-FS-NODE-WRITE | 3 |
| ST-EXPOSE-BIND | 2 |
| ST-DYN-PY | 2 |
| ST-INSTALL-NPM | 1 |
| ST-CMDI-PY | 1 |

## Reproduce

Every number above is re-derivable: run the same manifest through the same engine.

```bash
pip install -e .
python tests/manual_eval/corpus_report.py  # default manifest: report_manifest.csv
```

The manifest auto-grows from the official MCP registry (append-only, with resolvability and public-hygiene gates and a per-run cap), so the corpus expands over time without manual curation.

Unreachable/private components are skipped (listed in the JSON), never silently dropped; results characterize the manifest, not a claim of statistical representativeness.

This report is aggregate-only. The JSON lists each component's source and scan status but **not** a per-component risk verdict, so it never publishes a risk label against a named third-party project — scan any component yourself with the command above.
