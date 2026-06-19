# OWASP Agentic Skills Top 10 — coverage mapping

How SkillTotal's deterministic static findings map to the
[OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) (v1.0, 2026).
Every finding in the JSON report carries an `owasp` array of category ids (e.g. `["AST04"]`), and
SARIF output emits the taxonomy as native `taxonomies` + per-rule `relationships`. The mapping is a
pure, machine-readable projection over the rule registry (`skilltotal/owasp.py`, `OWASP_BY_RULE`) —
no execution, no LLM. It is the single source of truth; a completeness test
(`tests/test_owasp_mapping.py`) forces every rule to declare a category or an explicit empty mapping.

**Honesty rule:** a rule is mapped only where there is a genuine, statically-checkable fit. Risks
that need runtime/governance observation (AST06–AST10) and classic code-level findings with no clean
AST category are left **unmapped** (empty `owasp`) rather than forced into a label.

## Covered (statically checkable)

| OWASP category | SkillTotal rules | Notes |
|---|---|---|
| **AST01 Malicious Skills** | `ST-OBF-DECODE-EXEC(-PY/-SH)`, `ST-PTH-EXEC`, `ST-ENCRYPTED-ARCHIVE`, `ST-SHELL-EVASION`, `ST-COMBO-EXFIL`, `ST-FLOW-TRIFECTA`, `ST-EMAIL-BCC-EXFIL`, `ST-CONVERGENCE` | deliberate harm: decode-and-execute, persistence, exfiltration, evasion, multi-indicator convergence |
| **AST02 Supply Chain Compromise** | `ST-INSTALL-NPM(-PREPARE)`, `ST-INSTALL-PY`, `ST-INSTALL-DROPPER`, `ST-SHELL-PIPE-EXEC` | install-time hooks and remote-fetch-and-run (`curl \| sh`) |
| **AST03 Over-Privileged Skills** | `ST-MCP-OVERBROAD-SCOPE`, `ST-MCP-AUTO-APPROVE`, `ST-MCP-DANGEROUS-TOOL`, `ST-MCP-SERVER-EXEC`, `ST-SKILL-CAP-MISMATCH` | excessive scope/autonomy/dangerous host powers; undeclared capabilities |
| **AST04 Insecure Metadata** | `ST-MCP-TOOL-POISONING`, `ST-MCP-TOOL-SHADOWING`, `ST-PROMPT-INJECTION`, `ST-PROMPT-WEAK`, `ST-HIDDEN-UNICODE(-AMBIG)`, `ST-SKILL-CAP-MISMATCH` | misleading/falsified descriptions, hidden/smuggled instructions, falsified capability declarations |
| **AST05 Unsafe Deserialization** | `ST-DESERIALIZE-PY`, `ST-TAINT-DESERIAL-PY` | unsafe `pickle`/`yaml`/`marshal` loads, incl. taint into a deserialize sink |

`ST-SKILL-CAP-MISMATCH` spans **AST03 + AST04** (code does more than the skill declares: both
over-privilege and a falsified declaration).

## Honest gaps (intentionally unmapped)

- **AST06 Weak Isolation, AST07 Update Drift, AST08 Poor Scanning, AST09 No Governance,
  AST10 Cross-Platform Reuse** — these require executing the skill, registry/advisory data, or
  organizational process, none of which a component-only static engine observes. Update-drift /
  dependency-CVE and cross-platform provenance are out of scope for the offline engine; runtime
  isolation and governance belong to the hosted SkillTotal Cloud and to deployment process.
- **Classic code-level findings and raw capabilities carry no AST category** (empty `owasp`):
  command injection (`ST-CMDI-*`, `ST-TAINT-SHELL/EXEC-PY`), dynamic code execution capability
  (`ST-DYN-*`), filesystem/network/shell capabilities (`ST-FS-*`, `ST-NET-*`, `ST-SHELL-NODE/PY`),
  MCP presence (`ST-MCP-DETECTED`), obfuscation signals (`ST-OBF-BASE64-BLOB/HEX/MINIFIED`),
  hardcoded secrets / sensitive-path access (`ST-SECRET-EMBEDDED`, `ST-SENS-*`), and network
  exposure misconfig (`ST-EXPOSE-*`). They are still reported with full evidence; they simply have
  no honest single AST category, and capability findings never affect the score.

> A complete agentic-skill posture needs both static (this engine) and runtime/governance
> verification; SkillTotal's free engine covers the statically-checkable AST risks end-to-end and
> reports the rest honestly rather than implying coverage it does not have. See also
> `docs/mcp-owasp-mapping.md` for the OWASP MCP Security Cheat Sheet mapping.
