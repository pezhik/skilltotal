"""OWASP Agentic Skills Top 10 (v1.0, 2026) taxonomy + the deterministic mapping from
SkillTotal rule ids to taxonomy categories.

Pure projection layer (like capabilities.py): no detection logic, no execution, no network.
It only attaches machine-readable, industry-standard references to findings the engine already
produced. We map a rule ONLY where there is a genuine, statically-checkable fit. Risks that
require runtime/governance observation (AST06-AST10) and classic code-level issues with no clean
AST category are intentionally left unmapped (empty tuple) rather than forced into a category.
See docs/owasp-agentic-skills-mapping.md for the rationale and honest gaps.
"""

from __future__ import annotations

from dataclasses import dataclass

_BASE_URL = "https://owasp.org/www-project-agentic-skills-top-10"


@dataclass(frozen=True)
class OwaspCategory:
    """One OWASP Agentic Skills Top 10 risk category."""

    id: str
    title: str
    url: str


# The full taxonomy (https://owasp.org/www-project-agentic-skills-top-10/, v1.0 2026 Edition).
OWASP_TAXONOMY: tuple[OwaspCategory, ...] = (
    OwaspCategory("AST01", "Malicious Skills", f"{_BASE_URL}/ast01"),
    OwaspCategory("AST02", "Supply Chain Compromise", f"{_BASE_URL}/ast02"),
    OwaspCategory("AST03", "Over-Privileged Skills", f"{_BASE_URL}/ast03"),
    OwaspCategory("AST04", "Insecure Metadata", f"{_BASE_URL}/ast04"),
    OwaspCategory("AST05", "Unsafe Deserialization", f"{_BASE_URL}/ast05"),
    OwaspCategory("AST06", "Weak Isolation", f"{_BASE_URL}/ast06"),
    OwaspCategory("AST07", "Update Drift", f"{_BASE_URL}/ast07"),
    OwaspCategory("AST08", "Poor Scanning", f"{_BASE_URL}/ast08"),
    OwaspCategory("AST09", "No Governance", f"{_BASE_URL}/ast09"),
    OwaspCategory("AST10", "Cross-Platform Reuse", f"{_BASE_URL}/ast10"),
)

VALID_OWASP_IDS: frozenset[str] = frozenset(c.id for c in OWASP_TAXONOMY)

# Explicit category tuple for EVERY rule id (empty tuple = no honest AST fit). The completeness
# test (tests/test_owasp_mapping.py) asserts this dict's keys equal rules.get_rules() exactly, so
# adding a new rule forces a deliberate taxonomy decision instead of a silent gap.
OWASP_BY_RULE: dict[str, tuple[str, ...]] = {
    # AST01 Malicious Skills — deliberate harm: decode-and-execute, persistence, exfiltration,
    # evasion, multi-indicator convergence.
    "ST-COMBO-EXFIL": ("AST01",),
    "ST-CONVERGENCE": ("AST01",),
    "ST-EMAIL-BCC-EXFIL": ("AST01",),
    "ST-ENCRYPTED-ARCHIVE": ("AST01",),
    "ST-FLOW-TRIFECTA": ("AST01",),
    "ST-OBF-DECODE-EXEC": ("AST01",),
    "ST-OBF-DECODE-EXEC-PY": ("AST01",),
    "ST-OBF-DECODE-EXEC-SH": ("AST01",),
    "ST-PTH-EXEC": ("AST01",),
    "ST-SHELL-EVASION": ("AST01",),
    # AST02 Supply Chain Compromise — install-time hooks and remote-fetch-and-run.
    "ST-INSTALL-DROPPER": ("AST02",),
    "ST-INSTALL-NPM": ("AST02",),
    "ST-INSTALL-NPM-PREPARE": ("AST02",),
    "ST-INSTALL-PY": ("AST02",),
    "ST-SHELL-PIPE-EXEC": ("AST02",),
    "ST-TYPOSQUAT": ("AST02",),
    # AST03 Over-Privileged Skills — excessive scope/autonomy/dangerous host powers.
    "ST-MCP-AUTO-APPROVE": ("AST03",),
    "ST-MCP-DANGEROUS-TOOL": ("AST03",),
    "ST-MCP-OVERBROAD-SCOPE": ("AST03",),
    "ST-MCP-SERVER-EXEC": ("AST03",),
    # AST04 Insecure Metadata — misleading/falsified descriptions, hidden/smuggled instructions.
    "ST-HIDDEN-UNICODE": ("AST04",),
    "ST-HIDDEN-UNICODE-AMBIG": ("AST04",),
    "ST-MCP-TOOL-POISONING": ("AST04",),
    "ST-MCP-TOOL-SHADOWING": ("AST04",),
    "ST-PROMPT-INJECTION": ("AST04",),
    "ST-PROMPT-WEAK": ("AST04",),
    # Spans both: code does more than the skill declares (falsified declaration + over-privilege).
    "ST-SKILL-CAP-MISMATCH": ("AST03", "AST04"),
    # AST05 Unsafe Deserialization.
    "ST-DESERIALIZE-PY": ("AST05",),
    "ST-TAINT-DESERIAL-PY": ("AST05",),
    # No honest AST fit — classic code-level vulnerabilities, raw capabilities, or network
    # misconfig. Left empty on purpose (never force a category); documented as gaps.
    "ST-AUTH-DELEGATED": (),  # capability / positive execution-context signal; no AST-risk fit
    "ST-AUTH-SCOPED": (),  # capability / positive execution-context signal; no AST-risk fit
    "ST-CMDI-NODE": (),
    "ST-CMDI-PY": (),
    "ST-DYN-NODE": (),
    "ST-DYN-PY": (),
    "ST-EXPOSE-BIND": (),
    "ST-EXPOSE-DEBUG": (),
    "ST-FS-NODE-READ": (),
    "ST-FS-NODE-WRITE": (),
    "ST-FS-PY-READ": (),
    "ST-FS-PY-WRITE": (),
    "ST-MCP-DETECTED": (),
    "ST-NET-NODE": (),
    "ST-NET-PY": (),
    "ST-OBF-BASE64-BLOB": (),
    "ST-OBF-HEX": (),
    "ST-OBF-MINIFIED": (),
    "ST-SECRET-EMBEDDED": (),
    "ST-SENS-PATH": (),
    "ST-SENS-PATH-PY": (),
    "ST-SENS-WORD": (),
    "ST-SHELL-NODE": (),
    "ST-SHELL-PY": (),
    "ST-TAINT-EXEC-PY": (),
    "ST-TAINT-SHELL-PY": (),
}


def owasp_for(rule_id: str) -> tuple[str, ...]:
    """OWASP Agentic Skills Top 10 category ids for a rule id (empty tuple if none/unknown)."""
    return OWASP_BY_RULE.get(rule_id, ())
