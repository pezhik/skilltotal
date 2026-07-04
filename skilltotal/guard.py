"""Install-time guard: an opinionated allow/block decision over a scan report.

``skilltotal guard <source>`` answers one question — "is it safe to install this component
right now?" — with an exit code an installer can chain on::

    skilltotal guard npm:some-mcp-server && claude mcp add some-mcp-server ...

The decision is deliberately different from the ``scan --fail-on`` severity gate. That gate
trips on any single finding of a given severity — including never-scored *capability*
findings (shell access, network egress) that almost every legitimate MCP server has, which
would make an install guard cry wolf on most of the ecosystem. The guard instead uses the
two signals designed for exactly this call: the malware verdict
(``has_malicious_indicators``) and the aggregate risk band (which only malicious-indicator
and risky-construct findings feed). A powerful-but-clean component is allowed; a component
with malicious indicators, or with scored risk at/above the block level, is not.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# What each --block-on level blocks, besides malicious indicators (always blocked).
_BLOCKED_BANDS: dict[str, tuple[str, ...]] = {
    "malicious": (),
    "high": ("high", "critical"),
    "medium": ("medium", "high", "critical"),
}

BLOCK_LEVELS = tuple(_BLOCKED_BANDS)
DEFAULT_BLOCK_LEVEL = "high"


@dataclass
class GuardDecision:
    """Allow/block outcome with the reasons that produced it (empty when allowed)."""

    allow: bool
    block_on: str
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": "allow" if self.allow else "block",
            "block_on": self.block_on,
            "reasons": self.reasons,
        }


def evaluate(report: dict[str, Any], block_on: str = DEFAULT_BLOCK_LEVEL) -> GuardDecision:
    """Decide allow/block for a serialized report (``Report.to_dict()`` shape)."""
    if block_on not in _BLOCKED_BANDS:
        raise ValueError(f"unknown block level: {block_on!r}")
    reasons: list[str] = []

    verdict = report.get("verdict") or {}
    if verdict.get("has_malicious_indicators"):
        headline = verdict.get("headline") or "malicious indicators present"
        reasons.append(f"malicious indicators: {headline}")

    risk_level = str(report.get("risk_level", ""))
    if risk_level in _BLOCKED_BANDS[block_on]:
        reasons.append(
            f"risk {report.get('risk_score', 0)}/100 ({risk_level}) is at/above the "
            f"'{block_on}' block level"
        )

    return GuardDecision(allow=not reasons, block_on=block_on, reasons=reasons)
