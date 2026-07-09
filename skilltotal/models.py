"""Normalized, strongly-typed data models for SkillTotal.

These dataclasses are the contract shared by scanners, the scoring engine, the report
renderer, the CLI, and (in the future) the web/SaaS products. Keeping them dependency-free
(stdlib ``dataclasses`` + ``enum``) makes them trivial to serialize and reuse anywhere.

Design invariant (enforced in code): a confirmed :class:`Finding` MUST carry at least one
:class:`Evidence` object. Signals that cannot be evidenced belong in :class:`NeedsReview`,
never in ``findings``. This guarantees the project rule "no confirmed finding without
evidence".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity. Inherits ``str`` so values serialize directly to JSON."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> int:
        """Points this severity contributes to the risk score."""
        return _SEVERITY_WEIGHTS[self]

    @property
    def rank(self) -> int:
        """Ordinal for comparisons (higher = more severe)."""
        return _SEVERITY_RANK[self]


_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class RiskLevel(str, Enum):
    """Overall component risk band derived from the numeric risk score (0-100)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: int) -> RiskLevel:
        if score >= 75:
            return cls.CRITICAL
        if score >= 50:
            return cls.HIGH
        if score >= 25:
            return cls.MEDIUM
        return cls.LOW


class Capability(str, Enum):
    """Evidence-based capabilities a component may possess."""

    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    SHELL_EXECUTION = "shell_execution"
    NETWORK_EGRESS = "network_egress"
    INSTALL_TIME_EXECUTION = "install_time_execution"
    DYNAMIC_CODE_EXECUTION = "dynamic_code_execution"
    MCP_TOOLS_DETECTED = "mcp_tools_detected"
    PROMPT_SURFACE_RISK = "prompt_surface_risk"
    DELEGATED_AUTHENTICATION = "delegated_authentication"


class ThreatClass(str, Enum):
    """How to read a finding — the second axis next to severity.

    Separates "is this likely malware?" from "is this risky code?" so the report can give a
    fast malware verdict without drowning it in code-safety hygiene.
    """

    # Signals of deliberate deception / hidden execution (drives the malware verdict):
    # tool poisoning, prompt injection, decode-and-exec, hidden unicode instructions.
    MALICIOUS_INDICATOR = "malicious_indicator"
    # Dangerous, likely-unintentional constructs: hardcoded secrets, command injection,
    # unsafe deserialization, network exposure. A real risk regardless of author intent.
    RISKY_CONSTRUCT = "risky_construct"
    # Neutral capability surface (can exec / read fs / reach network). Informational.
    CAPABILITY = "capability"


@dataclass(frozen=True)
class Evidence:
    """A concrete, verifiable anchor for a finding.

    Every field is mandatory; an Evidence object always points at real source.
    """

    file: str
    line_start: int
    line_end: int
    snippet: str
    # Character offset of the match start within the source file. Internal only: NOT
    # serialized (keeps REPORT_SCHEMA_VERSION stable) and excluded from equality/hash, so it
    # never changes dedupe behavior. The engine's code-context demotion uses it to tell a real
    # construct from a pattern that merely appears inside a Python string literal or comment.
    # None when the evidence did not come from a regex match (e.g. AST/JSON anchored).
    match_offset: int | None = field(default=None, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "snippet": self.snippet,
        }


@dataclass
class Finding:
    """A confirmed, evidence-backed security finding."""

    id: str
    severity: Severity
    category: str
    title: str
    description: str
    evidence: list[Evidence]
    recommendation: str
    # Projected from the rule's RuleSpec by the engine; defaults to capability.
    threat_class: ThreatClass = ThreatClass.CAPABILITY
    # OWASP Agentic Skills Top 10 category ids (e.g. ("AST04",)); projected by the engine.
    # Empty when the rule has no honest fit in that taxonomy. Never affects the score.
    owasp: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # Hard invariant: a confirmed finding cannot exist without evidence.
        if not self.evidence:
            raise ValueError(
                f"Finding {self.id!r} has no evidence. Un-evidenced signals must be "
                "emitted as NeedsReview, not Finding."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": [e.to_dict() for e in self.evidence],
            "recommendation": self.recommendation,
            "threat_class": self.threat_class.value,
            "owasp": list(self.owasp),
        }


@dataclass
class NeedsReview:
    """A low-confidence or un-evidenced signal that must NOT affect the score.

    ``file``/``line`` are optional because some heuristics flag a condition without a
    precise location; when the line IS known, populate it so consumers can deep-link.
    """

    category: str
    title: str
    reason: str
    file: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "reason": self.reason,
            "file": self.file,
            "line": self.line,
        }


@dataclass
class CapabilityEvidence:
    """A detected capability together with the evidence that proves it."""

    capability: Capability
    evidence: list[Evidence]

    def to_dict(self) -> dict[str, Any]:
        return {"evidence": [e.to_dict() for e in self.evidence]}


@dataclass
class Component:
    """Identity of the analyzed component (derived only from the component itself)."""

    name: str
    type: str
    source: str
    version: str = ""
    # For package sources (npm/PyPI): the exact distribution artifact that was fetched
    # and analyzed. Lets consumers deep-link evidence to the published artifact (e.g.
    # PyPI files.pythonhosted.org URL -> inspector.pypi.io). None for git/local sources.
    download_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "source": self.source,
            "version": self.version,
            "download_url": self.download_url,
        }


@dataclass
class Report:
    """The complete, normalized analysis result."""

    component: Component
    risk_score: int
    risk_level: RiskLevel
    summary: str
    capabilities: dict[Capability, list[Evidence]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    needs_review: list[NeedsReview] = field(default_factory=list)
    # Fast top-line answer to "is this likely malware?" — independent of risk_score, which
    # also rises on legitimate-but-powerful or sloppy code. Populated by the engine.
    verdict: dict[str, Any] = field(default_factory=dict)
    # Behavioral trait fingerprint + standards crosswalk (CSA/MAESTRO/ATLAS). Pre-serialized
    # by the engine (like verdict/metadata) to keep this module independent of the traits
    # projection layer. Descriptive only — never affects the score (added in schema 1.5).
    traits: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component.to_dict(),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "summary": self.summary,
            "verdict": self.verdict,
            "capabilities": {
                cap.value: [e.to_dict() for e in evs]
                for cap, evs in self.capabilities.items()
            },
            "traits": self.traits,
            "findings": [f.to_dict() for f in self.findings],
            "needs_review": [n.to_dict() for n in self.needs_review],
            "metadata": self.metadata,
        }
