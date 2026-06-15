"""Public rules registry used by the ``skilltotal rules list`` command.

Aggregates every :class:`~skilltotal.scanners.base.RuleSpec` declared by the scanners and
adds the synthesized combination rule, so users can enumerate exactly what SkillTotal
looks for.
"""

from __future__ import annotations

from skilltotal.agent_skill import SKILL_MISMATCH_FINDING_ID
from skilltotal.models import Severity, ThreatClass
from skilltotal.scanners import all_rules
from skilltotal.scanners.base import RuleSpec
from skilltotal.scoring import COMBO_FINDING_ID

# The combination rule is synthesized in scoring, not by a scanner; expose it for listing.
# Its threat_class must match the synthesized finding (RISKY_CONSTRUCT): _assign_threat_classes
# projects this registry value onto the finding, so a mismatch here would silently un-score it.
_COMBO_RULE = RuleSpec(
    id=COMBO_FINDING_ID,
    category="exfiltration_path",
    severity=Severity.CRITICAL,
    title="Sensitive-data access combined with network egress",
    description=(
        "Raised when a component references credential/secret locations and can also reach "
        "the network — together a credential-exfiltration path."
    ),
    recommendation="Verify secrets read from disk are never transmitted off-host without consent.",
    capability=None,
    threat_class=ThreatClass.RISKY_CONSTRUCT,
)


# Synthesized in skilltotal.agent_skill (after capabilities), not by a scanner; expose for listing.
# threat_class must match the finding (RISKY_CONSTRUCT) or it is silently unscored.
_SKILL_MISMATCH_RULE = RuleSpec(
    id=SKILL_MISMATCH_FINDING_ID,
    category="least_privilege",
    severity=Severity.MEDIUM,
    title="Skill does more than its declared tools allow",
    description=(
        "Raised when an Agent Skill's declared allowed-tools do not cover a dangerous capability "
        "its bundled code actually exercises (undeclared-capability / least-privilege violation)."
    ),
    recommendation="Align allowed-tools with actual behavior, or remove the undeclared capability.",
    capability=None,
    threat_class=ThreatClass.RISKY_CONSTRUCT,
)


def get_rules() -> list[RuleSpec]:
    """All rules, sorted by id, including the synthesized combination + skill-mismatch rules."""
    rules = list(all_rules()) + [_COMBO_RULE, _SKILL_MISMATCH_RULE]
    return sorted(rules, key=lambda r: r.id)


def rules_as_dicts() -> list[dict[str, str]]:
    return [r.to_dict() for r in get_rules()]
