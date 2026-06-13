"""Public rules registry used by the ``skilltotal rules list`` command.

Aggregates every :class:`~skilltotal.scanners.base.RuleSpec` declared by the scanners and
adds the synthesized combination rule, so users can enumerate exactly what SkillTotal
looks for.
"""

from __future__ import annotations

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


def get_rules() -> list[RuleSpec]:
    """All rules, sorted by id, including the synthesized combination rule."""
    rules = list(all_rules()) + [_COMBO_RULE]
    return sorted(rules, key=lambda r: r.id)


def rules_as_dicts() -> list[dict[str, str]]:
    return [r.to_dict() for r in get_rules()]
