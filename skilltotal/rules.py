"""Public rules registry used by the ``skilltotal rules list`` command.

Aggregates every :class:`~skilltotal.scanners.base.RuleSpec` declared by the scanners and
adds the synthesized combination rule, so users can enumerate exactly what SkillTotal
looks for.
"""

from __future__ import annotations

from skilltotal.models import Severity
from skilltotal.scanners import all_rules
from skilltotal.scanners.base import RuleSpec
from skilltotal.scoring import COMBO_FINDING_ID

# The combination rule is synthesized in scoring, not by a scanner; expose it for listing.
_COMBO_RULE = RuleSpec(
    id=COMBO_FINDING_ID,
    category="exfiltration_path",
    severity=Severity.CRITICAL,
    title="Combined filesystem access and network egress",
    description=(
        "Raised when a component exhibits both filesystem and network capabilities."
    ),
    recommendation="Verify disk data is never transmitted off-host without consent.",
    capability=None,
)


def get_rules() -> list[RuleSpec]:
    """All rules, sorted by id, including the synthesized combination rule."""
    rules = list(all_rules()) + [_COMBO_RULE]
    return sorted(rules, key=lambda r: r.id)


def rules_as_dicts() -> list[dict[str, str]]:
    return [r.to_dict() for r in get_rules()]
