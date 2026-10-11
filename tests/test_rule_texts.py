"""Rule texts describe behavior, never a campaign.

A finding's title, description and recommendation appear on the report of whatever component the
rule matched, including well-known projects. "The MCP-config injection the SANDWORM_MODE npm
campaign used" next to the official MCP SDK's documented `mcp install` read as an accusation. The
invariant: interpret evidence only, never assert intent; where a technique was seen in the wild
belongs in a code comment and the changelog, not in what a report says about a component.
"""

from __future__ import annotations

import re

from skilltotal.rules import get_rules

_CAMPAIGN_WORDS = re.compile(
    r"\b(?:campaigns?|worms?|SANDWORM\w*|Shai[- ]Hulud|Miasma|s1ngularity|GlassWorm|ClawHavoc)\b",
    re.IGNORECASE,
)


def test_no_rule_text_names_a_malware_campaign():
    offenders = []
    for rule in get_rules():
        for field in ("title", "description", "recommendation"):
            text = getattr(rule, field, "") or ""
            match = _CAMPAIGN_WORDS.search(text)
            if match:
                offenders.append(f"{rule.id}.{field}: {match.group(0)!r}")
    assert not offenders, "rule texts name a campaign: " + "; ".join(offenders)
