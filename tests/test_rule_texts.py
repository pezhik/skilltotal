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


# Verbs that say what the component DOES with intent ("steals", "harvests", "exfiltrates",
# "hijacks") instead of what was matched: a report says "sends a credential off-host", which the
# evidence shows, never "steals" it, which it cannot (review 2026-11-21: seven rules said so).
_INTENT_WORDS = re.compile(
    r"\b(?:steal(?:s|ing)?|harvest(?:s|ing)?|exfiltrat(?:es|ing|ed)|hijack(?:s|ing|ed)?)\b",
    re.IGNORECASE,
)


def test_rule_titles_and_descriptions_never_assert_intent():
    offenders = []
    for rule in get_rules():
        for field in ("title", "description"):
            text = getattr(rule, field, "") or ""
            match = _INTENT_WORDS.search(text)
            if match:
                offenders.append(f"{rule.id}.{field}: {match.group(0)!r}")
    assert not offenders, "rule texts assert intent: " + "; ".join(offenders)


def test_rule_texts_are_ascii():
    """The CLI prints these to consoles in a legacy code page (cp437, cp866), where an ellipsis or
    an em dash came out as mojibake or "?"."""
    offenders = []
    for rule in get_rules():
        for field in ("title", "description", "recommendation"):
            text = getattr(rule, field, "") or ""
            odd = sorted({c for c in text if ord(c) > 127})
            if odd:
                offenders.append(f"{rule.id}.{field}: {' '.join(f'U+{ord(c):04X}' for c in odd)}")
    assert not offenders, "rule texts carry non-ASCII characters: " + "; ".join(offenders)
