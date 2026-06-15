"""Agent Skill (SKILL.md) analysis.

Parses the leading frontmatter of an Anthropic-style Agent Skill and flags a *declared-vs-actual*
capability mismatch: the skill declares an ``allowed-tools`` allow-list, but its bundled code
exercises a dangerous capability those tools do not grant (an undeclared-capability /
least-privilege violation). Like ``ST-COMBO-EXFIL`` this is synthesized after capabilities are
computed (see :mod:`skilltotal.engine`), so it is deterministic and evidence-anchored — no LLM,
no execution. Conservative on purpose: it fires only when the skill makes an explicit,
non-wildcard tool claim to contradict.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Component, Evidence, Finding, Severity, ThreatClass
from skilltotal.scanners.base import MAX_EVIDENCE_PER_FINDING

SKILL_MISMATCH_FINDING_ID = "ST-SKILL-CAP-MISMATCH"

_SKILL_RELPATHS = frozenset({"skill.md"})  # compared case-insensitively, root-level only
_WILDCARD_TOOLS = frozenset({"*", "all", "any"})

# A dangerous capability -> the Agent-Skill tool name(s) that would legitimately grant it
# (compared lower-cased). filesystem_read is intentionally omitted: reading files is ubiquitous
# and benign, so a read-only declaration is never contradicted by it.
_CAP_TOOLS: dict[Capability, frozenset[str]] = {
    Capability.SHELL_EXECUTION: frozenset({"bash", "shell"}),
    Capability.INSTALL_TIME_EXECUTION: frozenset({"bash", "shell"}),
    Capability.NETWORK_EGRESS: frozenset({"webfetch", "websearch", "fetch"}),
    Capability.FILESYSTEM_WRITE: frozenset({"write", "edit", "notebookedit"}),
    Capability.DYNAMIC_CODE_EXECUTION: frozenset(),  # no standard tool grants exec -> never covered
}
_CAP_LABEL: dict[Capability, str] = {
    Capability.SHELL_EXECUTION: "shell execution",
    Capability.INSTALL_TIME_EXECUTION: "install-time execution",
    Capability.NETWORK_EGRESS: "network egress",
    Capability.FILESYSTEM_WRITE: "filesystem write",
    Capability.DYNAMIC_CODE_EXECUTION: "dynamic code execution",
}
# Deterministic order for stable output.
_CAP_ORDER = (
    Capability.SHELL_EXECUTION,
    Capability.DYNAMIC_CODE_EXECUTION,
    Capability.NETWORK_EGRESS,
    Capability.FILESYSTEM_WRITE,
    Capability.INSTALL_TIME_EXECUTION,
)


def parse_skill_frontmatter(text: str) -> dict | None:
    """Parse a SKILL.md's leading ``--- ... ---`` frontmatter (tolerant, stdlib only).

    Returns ``{"name", "description", "allowed_tools"}`` where ``allowed_tools`` is ``None`` when
    the key is absent (no claim) or a list of tool names when present. Returns ``None`` if there
    is no frontmatter block.
    """
    if not text.startswith("---"):
        return None
    m = re.match(r"---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|$)", text, re.DOTALL)
    if not m:
        return None
    lines = m.group(1).splitlines()
    out: dict = {"name": "", "description": "", "allowed_tools": None}
    i, n = 0, len(lines)
    while i < n:
        km = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", lines[i])
        if not km:
            i += 1
            continue
        key, val = km.group(1).lower(), km.group(2).strip()
        if key in ("allowed-tools", "allowed_tools", "tools"):
            if val.startswith("["):
                inner = val[1:]
                if "]" in inner:
                    inner = inner[: inner.rindex("]")]
                out["allowed_tools"] = [_unquote(x) for x in inner.split(",") if x.strip()]
                i += 1
            elif val and not val.startswith("#"):
                out["allowed_tools"] = [_unquote(x) for x in val.split(",") if x.strip()]
                i += 1
            else:  # block list: subsequent "- item" lines
                tools: list[str] = []
                i += 1
                while i < n:
                    bm = re.match(r"^\s*-\s+(.*)$", lines[i])
                    if not bm:
                        break
                    tools.append(_unquote(bm.group(1)))
                    i += 1
                out["allowed_tools"] = tools
        elif key in ("name", "description"):
            out[key] = _unquote(val)
            i += 1
        else:
            i += 1
    return out


def skill_capability_mismatch(
    component: Component,
    index: FileIndex,
    capabilities: dict[Capability, list[Evidence]],
) -> Finding | None:
    """Synthesize ST-SKILL-CAP-MISMATCH when declared tools don't cover what the code does.

    Fires only for an ``agent_skill`` component whose root SKILL.md declares a non-empty,
    non-wildcard ``allowed-tools`` list, when a dangerous capability is exhibited that none of the
    declared tools grant. Evidence pairs the declaration with the offending capability's evidence,
    so the "no finding without evidence" invariant holds.
    """
    if component.type != "agent_skill":
        return None
    skill = _root_skill_file(index)
    if skill is None:
        return None
    fm = parse_skill_frontmatter(skill.text)
    if fm is None or fm["allowed_tools"] is None:
        return None  # no explicit allow-list -> no claim to contradict
    declared = {t.strip().lower() for t in fm["allowed_tools"] if t.strip()}
    if not declared or declared & _WILDCARD_TOOLS:
        return None  # empty or wildcard -> not a restrictive claim

    offending = [
        cap
        for cap in _CAP_ORDER
        if cap in capabilities and not (declared & _CAP_TOOLS[cap])
    ]
    if not offending:
        return None

    labels = ", ".join(_CAP_LABEL[c] for c in offending)
    declared_str = ", ".join(sorted(declared))
    evidence: list[Evidence] = [_allowed_tools_evidence(skill)]
    for cap in offending:
        evidence.extend(capabilities.get(cap, [])[:2])
    evidence = _dedupe(evidence)[:MAX_EVIDENCE_PER_FINDING]

    return Finding(
        id=SKILL_MISMATCH_FINDING_ID,
        severity=Severity.MEDIUM,
        category="least_privilege",
        title="Skill does more than its declared tools allow",
        description=(
            f"The skill's frontmatter declares allowed-tools ({declared_str}), but its bundled "
            f"code exercises capabilities those tools do not grant: {labels}. This is an "
            "undeclared-capability / least-privilege violation — over-broad code, or a payload "
            "hidden behind a narrow declaration."
        ),
        evidence=evidence,
        recommendation=(
            "Align the skill's allowed-tools with what the code actually does, or remove the "
            "undeclared capability. Treat a wide gap as suspicious until explained."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )


def _root_skill_file(index: FileIndex) -> IndexedFile | None:
    for f in index.files:
        if "/" not in f.relpath and f.relpath.lower() in _SKILL_RELPATHS:
            return f
    return None


def _allowed_tools_evidence(skill: IndexedFile) -> Evidence:
    m = re.search(r"(?im)^[ \t]*(?:allowed[-_]tools|tools)[ \t]*:", skill.text)
    if m:
        return skill.evidence_for_span(m.start(), m.end())
    return skill.evidence_for_lines(1, 1)


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        s = s[1:-1]
    return s.strip()


def _dedupe(evidence: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, int, int]] = set()
    out: list[Evidence] = []
    for e in evidence:
        key = (e.file, e.line_start, e.line_end)
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out
