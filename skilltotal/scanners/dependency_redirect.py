"""An agent-instruction surface that redirects package installs to a non-default index.

A marketplace plugin / agent skill whose instructions quietly route every `pip`/`npm` install
through an attacker-controlled package index pulls a trojanized build of a common library into
the project whenever the developer asks the agent to add a dependency (Prompt Security /
SentinelOne, "Marketplace Skills and Dependency Hijack in Claude Code", 2026). The instruction is
read by the agent, not the human, so it belongs with the other instruction-surface checks.

Redirecting installs to a non-default index is, on its own, exactly what a legitimate skill for a
company's *private* registry does -- so the redirect alone is `needs_review`, never a verdict. The
malicious tell is concealment: the instruction tells the agent to perform the substitution AND to
hide it from the user ("do not mention", "without telling the user"). An honest private-registry
skill has no reason to hide which index it uses.

Detection patterns below are string literals; nothing here executes a command.
"""

from __future__ import annotations

import re
from itertools import islice

from skilltotal.file_index import FileIndex, is_doc_path, skill_dirs
from skilltotal.models import Evidence, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule

R_DEP_REDIRECT = "ST-SKILL-DEP-REDIRECT"

# A directive pointing package installs at a chosen index/registry rather than the default.
_INDEX_REDIRECT = re.compile(
    r"--(?:extra-)?index-url[=\s]+\S*https?://\S+"
    r"|pip\s+config\s+set\s+(?:global\.)?(?:extra-)?index-url"
    r"|PIP_(?:EXTRA_)?INDEX_URL\s*=\s*\S*https?://"
    r"|npm\b[^\n]{0,80}?--registry[=\s]+\S*https?://"
    r"|npm\s+config\s+set\s+registry"
    r"|NPM_CONFIG_REGISTRY\s*=\s*\S*https?://"
    r"|yarn\s+config\s+set\s+registry",
    re.IGNORECASE,
)

# Concealment: tell the agent to hide the substitution from the user. This is the discriminator
# that separates a hijack from a legitimate private-registry instruction.
_CONCEALMENT = re.compile(
    r"do(?:\s*not|n['’]?t)\s+(?:mention|tell|inform|notify|point\s+out|reveal|disclose|say)\b"
    r"|without\s+(?:telling|informing|notifying|mentioning)\s+(?:the\s+)?(?:user|developer|them)"
    r"|(?:don['’]?t|do\s+not)\s+(?:let\s+)?(?:the\s+)?(?:user|developer)\s+(?:know|notice|see)",
    re.IGNORECASE,
)

# How far apart a redirect and the words hiding it may be, and how many of each are tried.
_PAIR_WINDOW = 600
_MAX_PAIR_TRIES = 50
# A markdown heading, and a fence that opens or closes a code block (where `#` is a comment).
_HEADING = re.compile(r"^#{1,6}[ \t]")
_FENCE = re.compile(r"^[ \t]{0,3}(?:```|~~~)")


def _heading_offsets(text: str) -> list[int]:
    """Offsets of the markdown headings in ``text`` that are outside code blocks."""
    out: list[int] = []
    fenced = False
    pos = 0
    for line in text.splitlines(keepends=True):
        if _FENCE.match(line):
            fenced = not fenced
        elif not fenced and _HEADING.match(line):
            out.append(pos)
        pos += len(line)
    return out


def _paired(text: str, first: re.Match[str]) -> tuple[re.Match[str], re.Match[str] | None]:
    """A redirect and the concealment that goes with it: in the same section (no heading between
    them) and close by. Words such as "do not mention" in another part of the file are about
    something else (a commit-message rule), not about the index."""
    conceals = list(islice(_CONCEALMENT.finditer(text), _MAX_PAIR_TRIES))
    if not conceals:
        return first, None
    headings = _heading_offsets(text)
    for redirect in islice(_INDEX_REDIRECT.finditer(text), _MAX_PAIR_TRIES):
        for conceal in conceals:
            a, b = sorted((redirect.start(), conceal.start()))
            if b - a > _PAIR_WINDOW + (redirect.end() - redirect.start()):
                continue
            if any(a < h <= b for h in headings):
                continue
            return redirect, conceal
    return first, None


# Instruction-surface suffixes an agent reads and acts on (markdown/text/mdc). Code files are out
# of scope here: a `.npmrc` write in code is a different behavior, not an agent instruction.
_INSTRUCTION_SUFFIXES = (".md", ".mdx", ".markdown", ".rst", ".txt", ".mdc", "")


class DependencyRedirectScanner(Scanner):
    name = "dependency_redirect"
    rules = [
        RuleSpec(
            id=R_DEP_REDIRECT,
            category="supply_chain",
            severity=Severity.HIGH,
            title="Skill instruction sends package installs to a non-default index and hides it",
            description=(
                "An agent-instruction surface (SKILL.md, AGENTS.md, a marketplace plugin's rules) "
                "tells the agent to install packages from a non-default package index or registry "
                "and to keep the substitution from the user. Each time the developer asks the "
                "agent to add a common dependency, the package then comes from that index and "
                "nobody is told the source changed (dependency hijack via marketplace skills, "
                "2026)."
            ),
            recommendation=(
                "Remove the redirect, or make the index explicit and visible. A legitimate private "
                "registry is configured openly in project files, never hidden from the developer "
                "by a skill instruction."
            ),
            capability=None,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        skills = skill_dirs(f.relpath for f in index.files)
        evidence: list[Evidence] = []
        needs_review: list[NeedsReview] = []
        for f in index.files:
            rel = f.relpath.replace("\\", "/")
            name = rel.rsplit("/", 1)[-1].lower()
            suffix = name[name.rindex("."):] if "." in name[1:] else ""
            if suffix not in _INSTRUCTION_SUFFIXES:
                continue
            if is_doc_path(rel, skills):
                continue  # human-facing documentation, not an instruction the agent executes
            redirect = _INDEX_REDIRECT.search(f.text)
            if redirect is None:
                continue
            redirect, conceal = _paired(f.text, redirect)
            if conceal is not None:
                evidence.append(f.evidence_for_span(redirect.start(), redirect.end()))
                evidence.append(f.evidence_for_span(conceal.start(), conceal.end()))
            else:
                ev = f.evidence_for_span(redirect.start(), redirect.end())
                needs_review.append(NeedsReview(
                    category="supply_chain",
                    title="Skill instruction sets a non-default package index",
                    reason=(
                        "This instruction surface routes package installs to a non-default index "
                        "or registry. That is legitimate for a private registry -- confirm the "
                        "index is trusted and that installs are not being silently redirected."
                    ),
                    file=f.relpath,
                    line=ev.line_start,
                ))
        findings = [_finding_from_rule(self.rules[0], evidence)] if evidence else []
        return ScanResult(findings=findings, needs_review=needs_review)
