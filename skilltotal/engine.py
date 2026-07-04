"""Analysis orchestrator — the reusable core entry point.

This module ties collection, indexing, scanning, capability extraction, and scoring
together into a single :class:`~skilltotal.models.Report`. Future web/SaaS products are
expected to import :func:`analyze_directory` (pure, no process I/O) directly; the CLI uses
:func:`analyze` which also handles source collection and cleanup.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from skilltotal import REPORT_SCHEMA_VERSION, RULESET_VERSION, __version__
from skilltotal.agent_skill import skill_capability_mismatch
from skilltotal.baseline import apply_suppressions
from skilltotal.capabilities import extract_capabilities
from skilltotal.collector import collect
from skilltotal.file_index import (
    FileIndex,
    IndexedFile,
    is_data_corpus_path,
    is_doc_path,
    is_test_path,
)
from skilltotal.models import (
    Component,
    Evidence,
    Finding,
    NeedsReview,
    Report,
    RiskLevel,
    Severity,
    ThreatClass,
)
from skilltotal.owasp import owasp_for
from skilltotal.rules import get_rules
from skilltotal.scanners import SCANNERS
from skilltotal.scoring import (
    compute_score,
    convergence_finding,
    exfiltration_finding,
    install_dropper_finding,
    risk_level,
    trifecta_finding,
)
from skilltotal.typosquatting import package_name_typosquatting


def analyze(
    source: str,
    *,
    suppress: set[str] | None = None,
    ignore_rules: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
) -> Report:
    """Resolve ``source`` (path or URL), analyze it, and return a Report."""
    with collect(source) as ctx:
        report = analyze_directory(
            ctx.root,
            ctx.component,
            suppress=suppress,
            ignore_rules=ignore_rules,
            exclude=exclude,
        )
        if ctx.note:
            report.needs_review.append(
                NeedsReview(category="source", title="Scan target normalized", reason=ctx.note)
            )
        return report


def analyze_directory(
    root: Path,
    component: Component,
    *,
    suppress: set[str] | None = None,
    ignore_rules: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
) -> Report:
    """Analyze an already-local component directory. Pure: no stdout, no exit.

    ``suppress`` is an optional set of baseline fingerprints to drop before scoring.
    ``ignore_rules`` drops whole rule ids; ``exclude`` is a list of path globs to skip.
    """
    index = FileIndex.build(Path(root), exclude=exclude)

    findings: list[Finding] = []
    needs_review: list[NeedsReview] = []
    for scanner in SCANNERS:
        result = scanner.scan(index)
        findings.extend(result.findings)
        needs_review.extend(result.needs_review)

    findings, suppressed_count = apply_suppressions(findings, suppress or set())
    ignore_set = {r for r in ignore_rules} if ignore_rules else set()
    if ignore_set:
        # Drop early so ignored base findings don't feed the synthesized rules below.
        findings = [f for f in findings if f.id not in ignore_set]
    findings = _apply_inline_ignores(findings, index)

    # Demote evidence that does not represent executed/agent-facing behavior to needs_review
    # (never scored). Sibling gates, applied in order:
    #   1. test code   - not executed by consumers
    #   2. documentation/prose - READMEs, changelogs, ignore-files: descriptive, not behavior
    #   3. data/eval corpus - inert reference data (eval_datasets/poisoning.yaml, fixtures/*.json):
    #      a sample attack is a detector test vector, not behavior (code there is still scored)
    #   4. Python/shell code-context - a pattern that only appears inside a string literal/comment
    #      is a literal or doc example (e.g. a scanner's own rule definitions), not behavior
    findings, test_review = _split_test_evidence(findings, index)
    needs_review.extend(test_review)
    findings, doc_review = _split_doc_evidence(findings)
    needs_review.extend(doc_review)
    findings, corpus_review = _split_data_corpus_evidence(findings)
    needs_review.extend(corpus_review)
    findings, code_ctx_review = _split_code_context_evidence(findings, index)
    needs_review.extend(code_ctx_review)

    capabilities = extract_capabilities(findings)

    # Sensitive-data access (credential paths / embedded secrets) + network egress is the
    # genuine credential-exfiltration pattern -> synthesized critical risky-construct finding.
    # (Plain filesystem + network is a neutral capability and is intentionally not flagged.)
    combo = exfiltration_finding(findings, capabilities)
    if combo is not None:
        findings.append(combo)

    # Lethal-trifecta flow: untrusted-instruction surface + file access + network egress.
    # Suppressed when the credential-specific combo already fired (covers the same concern).
    trifecta = trifecta_finding(findings, capabilities, combo_fired=combo is not None)
    if trifecta is not None:
        findings.append(trifecta)

    # Install-time dropper: a lifecycle/build hook paired with a decode-exec or credential payload.
    dropper = install_dropper_finding(findings)
    if dropper is not None:
        findings.append(dropper)

    # Agent Skill: declared allowed-tools vs. what the bundled code actually does (deterministic
    # least-privilege / undeclared-capability check). Synthesized here, after capabilities.
    mismatch = skill_capability_mismatch(component, index, capabilities)
    if mismatch is not None:
        findings.append(mismatch)

    # Supply chain: npm/PyPI package name one or two edits from a popular package (typosquatting).
    # Synthesized here off component identity; deterministic, evidence-anchored to the manifest.
    typosquat = package_name_typosquatting(component, index)
    if typosquat is not None:
        findings.append(typosquat)

    if ignore_set:
        # Drop again after synthesis so ignored synthesized ids (e.g. ST-COMBO-EXFIL) are honored.
        findings = [f for f in findings if f.id not in ignore_set]

    _assign_threat_classes(findings)

    # Convergence runs last: it counts the now-classified malicious indicators. A non-empty result
    # is already classified (RISKY_CONSTRUCT) on construction, so it needs no re-projection.
    convergence = convergence_finding(findings)
    if convergence is not None and convergence.id not in ignore_set:
        findings.append(convergence)

    # Attach OWASP Agentic Skills Top 10 categories last, once every finding (incl. synthesized
    # ones) is present. Pure metadata projection — never affects the score.
    _assign_owasp(findings)

    score = compute_score(findings)
    level = risk_level(score)

    report = Report(
        component=component,
        risk_score=score,
        risk_level=level,
        summary=_summary(level, score, findings, capabilities, needs_review),
        verdict=_verdict(findings, level),
        capabilities=capabilities,
        findings=_sort_findings(findings),
        needs_review=needs_review,
        metadata=_metadata(index, findings, suppressed_count),
    )
    return report


# Rule id -> threat class, from the single source of truth (RuleSpec via the registry).
_THREAT_CLASS_BY_ID = {r.id: r.threat_class for r in get_rules()}

# Rule id -> Python code-context policy, for rules that need string/comment demotion.
_CODE_CTX_POLICY = {r.id: r.code_context for r in get_rules() if r.code_context != "any"}


def _assign_threat_classes(findings: list[Finding]) -> None:
    """Project each rule's declared threat_class onto its findings (one chokepoint)."""
    for f in findings:
        f.threat_class = _THREAT_CLASS_BY_ID.get(f.id, f.threat_class)


def _assign_owasp(findings: list[Finding]) -> None:
    """Project each rule's OWASP Agentic Skills Top 10 categories onto its findings."""
    for f in findings:
        f.owasp = owasp_for(f.id)


def _verdict(findings: list[Finding], level) -> dict:
    """Plain-language top-line answer, mapped to the two real user fears:

    1. "Is it malicious?" -> ``has_malicious_indicators`` (deliberate deception/stealth
       only: poisoning, obfuscated exec, prompt injection, hidden unicode). Kept narrow and
       high-confidence so we never label a legitimate-but-powerful component "malware".
    2. "Could it leak my data / get me compromised?" -> the severity tier, surfaced as
       "High-risk capabilities" even with no malice (e.g. a clear-text credential+network
       exfiltration path). This keeps the headline consistent with the risk score instead of
       the confusing "critical, but not malware".

    Returns a single ``level`` (one of malicious | critical | high | medium | low), a
    human ``headline``, and up to three plain ``reasons``.
    """
    by_class = {c: 0 for c in ThreatClass}
    for f in findings:
        by_class[f.threat_class] += 1
    has_mal = by_class[ThreatClass.MALICIOUS_INDICATOR] > 0

    if has_mal:
        vlevel, headline = "malicious", "Malicious indicators found"
    elif level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        vlevel, headline = level.value, "High-risk capabilities - review before installing"
    elif level is RiskLevel.MEDIUM:
        vlevel, headline = "medium", "Some risk - review before installing"
    elif by_class[ThreatClass.CAPABILITY] > 0:
        # Clean, but powerful: no malicious indicators and no risky constructs, yet the
        # component has real capabilities (shell/filesystem/network). Acknowledge them instead
        # of the dismissive "nothing here" so a capable tool reads correctly.
        vlevel, headline = "low", "No malicious indicators - review capabilities before installing"
    else:
        vlevel, headline = "low", "No significant risks found"

    return {
        "level": vlevel,
        "headline": headline,
        "has_malicious_indicators": has_mal,
        "reasons": _verdict_reasons(findings),
        "malicious_indicators": by_class[ThreatClass.MALICIOUS_INDICATOR],
        "risky_constructs": by_class[ThreatClass.RISKY_CONSTRUCT],
        "capabilities": by_class[ThreatClass.CAPABILITY],
    }


def _verdict_reasons(findings: list[Finding], limit: int = 3) -> list[str]:
    """Top distinct finding titles (malicious first, then by severity) as plain reasons."""
    ordered = sorted(
        findings,
        key=lambda f: (f.threat_class is not ThreatClass.MALICIOUS_INDICATOR, -f.severity.rank),
    )
    reasons: list[str] = []
    for f in ordered:
        if f.title not in reasons:
            reasons.append(f.title)
        if len(reasons) >= limit:
            break
    return reasons


# Inline suppression marker: `# skilltotal:ignore` or `# skilltotal:ignore[ST-X, ST-Y]`
# (any comment syntax — #, //, <!-- -->). A bare marker ignores any rule on that line.
_INLINE_IGNORE_RE = re.compile(r"skilltotal:\s*ignore(?:\[([^\]]*)\])?", re.IGNORECASE)


def _apply_inline_ignores(findings: list[Finding], index: FileIndex) -> list[Finding]:
    """Drop evidence whose source line (or the line above) carries a skilltotal:ignore marker."""
    by_path = {f.relpath: f for f in index.files}
    kept: list[Finding] = []
    for finding in findings:
        remaining = [e for e in finding.evidence if not _line_ignores(e, finding.id, by_path)]
        if remaining:
            kept.append(_finding_with_evidence(finding, remaining))
    return kept


def _line_ignores(evidence: Evidence, rule_id: str, by_path: dict[str, IndexedFile]) -> bool:
    f = by_path.get(evidence.file)
    if f is None:
        return False
    for line_no in (evidence.line_start, evidence.line_start - 1):
        m = _INLINE_IGNORE_RE.search(f.line_text(line_no))
        if m is None:
            continue
        ids = m.group(1)
        if not ids:  # bare marker -> ignore whatever rule matched here
            return True
        wanted = {x.strip().upper() for x in ids.replace(";", ",").split(",") if x.strip()}
        if rule_id.upper() in wanted:
            return True
    return False


def _is_test_evidence(evidence: Evidence, by_path: dict[str, IndexedFile]) -> bool:
    """True if evidence is in test code — by path (test dirs/suffixes) or inline Rust tests.

    Rust unit tests live in the same .rs file as production code under `#[cfg(test)]` / `#[test]`,
    which the path-based ``is_test_path`` cannot see. That gated code is not compiled into the
    shipped artifact, so a credential there is a fixture, not behavior — demote it like any test.
    """
    if is_test_path(evidence.file):
        return True
    if evidence.match_offset is None:
        return False
    f = by_path.get(evidence.file)
    return f is not None and f.in_rust_test(evidence.match_offset)


def _split_test_evidence(
    findings: list[Finding],
    index: FileIndex,
) -> tuple[list[Finding], list[NeedsReview]]:
    """Keep only non-test evidence on findings; summarize test-only matches as review."""
    by_path = {f.relpath: f for f in index.files}
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        prod = [e for e in finding.evidence if not _is_test_evidence(e, by_path)]
        test = [e for e in finding.evidence if _is_test_evidence(e, by_path)]
        if prod:
            if len(prod) != len(finding.evidence):
                finding = Finding(
                    id=finding.id,
                    severity=finding.severity,
                    category=finding.category,
                    title=finding.title,
                    description=finding.description,
                    evidence=prod,
                    recommendation=finding.recommendation,
                )
            kept.append(finding)
        if test:
            files = sorted({e.file for e in test})
            review.append(
                NeedsReview(
                    category=finding.category,
                    title=f"{finding.title} (test code only)",
                    reason=(
                        f"{finding.id} matched only in test code "
                        f"({', '.join(files[:5])}); test code is not executed by consumers."
                    ),
                    file=files[0],
                    line=next((e.line_start for e in test if e.file == files[0]), None),
                )
            )
    return kept, review


def _finding_with_evidence(finding: Finding, evidence: list[Evidence]) -> Finding:
    """Return ``finding`` unchanged, or a copy with its evidence narrowed to ``evidence``."""
    if len(evidence) == len(finding.evidence):
        return finding
    return Finding(
        id=finding.id,
        severity=finding.severity,
        category=finding.category,
        title=finding.title,
        description=finding.description,
        evidence=evidence,
        recommendation=finding.recommendation,
        threat_class=finding.threat_class,
        owasp=finding.owasp,
    )


def _demoted_review(finding: Finding, demoted: list[Evidence], note: str) -> NeedsReview:
    files = sorted({e.file for e in demoted})
    return NeedsReview(
        category=finding.category,
        title=f"{finding.title} ({note})",
        reason=(
            f"{finding.id} matched only in {note} ({', '.join(files[:5])}); "
            "this context does not represent executed behavior."
        ),
        file=files[0],
        line=next((e.line_start for e in demoted if e.file == files[0]), None),
    )


def _split_doc_evidence(
    findings: list[Finding],
) -> tuple[list[Finding], list[NeedsReview]]:
    """Demote evidence found only in human-facing documentation/metadata to needs_review.

    READMEs, changelogs, license/notice files, docs/ trees and ignore-files are never executed
    and are not an agent-instruction surface (those — SKILL.md, manifests — are excluded by
    ``is_doc_path``), so a pattern that appears only there is descriptive, not behavior.
    """
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        prod = [e for e in finding.evidence if not is_doc_path(e.file)]
        docs = [e for e in finding.evidence if is_doc_path(e.file)]
        if prod:
            kept.append(_finding_with_evidence(finding, prod))
        if docs:
            review.append(_demoted_review(finding, docs, "documentation only"))
    return kept, review


def _split_data_corpus_evidence(
    findings: list[Finding],
) -> tuple[list[Finding], list[NeedsReview]]:
    """Demote evidence found only in inert data/eval/benchmark corpus files to needs_review.

    A pattern that appears only in reference data — a prompt-injection string in
    ``eval_datasets/poisoning.yaml``, a credential path in ``fixtures/sample.json`` — is a
    detector test vector or sample, not the component's executed behavior or agent-instruction
    surface. ``is_data_corpus_path`` is restricted to non-code files, so a real payload shipped
    as code in such a directory is still scanned and scored.
    """
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        prod = [e for e in finding.evidence if not is_data_corpus_path(e.file)]
        corpus = [e for e in finding.evidence if is_data_corpus_path(e.file)]
        if prod:
            kept.append(_finding_with_evidence(finding, prod))
        if corpus:
            review.append(_demoted_review(finding, corpus, "data/eval corpus only"))
    return kept, review


def _split_code_context_evidence(
    findings: list[Finding], index: FileIndex
) -> tuple[list[Finding], list[NeedsReview]]:
    """Demote regex matches inside a Python string literal/comment, per the rule's policy.

    A behavior/text detector matches its own pattern literals (and docstrings describing them)
    when scanning analyzer/security source; such `.py` matches are literals/examples, not
    executed behavior. Non-Python or non-regex (JSON/AST, no ``match_offset``) evidence is kept.
    """
    if not _CODE_CTX_POLICY:
        return findings, []
    by_path: dict[str, IndexedFile] = {f.relpath: f for f in index.files}
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        policy = _CODE_CTX_POLICY.get(finding.id)
        if policy is None:
            kept.append(finding)
            continue
        real = [e for e in finding.evidence if not _is_noncode_context(e, policy, by_path)]
        demoted = [e for e in finding.evidence if _is_noncode_context(e, policy, by_path)]
        if real:
            kept.append(_finding_with_evidence(finding, real))
        if demoted:
            review.append(
                _demoted_review(finding, demoted, "a non-executable string/comment context")
            )
    return kept, review


def _is_noncode_context(e: Evidence, policy: str, by_path: dict[str, IndexedFile]) -> bool:
    """True if evidence ``e`` is a non-executable string/comment match that ``policy`` demotes.

    Python: a match inside a comment (any policy) or a string literal
    (``strings_and_comments``/``strings_and_comments_all``).
    Shell: a match inside a ``#`` comment — so a ``# Usage: curl … | bash`` example line is a
    doc comment, not a runnable remote pipe-to-shell.
    C-family (.ts/.js/.go/.rs/…): a match inside a ``//`` or ``/* */`` comment — so a JSDoc line
    describing a threat (``* exfiltrate … to …``) is a description, not behavior. Under the
    ``strings_and_comments_all`` policy, C-family string literals are demoted too (a
    prompt-injection phrase held in a value-string is a pattern definition, not a live directive).
    """
    f = by_path.get(e.file)
    if f is None or e.match_offset is None:
        return False
    if f.suffix in (".py", ".pyw"):
        if f.in_comment(e.match_offset):
            return True
        return (
            policy in ("strings_and_comments", "strings_and_comments_all")
            and f.in_string(e.match_offset)
        )
    if f.suffix in (".sh", ".bash", ".zsh"):
        return f.in_shell_comment(e.match_offset)
    # C-family: demote matches in // and /* */ comments (a description in a code comment is not
    # behavior). String literals are demoted ONLY for the strings_and_comments_all policy
    # (ST-PROMPT-INJECTION); for every other rule a credential path passed as a string argument is
    # real access, so its C-family strings are kept.
    if f.in_c_comment(e.match_offset):
        return True
    return policy == "strings_and_comments_all" and f.in_c_string(e.match_offset)


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity.rank, f.id))


def _summary(level, score, findings, capabilities, needs_review) -> str:
    caps = ", ".join(sorted(c.value for c in capabilities)) or "none"
    parts = [
        f"Risk level {level.value.upper()} (score {score}/100).",
        f"{len(findings)} finding(s); capabilities: {caps}.",
    ]
    if needs_review:
        parts.append(f"{len(needs_review)} item(s) require manual review.")
    return " ".join(parts)


def _metadata(index: FileIndex, findings: list[Finding], suppressed_count: int) -> dict:
    by_severity = {s.value: 0 for s in Severity}
    for f in findings:
        by_severity[f.severity.value] += 1
    return {
        "skilltotal_version": __version__,
        "schema_version": REPORT_SCHEMA_VERSION,
        "ruleset_version": RULESET_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files_indexed": index.stats.get("indexed", 0),
        "files_skipped_binary": index.stats.get("skipped_binary", 0),
        "files_skipped_large": index.stats.get("skipped_large", 0),
        "scanners_run": [s.name for s in SCANNERS],
        "findings_by_severity": by_severity,
        "suppressed_count": suppressed_count,
    }
