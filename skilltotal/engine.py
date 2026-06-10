"""Analysis orchestrator — the reusable core entry point.

This module ties collection, indexing, scanning, capability extraction, and scoring
together into a single :class:`~skilltotal.models.Report`. Future web/SaaS products are
expected to import :func:`analyze_directory` (pure, no process I/O) directly; the CLI uses
:func:`analyze` which also handles source collection and cleanup.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from skilltotal import REPORT_SCHEMA_VERSION, RULESET_VERSION, __version__
from skilltotal.baseline import apply_suppressions
from skilltotal.capabilities import extract_capabilities
from skilltotal.collector import collect
from skilltotal.file_index import FileIndex, is_test_path
from skilltotal.models import (
    Component,
    Finding,
    NeedsReview,
    Report,
    Severity,
)
from skilltotal.scanners import SCANNERS
from skilltotal.scoring import combined_fs_network_finding, compute_score, risk_level


def analyze(source: str, *, suppress: set[str] | None = None) -> Report:
    """Resolve ``source`` (path or URL), analyze it, and return a Report."""
    with collect(source) as ctx:
        return analyze_directory(ctx.root, ctx.component, suppress=suppress)


def analyze_directory(
    root: Path, component: Component, *, suppress: set[str] | None = None
) -> Report:
    """Analyze an already-local component directory. Pure: no stdout, no exit.

    ``suppress`` is an optional set of baseline fingerprints to drop before scoring.
    """
    index = FileIndex.build(Path(root))

    findings: list[Finding] = []
    needs_review: list[NeedsReview] = []
    for scanner in SCANNERS:
        result = scanner.scan(index)
        findings.extend(result.findings)
        needs_review.extend(result.needs_review)

    findings, suppressed_count = apply_suppressions(findings, suppress or set())

    # Demote findings whose evidence comes only from test code to needs_review; test code
    # is not executed by consumers, so it must not drive capabilities or the score.
    findings, test_review = _split_test_evidence(findings)
    needs_review.extend(test_review)

    capabilities = extract_capabilities(findings)

    combo = combined_fs_network_finding(capabilities)
    if combo is not None:
        findings.append(combo)

    score = compute_score(findings)
    level = risk_level(score)

    report = Report(
        component=component,
        risk_score=score,
        risk_level=level,
        summary=_summary(level, score, findings, capabilities, needs_review),
        capabilities=capabilities,
        findings=_sort_findings(findings),
        needs_review=needs_review,
        metadata=_metadata(index, findings, suppressed_count),
    )
    return report


def _split_test_evidence(
    findings: list[Finding],
) -> tuple[list[Finding], list[NeedsReview]]:
    """Keep only non-test evidence on findings; summarize test-only matches as review."""
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        prod = [e for e in finding.evidence if not is_test_path(e.file)]
        test = [e for e in finding.evidence if is_test_path(e.file)]
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
