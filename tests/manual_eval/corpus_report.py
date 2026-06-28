"""Reproducible corpus characterization: scan a manifest of real AI components with the
static engine and aggregate the risk + OWASP Agentic Skills Top 10 distribution.

Stdlib only, no LLM, no execution beyond the engine's normal static analysis. Network-bound
when the manifest references registry/git sources; resilient per row (a single failure never
aborts the run). The full run is manual (like calibrate.py); CI tests the aggregation offline.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from skilltotal import REPORT_SCHEMA_VERSION, RULESET_VERSION, __version__, engine
from skilltotal.collector import CollectionError
from skilltotal.owasp import OWASP_TAXONOMY

_LEVELS = ("low", "medium", "high", "critical")


@dataclass
class CompResult:
    source: str
    type: str
    name: str
    status: str  # ok | skipped | error
    detail: str = ""
    resolved_version: str | None = None
    risk_level: str | None = None
    has_malicious: bool | None = None
    owasp: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)


def load_manifest(path: Path) -> list[tuple[str, str, str]]:
    """Parse the manifest CSV into ``(source, type, name)`` rows (blank/``#`` sources skipped)."""
    rows: list[tuple[str, str, str]] = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for r in csv.DictReader(fh):
            src = (r.get("source") or "").strip()
            if not src or src.startswith("#"):
                continue
            rows.append((src, (r.get("type") or "").strip(), (r.get("name") or "").strip()))
    return rows


def scan_row(source: str, type_: str, name: str) -> CompResult:
    """Statically analyze one component; never raises (records skipped/error instead)."""
    try:
        report = engine.analyze(source)
    except CollectionError as exc:
        return CompResult(source, type_, name, "skipped", detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - the harness must never abort the whole run
        return CompResult(source, type_, name, "error", detail=repr(exc))
    owasp = sorted({c for f in report.findings for c in f.owasp})
    verdict = report.verdict or {}
    return CompResult(
        source=source,
        type=type_,
        name=name,
        status="ok",
        resolved_version=report.component.version or None,
        risk_level=report.risk_level.value,
        has_malicious=bool(verdict.get("has_malicious_indicators")),
        owasp=owasp,
        capabilities=sorted(c.value for c in report.capabilities),
        rule_ids=[f.id for f in report.findings],
    )


def aggregate(results: list[CompResult], manifest_sha: str) -> dict:
    """Reduce per-component results to the published aggregate (deterministic, no I/O)."""
    ok = [r for r in results if r.status == "ok"]
    n = len(ok)

    def pct(c: int) -> float:
        return round(100 * c / n, 1) if n else 0.0

    risk = Counter(r.risk_level for r in ok)
    owasp_counts = {cat.id: sum(1 for r in ok if cat.id in r.owasp) for cat in OWASP_TAXONOMY}
    cap_counts = Counter(c for r in ok for c in r.capabilities)
    rule_counts = Counter(rid for r in ok for rid in r.rule_ids)
    by_type: dict[str, dict[str, int]] = {}
    for t in sorted({r.type for r in ok if r.type}):
        sub = [r for r in ok if r.type == t]
        by_type[t] = {lvl: sum(1 for r in sub if r.risk_level == lvl) for lvl in _LEVELS}
    mal = sum(1 for r in ok if r.has_malicious)
    return {
        "provenance": {
            "engine_version": __version__,
            "ruleset_version": RULESET_VERSION,
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "manifest_sha256": manifest_sha,
            "components_total": len(results),
            "scanned": n,
            "skipped": sum(1 for r in results if r.status == "skipped"),
            "errors": sum(1 for r in results if r.status == "error"),
        },
        "risk_distribution": {
            lvl: {"count": risk.get(lvl, 0), "pct": pct(risk.get(lvl, 0))} for lvl in _LEVELS
        },
        "malicious_indicators": {"count": mal, "pct": pct(mal)},
        "owasp": {cid: {"count": c, "pct": pct(c)} for cid, c in owasp_counts.items()},
        "capabilities": {cap: {"count": c, "pct": pct(c)} for cap, c in sorted(cap_counts.items())},
        "top_rules": [{"id": rid, "count": c} for rid, c in rule_counts.most_common(15)],
        "by_type": by_type,
        # Per-component rows carry the manifest identity + scan STATUS only — deliberately NOT a
        # per-project risk verdict (risk_level / has_malicious / rules). The report characterizes
        # the corpus in aggregate; it must never publish a risk label against a named third-party
        # project, where a false positive would be reputationally costly to them and to us.
        "components": [
            {"source": r.source, "type": r.type, "name": r.name, "status": r.status,
             "detail": r.detail}
            for r in results
        ],
    }


def to_markdown(agg: dict) -> str:
    """Render the aggregate as a human-readable Markdown report."""
    p = agg["provenance"]
    lines = [
        "# SkillTotal corpus report",
        "",
        f"Deterministic static scan of **{p['scanned']}** AI components "
        f"(engine v{p['engine_version']}, ruleset {p['ruleset_version']}, "
        f"schema {p['report_schema_version']}, generated {p['generated_at']}).",
        "",
        f"Manifest sha256 `{p['manifest_sha256']}` · components listed: {p['components_total']} "
        f"(scanned {p['scanned']}, skipped {p['skipped']}, errors {p['errors']}).",
        "",
        "## Risk level distribution",
        "",
        "| level | count | % of scanned |",
        "|---|---|---|",
    ]
    for lvl in _LEVELS:
        b = agg["risk_distribution"][lvl]
        lines.append(f"| {lvl} | {b['count']} | {b['pct']}% |")
    m = agg["malicious_indicators"]
    lines += [
        "",
        f"**Malicious indicators:** {m['count']} / {p['scanned']} components ({m['pct']}%) "
        "carry at least one deliberate malicious-indicator finding.",
        "",
        "## OWASP Agentic Skills Top 10",
        "",
        "Components with at least one finding mapped to each category "
        "(see `docs/owasp-agentic-skills-mapping.md`). AST06-AST10 are runtime/governance and "
        "not statically checkable, so they read 0 here by construction.",
        "",
        "| category | count | % |",
        "|---|---|---|",
    ]
    for cid in (f"AST{n:02d}" for n in range(1, 11)):
        b = agg["owasp"][cid]
        lines.append(f"| {cid} | {b['count']} | {b['pct']}% |")
    lines += ["", "## Capability prevalence", "", "| capability | count | % |", "|---|---|---|"]
    for cap, b in agg["capabilities"].items():
        lines.append(f"| {cap} | {b['count']} | {b['pct']}% |")
    lines += ["", "## Top rules", "", "| rule | components |", "|---|---|"]
    for row in agg["top_rules"]:
        lines.append(f"| {row['id']} | {row['count']} |")
    lines += [
        "",
        "## Reproduce",
        "",
        "Every number above is re-derivable: run the same manifest through the same engine.",
        "",
        "```bash",
        "pip install -e .",
        "python tests/manual_eval/corpus_report.py  # default manifest: report_manifest.csv",
        "```",
        "",
        "The manifest auto-grows from the official MCP registry (append-only, with resolvability "
        "and public-hygiene gates and a per-run cap), so the corpus expands over time without "
        "manual curation.",
        "",
        "Unreachable/private components are skipped (listed in the JSON), never silently dropped; "
        "results characterize the manifest, not a claim of statistical representativeness.",
        "",
        "This report is aggregate-only. The JSON lists each component's source and scan status but "
        "**not** a per-component risk verdict, so it never publishes a risk label against a named "
        "third-party project — scan any component yourself with the command above.",
        "",
    ]
    return "\n".join(lines)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate the SkillTotal corpus report.")
    ap.add_argument("--manifest", default="tests/manual_eval/report_manifest.csv")
    ap.add_argument("--out-prefix", default="docs/corpus-report")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds to sleep between rows")
    args = ap.parse_args(argv)

    manifest = Path(args.manifest)
    rows = load_manifest(manifest)
    results: list[CompResult] = []
    for i, (source, type_, name) in enumerate(rows, 1):
        print(f"[{i}/{len(rows)}] {source}", flush=True)
        results.append(scan_row(source, type_, name))
        if args.delay:
            time.sleep(args.delay)
    agg = aggregate(results, sha256_file(manifest))
    out_json = Path(f"{args.out_prefix}.json")
    out_md = Path(f"{args.out_prefix}.md")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(agg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out_md.write_text(to_markdown(agg), encoding="utf-8")
    p = agg["provenance"]
    print(
        f"wrote {out_json} and {out_md}: "
        f"scanned {p['scanned']}, skipped {p['skipped']}, errors {p['errors']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
