"""Report rendering: JSON and human-readable text.

Rendering is kept separate from analysis so the same :class:`~skilltotal.models.Report`
can feed a CLI, a web response, or a SaaS API without change.
"""

from __future__ import annotations

import json

from skilltotal.models import Report
from skilltotal.scanners.base import RuleSpec

_INDENT = "  "


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def render_text(report: Report) -> str:
    c = report.component
    lines: list[str] = []
    lines.append("SkillTotal Security Report")
    lines.append("=" * 26)
    version = f" {c.version}" if c.version else ""
    lines.append(f"Component : {c.name}{version} ({c.type})")
    lines.append(f"Source    : {c.source}")
    lines.append(f"Risk      : {report.risk_level.value.upper()}  (score {report.risk_score}/100)")
    lines.append("")
    lines.append(report.summary)
    lines.append("")

    # Capabilities
    if report.capabilities:
        lines.append("Capabilities:")
        for cap, evs in sorted(report.capabilities.items(), key=lambda kv: kv[0].value):
            lines.append(f"{_INDENT}- {cap.value} ({len(evs)} evidence)")
        lines.append("")

    # Findings
    lines.append(f"Findings ({len(report.findings)}):")
    if not report.findings:
        lines.append(f"{_INDENT}(none)")
    for f in report.findings:
        lines.append(f"{_INDENT}[{f.severity.value.upper()}] {f.id}  {f.title}")
        lines.append(f"{_INDENT*2}{f.description}")
        lines.append(f"{_INDENT*2}Recommendation: {f.recommendation}")
        lines.append(f"{_INDENT*2}Evidence:")
        for e in f.evidence:
            loc = f"{e.file}:{e.line_start}-{e.line_end}"
            lines.append(f"{_INDENT*3}- {loc}")
            for snippet_line in e.snippet.splitlines() or [e.snippet]:
                lines.append(f"{_INDENT*4}{snippet_line}")
        lines.append("")

    # Needs review
    if report.needs_review:
        lines.append(f"Needs review ({len(report.needs_review)}):")
        for n in report.needs_review:
            where = f" ({n.file})" if n.file else ""
            lines.append(f"{_INDENT}- [{n.category}] {n.title}{where}")
            lines.append(f"{_INDENT*2}{n.reason}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_inventory_json(items: list[dict]) -> str:
    return json.dumps(items, indent=2, ensure_ascii=False)


def render_inventory_text(items: list[dict]) -> str:
    """Render the installed-component inventory as an aligned table."""
    if not items:
        return "No installed AI components (MCP servers or skills) found.\n"
    rows = []
    for it in items:
        verdict = it.get("verdict") or ("-" if it.get("scannable") else "not scanned")
        risk = it.get("risk_level") or ""
        where = it.get("source") or it.get("note", "")
        rows.append((it["host"], it["name"], it["kind"], where, verdict, risk))
    headers = ("HOST", "NAME", "KIND", "SOURCE", "VERDICT", "RISK")
    widths = [max(len(headers[i]), *(len(str(r[i])) for r in rows)) for i in range(len(headers))]
    lines = [f"SkillTotal inventory ({len(items)} component(s))", ""]
    lines.append("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    lines.append("-" * (sum(widths) + 2 * (len(headers) - 1)))
    for r in rows:
        lines.append("  ".join(str(r[i]).ljust(widths[i]) for i in range(len(headers))))
    flagged = [it for it in items if it.get("verdict") in ("malicious", "critical", "high")]
    if flagged:
        lines.append("")
        lines.append(f"{len(flagged)} component(s) need attention (high risk or malicious).")
    return "\n".join(lines) + "\n"


def render_rules_json(rules: list[RuleSpec]) -> str:
    return json.dumps([r.to_dict() for r in rules], indent=2, ensure_ascii=False)


def render_rules_text(rules: list[RuleSpec]) -> str:
    lines = [f"SkillTotal rules ({len(rules)}):", ""]
    id_w = max((len(r.id) for r in rules), default=2)
    sev_w = 8
    cat_w = max((len(r.category) for r in rules), default=8)
    header = f"{'ID'.ljust(id_w)}  {'SEVERITY'.ljust(sev_w)}  {'CATEGORY'.ljust(cat_w)}  TITLE"
    lines.append(header)
    lines.append("-" * len(header))
    for r in rules:
        lines.append(
            f"{r.id.ljust(id_w)}  {r.severity.value.ljust(sev_w)}  "
            f"{r.category.ljust(cat_w)}  {r.title}"
        )
    return "\n".join(lines) + "\n"
