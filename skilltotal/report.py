"""Report rendering: JSON and human-readable text.

Rendering is kept separate from analysis so the same :class:`~skilltotal.models.Report`
can feed a CLI, a web response, or a SaaS API without change.
"""

from __future__ import annotations

import json
import re

from skilltotal.diff import DiffReport
from skilltotal.file_index import neutralize_hidden
from skilltotal.guard import GuardDecision
from skilltotal.models import Report, ThreatClass
from skilltotal.scanners.base import RuleSpec

_INDENT = "  "
# Control characters other than tab and newline. Paths and snippets come from the scanned
# package, so a text report printed to a terminal must not carry escape sequences that move the
# cursor, rewrite earlier lines (a BLOCK turned into an ALLOW) or set the clipboard.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# The text report shows a few locations per finding; --json carries every one.
_TEXT_EVIDENCE_SHOWN = 3
_CLASS_ORDER = {"malicious_indicator": 0, "risky_construct": 1, "exposure": 2, "capability": 3}
_CLASS_LABEL = {
    "malicious_indicator": " - malicious indicator",
    "capability": " - capability, not scored",
}


def _terminal_safe(text: str) -> str:
    """Show control characters as ``\\x1b`` instead of sending them to the terminal."""
    return _CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def one_line(text: str) -> str:
    """``text`` safe to print as (part of) one line: hidden and control characters, newlines and
    tabs included, shown as ``<U+XXXX>``. A file name comes from the scanned package and may hold
    a newline: printed raw, it forges a line of the report, or a workflow command in a GitHub
    Actions log."""
    return neutralize_hidden(text).replace("\n", "<U+000A>").replace("\t", "<U+0009>")


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def render_text(report: Report) -> str:
    c = report.component
    lines: list[str] = []
    lines.append("SkillTotal Security Report")
    lines.append("=" * 26)
    version = f" {c.version}" if c.version else ""
    lines.append(f"Component : {one_line(c.name)}{one_line(version)} ({c.type})")
    lines.append(f"Source    : {one_line(c.source)}")
    config = report.metadata.get("config_applied")
    if config:
        # A config committed to the scanned repository can relax the gate: never silently.
        gates = "".join(
            f", {key} = {config[key]}" for key in ("fail_on", "fail_on_score") if key in config)
        lines.append(
            f"Config    : {one_line(str(config.get('path', '')))} ({config.get('exclude', 0)} "
            f"exclude(s), {config.get('ignore', 0)} ignored rule(s), {config.get('policy', 0)} "
            f"policy override(s){gates})"
        )
    # The verdict is the top-line answer and comes first: a malicious indicator is reported here,
    # not by the score, so a dropper whose score reads "medium" must not look medium.
    verdict = report.verdict or {}
    if verdict.get("headline"):
        # Under "Malicious indicators found", only what is one: a risky construct listed there
        # reads as malice the scan did not find.
        malicious = {f.title for f in report.findings
                     if f.threat_class is ThreatClass.MALICIOUS_INDICATOR}
        reasons = [r for r in verdict.get("reasons") or [] if r in malicious]
        lines.append(
            f"Verdict   : {str(verdict.get('level', '')).upper()} - {verdict['headline']}"
            + (f" ({'; '.join(reasons)})" if verdict.get("has_malicious_indicators") and reasons
               else "")
        )
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

    # Findings: what drives the verdict first. A capability is what the code can do, and it is
    # labeled as such, so "[HIGH]" next to a 0/100 score does not read as a contradiction.
    lines.append(f"Findings ({len(report.findings)}):")
    if not report.findings:
        lines.append(f"{_INDENT}(none)")
        lines.append("")
    for f in sorted(report.findings, key=lambda f: _CLASS_ORDER.get(f.threat_class.value, 4)):
        label = _CLASS_LABEL.get(f.threat_class.value, "")
        lines.append(f"{_INDENT}[{f.severity.value.upper()}{label}] {f.id}  {f.title}")
        lines.append(f"{_INDENT*2}{f.description}")
        lines.append(f"{_INDENT*2}Recommendation: {f.recommendation}")
        lines.append(f"{_INDENT*2}Evidence:")
        for e in f.evidence[:_TEXT_EVIDENCE_SHOWN]:
            lines_span = (f"{e.line_start}" if e.line_end == e.line_start
                          else f"{e.line_start}-{e.line_end}")
            lines.append(f"{_INDENT*3}- {one_line(e.file)}:{lines_span}")
            for snippet_line in e.snippet.splitlines() or [e.snippet]:
                lines.append(f"{_INDENT*4}{snippet_line}")
        hidden = len(f.evidence) - _TEXT_EVIDENCE_SHOWN
        if hidden > 0:
            lines.append(f"{_INDENT*3}... and {hidden} more (all of them in --json)")
        lines.append("")
    suppressed = report.metadata.get("suppressed_count") or 0
    if suppressed:
        lines.append(f"{suppressed} finding occurrence(s) suppressed by a baseline or an inline "
                     "skilltotal:ignore marker.")
    if report.findings:
        lines.append("To accept a false positive: put `# skilltotal:ignore[RULE-ID]` on its line, "
                     "or record the current findings with --write-baseline FILE.")
    if suppressed or report.findings:
        lines.append("")

    # Needs review
    if report.needs_review:
        lines.append(f"Needs review ({len(report.needs_review)}):")
        for n in report.needs_review:
            where = f" ({one_line(n.file)})" if n.file else ""
            lines.append(f"{_INDENT}- [{n.category}] {one_line(n.title)}{where}")
            lines.append(f"{_INDENT*2}{one_line(n.reason)}")
        lines.append("")

    return _terminal_safe("\n".join(lines).rstrip() + "\n")


def render_diff_json(diff: DiffReport) -> str:
    return json.dumps(diff.to_dict(), indent=2, ensure_ascii=False)


def render_diff_text(diff: DiffReport) -> str:
    lines: list[str] = []
    lines.append("SkillTotal Diff Report")
    lines.append("=" * 22)
    lines.append(f"Old : {_diff_side(diff.old)}")
    lines.append(f"New : {_diff_side(diff.new)}")
    lines.append("")
    lines.append(diff.summary)
    lines.append("")

    if diff.ruleset_mismatch:
        lines.append(
            f"NOTE: reports were produced by different rulesets "
            f"(old {diff.old.get('ruleset_version')}, new {diff.new.get('ruleset_version')}); "
            "some finding churn may come from detection changes, not component changes."
        )
        lines.append("")

    lines.append(f"New findings ({len(diff.new_findings)}):")
    if not diff.new_findings:
        lines.append(f"{_INDENT}(none)")
    for f in diff.new_findings:
        lines.append(f"{_INDENT}[{f['severity'].upper()}{_diff_label(f)}] {f['id']}  {f['title']}")
        for e in f.get("evidence", []):
            lines.append(f"{_INDENT*2}+ {one_line(e['file'])}:{e['line_start']}-{e['line_end']}")
            for snippet_line in e.get("snippet", "").splitlines():
                lines.append(f"{_INDENT*3}{snippet_line}")
    lines.append("")

    if diff.resolved_findings:
        lines.append(f"Resolved findings ({len(diff.resolved_findings)}):")
        for f in diff.resolved_findings:
            lines.append(
                f"{_INDENT}[{f['severity'].upper()}{_diff_label(f)}] {f['id']}  {f['title']}")
        lines.append("")

    if diff.changed_findings:
        lines.append(f"Changed findings ({len(diff.changed_findings)}):")
        for c in diff.changed_findings:
            lines.append(
                f"{_INDENT}[{c['severity'].upper()}{_diff_label(c)}] {c['id']}  {c['title']}  "
                f"(+{len(c['added_evidence'])} / -{len(c['removed_evidence'])} evidence)"
            )
            for e in c["added_evidence"]:
                lines.append(
                    f"{_INDENT*2}+ {one_line(e['file'])}:{e['line_start']}-{e['line_end']}")
            for e in c["removed_evidence"]:
                lines.append(
                    f"{_INDENT*2}- {one_line(e['file'])}:{e['line_start']}-{e['line_end']}")
        lines.append("")

    if diff.capabilities_added or diff.capabilities_removed:
        lines.append("Capability changes:")
        for cap in diff.capabilities_added:
            lines.append(f"{_INDENT}+ {cap}")
        for cap in diff.capabilities_removed:
            lines.append(f"{_INDENT}- {cap}")
        lines.append("")

    return _terminal_safe("\n".join(lines).rstrip() + "\n")


def _diff_label(finding: dict) -> str:
    """The threat-class label a scan report shows, so a capability in a diff does not read as
    new risk (``--fail-on-new`` never counts one)."""
    return _CLASS_LABEL.get(str(finding.get("threat_class", "")), "")


def _diff_side(side: dict) -> str:
    c = side.get("component", {})
    version = f" {c['version']}" if c.get("version") else ""
    return (
        f"{c.get('name', '?')}{version} ({c.get('type', '?')})  "
        f"risk {side.get('risk_score', 0)}/100 {str(side.get('risk_level', '')).upper()}"
    )


def render_guard_json(source: str, report: dict, decision: GuardDecision) -> str:
    return json.dumps(
        {
            "source": source,
            **decision.to_dict(),
            "risk_score": report.get("risk_score", 0),
            "risk_level": report.get("risk_level", ""),
            "verdict": report.get("verdict", {}),
            "capabilities": sorted(report.get("capabilities", {})),
        },
        indent=2,
        ensure_ascii=False,
    )


def render_guard_text(source: str, report: dict, decision: GuardDecision) -> str:
    c = report.get("component", {})
    verdict = report.get("verdict") or {}
    version = f" {c['version']}" if c.get("version") else ""
    lines = [
        "SkillTotal Guard",
        "=" * 16,
        f"Source    : {source}",
        f"Component : {c.get('name', '?')}{version} ({c.get('type', '?')})",
        f"Risk      : {report.get('risk_score', 0)}/100 "
        f"{str(report.get('risk_level', '')).upper()}",
    ]
    if verdict.get("headline"):
        lines.append(f"Verdict   : {verdict['headline']}")
    caps = sorted(report.get("capabilities", {}))
    if caps:
        lines.append(f"Capabilities: {', '.join(caps)}")
    lines.append("")
    lines.append(f"Decision  : {'ALLOW' if decision.allow else 'BLOCK'}")
    for reason in decision.reasons:
        lines.append(f"{_INDENT}- {reason}")
    if not decision.allow:
        lines.append("")
        lines.append(f"Inspect the full report: skilltotal scan {source}")
    return _terminal_safe("\n".join(lines) + "\n")


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
    return _terminal_safe("\n".join(lines) + "\n")


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
