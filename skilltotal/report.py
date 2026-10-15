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
from skilltotal.models import Report, ThreatClass, finding_counts
from skilltotal.scanners.base import RuleSpec

_INDENT = "  "
# Control characters other than tab and newline. Paths and snippets come from the scanned
# package, so a text report printed to a terminal must not carry escape sequences that move the
# cursor, rewrite earlier lines (a BLOCK turned into an ALLOW) or set the clipboard.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# Bidirectional embeddings, overrides and isolates: they make a line display in another order
# than it reads (`ALLOW` drawn over a `BLOCK`).
# Built from numbers, so this source file holds no bidi characters itself.
_BIDI_CONTROLS = re.compile(f"[{chr(0x202A)}-{chr(0x202E)}{chr(0x2066)}-{chr(0x2069)}]")
_WORKFLOW_COMMAND_START = re.compile(r"(?m)^([ \t]*)::")
# The text report shows a few locations per finding; --json carries every one.
_TEXT_EVIDENCE_SHOWN = 3
_CLASS_ORDER = {"malicious_indicator": 0, "risky_construct": 1, "exposure": 2, "capability": 3}
_CLASS_LABEL = {
    "malicious_indicator": " - malicious indicator",
    "capability": " - capability, not scored",
}


def _terminal_safe(text: str) -> str:
    """Show control characters as ``\\x1b`` instead of sending them to the terminal, and the
    bidirectional controls (which reorder what a line shows) as ``<U+202E>``."""
    text = _CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", text)
    text = _BIDI_CONTROLS.sub(lambda m: f"<U+{ord(m.group()):04X}>", text)
    # A GitHub runner reads `::command::` at the start of a line, leading blanks skipped, and
    # `##[command]` anywhere in one: a snippet printed by `skilltotal scan` in a CI step must not
    # set an output, add a path or stop the log. Shown with a visible break instead.
    text = _WORKFLOW_COMMAND_START.sub(r"\1:<U+200B>:", text)
    return text.replace("##[", "#<U+200B>#[")


def one_line(text: str) -> str:
    """``text`` safe to print as (part of) one line: hidden and control characters, newlines and
    tabs included, shown as ``<U+XXXX>``. A file name comes from the scanned package and may hold
    a newline: printed raw, it forges a line of the report, or a workflow command in a GitHub
    Actions log."""
    return neutralize_hidden(text).replace("\n", "<U+000A>").replace("\t", "<U+0009>")


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def render_text(report: Report, *, markers_apply: bool = True) -> str:
    """The full text report. ``markers_apply`` says whether inline ``skilltotal:ignore`` markers
    are honored for this source (only a local folder): the hint on how to accept a false positive
    must not point a person at a marker that would do nothing."""
    lines = _header_lines(report)

    # Capabilities
    if report.capabilities:
        lines.append("Capabilities:")
        for cap, evs in sorted(report.capabilities.items(), key=lambda kv: kv[0].value):
            lines.append(f"{_INDENT}- {cap.value} ({len(evs)} evidence)")
        lines.append("")

    # Findings: what drives the verdict first. A capability is what the code can do, and it is
    # labeled as such, so "[HIGH]" next to a 0/100 score does not read as a contradiction.
    risk, capability = finding_counts(report.findings)
    counts = f"{risk} risk, {capability} capability, not scored" if capability else str(risk)
    lines.append(f"Findings ({counts}):")
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
    # The baseline's share is on the Baseline line above; what is left here is the markers'.
    suppressed = ((report.metadata.get("suppressed_count") or 0)
                  - (report.metadata.get("baseline_suppressed_count") or 0))
    if suppressed > 0:
        lines.append(f"{suppressed} finding occurrence(s) suppressed by an inline "
                     "skilltotal:ignore marker.")
    if report.findings:
        if markers_apply:
            lines.append("To accept a false positive: put `# skilltotal:ignore[RULE-ID]` on its "
                         "line, or record the current findings with --write-baseline FILE.")
        else:
            # A marker in a fetched package or repository is never honored: it is the author's.
            lines.append("To accept a false positive: record the current findings with "
                         "--write-baseline FILE and scan with --baseline FILE, or set the rule "
                         "to \"warn\" or \"ignore\" under [policy] in .skilltotal.toml "
                         "(skilltotal:ignore markers apply only to a local folder).")
    if suppressed > 0 or report.findings:
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


def render_summary_text(report: Report, output: str) -> str:
    """The console summary of a scan whose full report went to the file ``output``: the header
    and verdict, the counts, and where the rest is."""
    lines = _header_lines(report)
    lines.append(f"Full report: {one_line(output)}")
    return _terminal_safe("\n".join(lines).rstrip() + "\n")


def _header_lines(report: Report) -> list[str]:
    """Title, component, config, verdict, baseline, risk and the summary line."""
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
        if config.get("baseline"):
            gates += f", baseline = {one_line(str(config['baseline']))}"
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
    hidden = report.metadata.get("baseline_suppressed_count")
    if hidden is not None:
        # Next to the verdict: a clean verdict after a baseline is clean of what it did not hide.
        baseline = report.metadata.get("baseline")
        by = f"baseline {one_line(str(baseline))}" if baseline else "the baseline"
        lines.append(f"Baseline  : {hidden} finding occurrence(s) suppressed by {by}")
    lines.append(f"Risk      : {report.risk_level.value.upper()}  (score {report.risk_score}/100)")
    lines.append("")
    lines.append(report.summary)
    lines.append("")
    return lines


def render_diff_json(diff: DiffReport) -> str:
    return json.dumps(diff.to_dict(), indent=2, ensure_ascii=False)


def render_diff_text(diff: DiffReport) -> str:
    lines: list[str] = []
    lines.append("SkillTotal Diff Report")
    lines.append("=" * 22)
    lines.append(f"Old : {_diff_side(diff.old)}")
    lines.append(f"New : {_diff_side(diff.new)}")
    lines.append("")
    lines.append(one_line(str(diff.summary)))
    lines.append("")

    if diff.ruleset_mismatch:
        lines.append(
            f"NOTE: reports were produced by different rulesets "
            f"(old {one_line(str(diff.old.get('ruleset_version')))}, "
            f"new {one_line(str(diff.new.get('ruleset_version')))}); "
            "some finding churn may come from detection changes, not component changes."
        )
        lines.append("")

    lines.append(f"New findings ({len(diff.new_findings)}):")
    if not diff.new_findings:
        lines.append(f"{_INDENT}(none)")
    for f in diff.new_findings:
        lines.append(f"{_INDENT}{_diff_heading(f)}")
        for e in f.get("evidence", []):
            lines.append(f"{_INDENT*2}+ {_diff_where(e)}")
            for snippet_line in str(e.get("snippet", "")).splitlines():
                lines.append(f"{_INDENT*3}{one_line(snippet_line)}")
    lines.append("")

    if diff.resolved_findings:
        lines.append(f"Resolved findings ({len(diff.resolved_findings)}):")
        for f in diff.resolved_findings:
            lines.append(f"{_INDENT}{_diff_heading(f)}")
        lines.append("")

    if diff.changed_findings:
        lines.append(f"Changed findings ({len(diff.changed_findings)}):")
        for c in diff.changed_findings:
            lines.append(
                f"{_INDENT}{_diff_heading(c)}  "
                f"(+{len(c['added_evidence'])} / -{len(c['removed_evidence'])} evidence)"
            )
            for e in c["added_evidence"]:
                lines.append(f"{_INDENT*2}+ {_diff_where(e)}")
            for e in c["removed_evidence"]:
                lines.append(f"{_INDENT*2}- {_diff_where(e)}")
        lines.append("")

    if diff.capabilities_added or diff.capabilities_removed:
        lines.append("Capability changes:")
        for cap in diff.capabilities_added:
            lines.append(f"{_INDENT}+ {one_line(str(cap))}")
        for cap in diff.capabilities_removed:
            lines.append(f"{_INDENT}- {one_line(str(cap))}")
        lines.append("")

    return _terminal_safe("\n".join(lines).rstrip() + "\n")


def _diff_label(finding: dict) -> str:
    """The threat-class label a scan report shows, so a capability in a diff does not read as
    new risk (``--fail-on-new`` never counts one)."""
    return _CLASS_LABEL.get(str(finding.get("threat_class", "")), "")


# Every field of a diff comes from a report, and a report can be a saved file someone else
# wrote, or describe a package whose manifest put a newline in its name: each is printed as one
# line, or a forged line (a GitHub Actions `::error` command) lands at column zero of a CI log
# (security review, 2026-10-15).
def _diff_heading(f: dict) -> str:
    return (f"[{one_line(str(f.get('severity', ''))).upper()}{_diff_label(f)}] "
            f"{one_line(str(f.get('id', '')))}  {one_line(str(f.get('title', '')))}")


def _diff_where(e: dict) -> str:
    return (f"{one_line(str(e.get('file', '')))}:{one_line(str(e.get('line_start', '')))}"
            f"-{one_line(str(e.get('line_end', '')))}")


def _diff_side(side: dict) -> str:
    c = side.get("component", {})
    c = c if isinstance(c, dict) else {}
    version = f" {one_line(str(c['version']))}" if c.get("version") else ""
    return (
        f"{one_line(str(c.get('name', '?')))}{version} ({one_line(str(c.get('type', '?')))})  "
        f"risk {one_line(str(side.get('risk_score', 0)))}/100 "
        f"{one_line(str(side.get('risk_level', ''))).upper()}"
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
        verdict = it.get("verdict") or ("-" if it.get("scannable") else (
            "this scanner" if it.get("this_tool") else "remote" if it.get("remote")
            else "risky" if it.get("risky") else "not scanned"))
        risk = it.get("risk_level") or ""
        where = it.get("source") or it.get("note", "")
        # Names, paths and notes come from config files anyone can write (a repository's
        # `.mcp.json`): a newline in one would forge a row or a workflow command.
        rows.append(tuple(one_line(str(v)) for v in
                          (it["host"], it["name"], it["kind"], where, verdict, risk)))
    headers = ("HOST", "NAME", "KIND", "SOURCE", "VERDICT", "RISK")
    widths = [max(len(headers[i]), *(len(str(r[i])) for r in rows)) for i in range(len(headers))]
    lines = [f"SkillTotal inventory ({len(items)} component(s))", ""]
    lines.append("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    lines.append("-" * (sum(widths) + 2 * (len(headers) - 1)))
    for r in rows:
        lines.append("  ".join(str(r[i]).ljust(widths[i]) for i in range(len(headers))))
    # Whatever `guard --installed` blocks needs attention here too: a typosquatted name blocks the
    # guard with a low score, and the two commands must not disagree about one component.
    flagged = [it for it in items if it.get("verdict") in ("malicious", "critical", "high")
               or it.get("risky") or it.get("guard") == "block"]
    if flagged:
        lines.append("")
        lines.append(f"{len(flagged)} component(s) need attention (high risk, malicious, blocked "
                     f"by `skilltotal guard`, or a launch command that runs a downloaded script).")
    for it in items:
        name = one_line(str(it["name"]))
        if it.get("risky") and it.get("note"):
            lines.append(f"  {name}: {one_line(str(it['note']))}")
        if it.get("guard") == "block":
            lines.extend(f"  {name}: {one_line(str(reason))}"
                         for reason in it.get("guard_reasons") or [])
        lines.extend(f"  {name}: inline secret in its config: {one_line(str(secret))}"
                     for secret in it.get("secrets") or [])
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
