"""SkillTotal command-line interface — the only I/O shell around the core engine.

Commands:
    skilltotal scan <source> [--json|--sarif] [--output FILE]
                             [--fail-on LEVEL | --fail-on-high] [--fail-on-score N]
                             [--exclude GLOB ...] [--config FILE]
                             [--baseline FILE | --write-baseline FILE]
        <source>: a local directory, a project archive (.zip/.tar.gz/.tgz/.tar) or a single
        file, a git URL, or an npm:<name> / pypi:<name> package spec.
        Optional project config: .skilltotal.toml (fail_on, fail_on_score, exclude, ignore,
        baseline, and a per-rule [policy] table with block/warn/ignore actions). CLI flags
        override config. Inline `# skilltotal:ignore[ST-ID]` suppresses a finding on its line.
    skilltotal diff <old> <new> [--json] [--output FILE] [--fail-on-new LEVEL]
        compare two versions of a component: each side is any scannable source (as in
        `scan`) or a previously saved JSON report. Reports new/resolved findings,
        evidence-level changes, and capability changes.
    skilltotal inventory [--json] [--no-scan] [--project DIR]
        discover AI components installed on this machine (agent configs / MCP servers), then scan.
    skilltotal rules list [--json]

Exit codes:
    0  success
    1  usage / collection error
    2  a configured gate tripped (scan --fail-on* / diff --fail-on-new)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from skilltotal import __version__
from skilltotal.baseline import build_baseline, load_baseline
from skilltotal.collector import CollectionError
from skilltotal.config import Config, find_config, load_config
from skilltotal.diff import diff_reports, max_new_severity
from skilltotal.engine import analyze
from skilltotal.inventory import discover
from skilltotal.models import Severity
from skilltotal.report import (
    render_diff_json,
    render_diff_text,
    render_inventory_json,
    render_inventory_text,
    render_json,
    render_rules_json,
    render_rules_text,
    render_text,
)
from skilltotal.rules import get_rules
from skilltotal.sarif import render_sarif

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FAIL_ON_HIGH = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skilltotal",
        description="AI Component Security Platform — static analysis of AI components.",
    )
    parser.add_argument("--version", action="version", version=f"skilltotal {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan",
        help="Scan a component: a local path/archive/file, a git URL, or an npm:/pypi: package.",
    )
    scan.add_argument(
        "source",
        help=(
            "Local directory, project archive (.zip/.tar.gz/.tgz/.tar) or single file, "
            "git URL, or npm:<name> / pypi:<name>."
        ),
    )
    scan.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    scan.add_argument(
        "--sarif",
        action="store_true",
        help="Emit SARIF 2.1.0 to stdout (and to --output if given).",
    )
    scan.add_argument(
        "--output",
        metavar="FILE",
        help="Write the report to FILE (SARIF if --sarif, else JSON).",
    )
    scan.add_argument(
        "--baseline",
        metavar="FILE",
        help="Suppress findings whose fingerprints are listed in this baseline file.",
    )
    scan.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="Write a baseline file covering the current findings, then exit normally.",
    )
    scan.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with code 2 if any finding is high or critical (alias for --fail-on high).",
    )
    scan.add_argument(
        "--fail-on",
        metavar="LEVEL",
        choices=["low", "medium", "high", "critical"],
        help="Exit with code 2 if any finding is at or above LEVEL severity.",
    )
    scan.add_argument(
        "--fail-on-score",
        metavar="N",
        type=int,
        help="Exit with code 2 if the risk score is >= N (0-100).",
    )
    scan.add_argument(
        "--exclude",
        metavar="GLOB",
        action="append",
        default=[],
        help="Skip files matching GLOB (repeatable). Combined with config 'exclude'.",
    )
    scan.add_argument(
        "--config",
        metavar="FILE",
        help="Path to a .skilltotal.toml config (default: auto-discover in the current dir).",
    )

    diff = sub.add_parser(
        "diff",
        help=(
            "Compare two versions of a component (any two scan sources, or previously "
            "saved JSON reports)."
        ),
    )
    diff.add_argument(
        "old",
        help="Old side: any scannable source (as in `scan`) or a saved JSON report file.",
    )
    diff.add_argument(
        "new",
        help="New side: any scannable source (as in `scan`) or a saved JSON report file.",
    )
    diff.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    diff.add_argument(
        "--output",
        metavar="FILE",
        help="Write the diff report to FILE as JSON.",
    )
    diff.add_argument(
        "--fail-on-new",
        metavar="LEVEL",
        choices=["low", "medium", "high", "critical"],
        help=(
            "Exit with code 2 if the new version introduces a finding (or new evidence "
            "on an existing finding) at or above LEVEL severity."
        ),
    )
    diff.add_argument(
        "--exclude",
        metavar="GLOB",
        action="append",
        default=[],
        help="Skip files matching GLOB on both sides (repeatable).",
    )
    diff.add_argument(
        "--config",
        metavar="FILE",
        help="Path to a .skilltotal.toml config (default: auto-discover in the current dir).",
    )

    inv = sub.add_parser(
        "inventory",
        help="Discover AI components installed on this machine and scan them.",
    )
    inv.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    inv.add_argument(
        "--no-scan", action="store_true", help="Only list discovered components, do not scan."
    )
    inv.add_argument(
        "--project", metavar="DIR", help="Also look for project-local agent configs in DIR."
    )

    rules = sub.add_parser("rules", help="Inspect the detection rules.")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    rules_list = rules_sub.add_parser("list", help="List all detection rules.")
    rules_list.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "diff":
        return _cmd_diff(args)
    if args.command == "inventory":
        return _cmd_inventory(args)
    if args.command == "rules":
        return _cmd_rules(args)
    parser.error("unknown command")  # pragma: no cover
    return EXIT_ERROR


def _cmd_scan(args: argparse.Namespace) -> int:
    config = _load_config(args)

    baseline_path = args.baseline or config.baseline
    suppress: set[str] = set()
    if baseline_path:
        try:
            suppress = load_baseline(baseline_path)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read baseline {baseline_path}: {exc}", file=sys.stderr)
            return EXIT_ERROR

    exclude = [*config.exclude, *args.exclude]
    try:
        report = analyze(
            args.source, suppress=suppress, ignore_rules=config.ignored_rules(), exclude=exclude
        )
    except CollectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.write_baseline:
        doc = build_baseline(report.findings)
        Path(args.write_baseline).write_text(
            json.dumps(doc, indent=2), encoding="utf-8"
        )
        print(
            f"Baseline with {len(doc['suppressed'])} fingerprint(s) written to "
            f"{args.write_baseline}",
            file=sys.stderr,
        )

    # Choose the structured renderer once; reuse for stdout and --output.
    if args.sarif:
        structured = render_sarif(report)
    else:
        structured = render_json(report)

    if args.sarif or args.json:
        print(structured)
    else:
        print(render_text(report))

    if args.output:
        Path(args.output).write_text(structured, encoding="utf-8")
        print(f"Report written to {args.output}", file=sys.stderr)

    level = args.fail_on or ("high" if args.fail_on_high else None) or config.fail_on
    score = args.fail_on_score if args.fail_on_score is not None else config.fail_on_score
    if _fails_gate(report, level, score, config.policy):
        return EXIT_FAIL_ON_HIGH
    return EXIT_OK


def _cmd_diff(args: argparse.Namespace) -> int:
    config = _load_config(args)
    exclude = [*config.exclude, *args.exclude]

    try:
        old_report = _resolve_diff_side(args.old, config, exclude)
        new_report = _resolve_diff_side(args.new, config, exclude)
    except CollectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read report: {exc}", file=sys.stderr)
        return EXIT_ERROR

    diff = diff_reports(old_report, new_report)

    if args.json:
        print(render_diff_json(diff))
    else:
        print(render_diff_text(diff))

    if args.output:
        Path(args.output).write_text(render_diff_json(diff), encoding="utf-8")
        print(f"Diff report written to {args.output}", file=sys.stderr)

    if args.fail_on_new:
        worst = max_new_severity(diff)
        if worst is not None and worst.rank >= Severity[args.fail_on_new.upper()].rank:
            return EXIT_FAIL_ON_HIGH
    return EXIT_OK


def _resolve_diff_side(source: str, config: Config, exclude: list[str]) -> dict:
    """Resolve one diff side: a saved JSON report is loaded, anything else is scanned."""
    path = Path(source)
    if path.is_file() and path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and {"component", "risk_score", "findings"} <= data.keys():
            return data
        # A .json file that is not a saved report (e.g. a bare package.json) is scanned
        # like any other single-file source.
    report = analyze(source, ignore_rules=config.ignored_rules(), exclude=exclude)
    return report.to_dict()


def _cmd_inventory(args: argparse.Namespace) -> int:
    project = Path(args.project) if args.project else None
    components = discover(project=project)

    items: list[dict] = []
    for c in components:
        item = {
            "host": c.host, "name": c.name, "kind": c.kind,
            "source": c.source, "scannable": c.scannable, "note": c.note,
            "config": c.config,
        }
        if c.scannable and not args.no_scan and c.source is not None:
            try:
                report = analyze(c.source)
                item["verdict"] = report.verdict.get("level")
                item["risk_level"] = report.risk_level.value
                item["risk_score"] = report.risk_score
                item["has_malicious_indicators"] = report.verdict.get("has_malicious_indicators")
            except CollectionError as exc:
                item["error"] = str(exc)
            except Exception as exc:  # noqa: BLE001 - one bad item must not abort the sweep
                item["error"] = f"scan failed: {exc}"
        items.append(item)

    if args.json:
        print(render_inventory_json(items))
    else:
        print(render_inventory_text(items))
    return EXIT_OK


def _cmd_rules(args: argparse.Namespace) -> int:
    if args.rules_command == "list":
        rules = get_rules()
        if args.json:
            print(render_rules_json(rules))
        else:
            print(render_rules_text(rules))
        return EXIT_OK
    return EXIT_ERROR


def _load_config(args: argparse.Namespace) -> Config:
    """Load .skilltotal.toml (explicit --config or auto-discovered); empty config if none."""
    path = Path(args.config) if args.config else find_config()
    if path is None:
        return Config()
    try:
        return load_config(path)
    except OSError as exc:
        print(f"warning: cannot read config {path}: {exc}", file=sys.stderr)
        return Config()


def _fails_gate(
    report, level: str | None, score: int | None, policy: dict[str, str] | None = None
) -> bool:
    """True if the report trips the configured CI gate (severity level and/or risk score).

    Per-rule policy actions refine the severity gate: a `block` rule trips it whenever it
    fires (even with no `fail_on` configured); a `warn` rule is exempt from the severity
    threshold (explicit accept-but-show). The aggregate `fail_on_score` gate is unaffected —
    warn findings still count toward the risk score.
    """
    policy = policy or {}
    if any(policy.get(f.id) == "block" for f in report.findings):
        return True
    if level:
        threshold = Severity[level.upper()].rank
        if any(
            f.severity.rank >= threshold and policy.get(f.id) != "warn"
            for f in report.findings
        ):
            return True
    if score is not None and report.risk_score >= score:
        return True
    return False
