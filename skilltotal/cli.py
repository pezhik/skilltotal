"""SkillTotal command-line interface — the only I/O shell around the core engine.

Commands:
    skilltotal scan <path-or-url> [--json] [--output FILE] [--fail-on-high]
    skilltotal rules list [--json]

Exit codes:
    0  success
    1  usage / collection error
    2  --fail-on-high set and a finding of severity >= high was produced
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from skilltotal import __version__
from skilltotal.baseline import build_baseline, load_baseline
from skilltotal.collector import CollectionError
from skilltotal.engine import analyze
from skilltotal.models import Severity
from skilltotal.report import (
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

    scan = sub.add_parser("scan", help="Scan a component (local path or git URL).")
    scan.add_argument("source", help="Local directory path or git repository URL.")
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
        help="Exit with code 2 if any finding is high or critical.",
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
    if args.command == "rules":
        return _cmd_rules(args)
    parser.error("unknown command")  # pragma: no cover
    return EXIT_ERROR


def _cmd_scan(args: argparse.Namespace) -> int:
    suppress: set[str] = set()
    if args.baseline:
        try:
            suppress = load_baseline(args.baseline)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read baseline {args.baseline}: {exc}", file=sys.stderr)
            return EXIT_ERROR

    try:
        report = analyze(args.source, suppress=suppress)
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

    if args.fail_on_high and _has_high(report):
        return EXIT_FAIL_ON_HIGH
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


def _has_high(report) -> bool:
    threshold = Severity.HIGH.rank
    return any(f.severity.rank >= threshold for f in report.findings)
