"""SkillTotal command-line interface — the only I/O shell around the core engine.

Commands:
    skilltotal scan <source> [--json|--sarif] [--output FILE]
                             [--fail-on LEVEL | --fail-on-high] [--fail-on-score N]
                             [--fail-on-unanalyzed]
                             [--exclude GLOB ...] [--config FILE]
                             [--baseline FILE | --write-baseline FILE]
        <source>: a local directory, a project archive (.zip/.tar.gz/.tgz/.tar) or a single
        file, a git URL, or an npm:<name> / pypi:<name> package spec.
        Optional project config: .skilltotal.toml (fail_on, fail_on_score, fail_on_unanalyzed,
        exclude, ignore, baseline, and a per-rule [policy] table with block/warn/ignore
        actions). CLI flags override config. Inline `# skilltotal:ignore[ST-ID]` suppresses a
        finding on its line when the source is a local directory (never in a fetched package
        or repository).
    skilltotal diff <old> <new> [--json] [--output FILE] [--fail-on-new LEVEL]
        compare two versions of a component: each side is any scannable source (as in
        `scan`) or a previously saved JSON report. Reports new/resolved findings,
        evidence-level changes, and capability changes.
    skilltotal guard <source> [--block-on malicious|high|medium] [--json]
    skilltotal guard --installed [--project DIR] [--block-on ...] [--json]
        pre-install allow/block decision (exit 2 on block): malicious indicators always
        block; scored risk at/above the block level blocks; capabilities alone never do.
    skilltotal inventory [--json] [--no-scan] [--project DIR]
        discover AI components installed on this machine (agent configs / MCP servers), then scan.
    skilltotal rules list [--json]
    skilltotal mcp
        run SkillTotal as an MCP server on stdio, so agents can scan components before
        installing them (register: {"command": "skilltotal", "args": ["mcp"]}).
    skilltotal hook claude-code
        Claude Code PreToolUse hook (used by the SkillTotal plugin): reads the hook event on
        stdin, scans any package the Bash command would install, and prints the decision.
        Always exits 0; a failed scan asks the person and never blocks the install, except in
        CI strict mode (CI or SKILLTOTAL_STRICT set), where what would be asked is denied. A
        scan that outlasts the wait goes on in the background and keeps its verdict for the
        next run of the command.

Exit codes:
    0  success
    1  usage / collection error
    2  a configured gate tripped (scan --fail-on* / diff --fail-on-new), or guard blocked the
       component
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from skilltotal import __version__
from skilltotal.guard import BLOCK_LEVELS, DEFAULT_BLOCK_LEVEL, evaluate

# The engine, the collector and the scanners are imported inside the commands that use them:
# the Claude Code hook starts this CLI before every install-like Bash command the agent runs, and
# loading the whole engine for a command that turns out to install nothing costs most of a second.
if TYPE_CHECKING:
    from skilltotal.config import Config
    from skilltotal.hook_scan import Marker, Pending, ScanContinues

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FAIL_ON_HIGH = 2


class _Parser(argparse.ArgumentParser):
    """argparse, except that a usage error exits 1 rather than 2: exit code 2 means a gate tripped,
    and a CI job must be able to tell a mistyped flag from a component that failed its check."""

    def error(self, message: str):  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
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
        help=(
            "Exit with code 2 on a high or critical finding (alias for --fail-on high). "
            "Malicious indicators trip it at any severity; capabilities never do."
        ),
    )
    scan.add_argument(
        "--fail-on",
        metavar="LEVEL",
        choices=["low", "medium", "high", "critical"],
        help=(
            "Exit with code 2 on a finding at or above LEVEL severity. Malicious indicators "
            "trip it at any severity; capabilities (what a component can do) never do."
        ),
    )
    scan.add_argument(
        "--fail-on-score",
        metavar="N",
        type=int,
        help="Exit with code 2 if the risk score is >= N (0-100).",
    )
    scan.add_argument(
        "--fail-on-unanalyzed",
        action="store_true",
        help="Exit with code 2 if any file, or any part of one, was not analyzed.",
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
    scan.add_argument(
        "--provenance",
        action="store_true",
        help=(
            "Also fetch registry metadata for npm:/pypi: sources and report provenance "
            "signals (recently published, deprecated/yanked, no recent releases, no "
            "repository link) as needs_review entries. Opt-in; never affects the score."
        ),
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

    guard = sub.add_parser(
        "guard",
        help=(
            "Pre-install check: allow/block decision for a component "
            "(chain it before installing, e.g. `skilltotal guard npm:x && ...`)."
        ),
    )
    guard.add_argument(
        "source",
        nargs="?",
        help="Component to check (same sources as `scan`). Omit with --installed.",
    )
    guard.add_argument(
        "--installed",
        action="store_true",
        help="Check every AI component installed on this machine instead of one source.",
    )
    guard.add_argument(
        "--project",
        metavar="DIR",
        help="With --installed: also check project-local agent configs in DIR.",
    )
    guard.add_argument(
        "--block-on",
        metavar="LEVEL",
        choices=list(BLOCK_LEVELS),
        default=DEFAULT_BLOCK_LEVEL,
        help=(
            "What blocks (exit 2): 'malicious' = only malicious indicators; "
            "'high' (default) = also risk level high/critical; 'medium' = also medium. "
            "Capabilities alone never block."
        ),
    )
    guard.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    inv = sub.add_parser(
        "inventory",
        help="Discover AI components installed on this machine and scan them.",
    )
    inv.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    inv.add_argument(
        "--sbom",
        action="store_true",
        help=(
            "Emit the inventory as a CycloneDX 1.6 AI-BOM (JSON) with the scan verdict "
            "attached as component properties."
        ),
    )
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

    sub.add_parser(
        "mcp",
        help=(
            "Run SkillTotal as an MCP server on stdio (tools: scan_component, "
            "diff_components, list_rules)."
        ),
    )

    hook = sub.add_parser(
        "hook",
        help="Agent hook entry points (used by the SkillTotal Claude Code plugin).",
    )
    hook.add_argument("agent", choices=["claude-code"], help="Which agent's hook format.")
    # The two processes a check runs in, started by the hook itself (see skilltotal.hook_scan).
    hook.add_argument("--supervise", metavar="DIR", help=argparse.SUPPRESS)
    hook.add_argument("--scan-into", metavar="DIR", help=argparse.SUPPRESS)

    return parser


def _no_lookup_in_current_directory(environ=os.environ, os_name: str = os.name) -> None:
    """Windows runs a bare program name from the current directory before PATH, so a scan run
    inside a cloned repository would start a ``git.exe`` committed to it. This variable turns that
    lookup off for this process and everything it starts."""
    if os_name == "nt":
        environ["NoDefaultCurrentDirectoryInExePath"] = "1"


def main(argv: list[str] | None = None) -> int:
    _no_lookup_in_current_directory()  # before anything can start a program
    # Redirected output on Windows is written in the legacy code page, which cannot encode much of
    # what a scanned package may contain: a `✓` in one snippet crashed `scan --json > r.json` and
    # left the file empty. Reports go out as UTF-8 and never fail on their own content.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):  # absent on injected test streams
            if stream.isatty():
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "diff":
        return _cmd_diff(args)
    if args.command == "guard":
        return _cmd_guard(args)
    if args.command == "inventory":
        return _cmd_inventory(args)
    if args.command == "rules":
        return _cmd_rules(args)
    if args.command == "mcp":
        return _cmd_mcp()
    if args.command == "hook":
        return _cmd_hook(args)
    parser.error("unknown command")  # pragma: no cover
    return EXIT_ERROR


class _ProgressLine:
    """One line on a terminal that says what a long scan is doing and for how long, rewritten in
    place and erased at the end. A clock thread keeps the seconds moving while one step runs."""

    def __init__(self, stream) -> None:
        import threading

        self._stream = stream
        self._started = time.monotonic()
        self._message = ""
        self._width = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._clock = threading.Thread(target=self._tick, daemon=True)
        self._clock.start()

    def __call__(self, message: str) -> None:
        with self._lock:
            self._message = message
            self._draw()

    def _tick(self) -> None:
        while not self._stop.wait(1.0):
            with self._lock:
                self._draw()

    def _draw(self) -> None:
        if not self._message:
            return
        line = f"{self._message}... {time.monotonic() - self._started:.0f}s"
        self._stream.write("\r" + line.ljust(self._width))
        self._stream.flush()
        self._width = len(line)

    def close(self) -> None:
        self._stop.set()
        self._clock.join(timeout=2)
        with self._lock:
            if self._width:
                self._stream.write("\r" + " " * self._width + "\r")
                self._stream.flush()
            self._width = 0


def _cmd_scan(args: argparse.Namespace) -> int:
    from skilltotal.baseline import build_baseline, load_baseline
    from skilltotal.collector import CollectionError, classify_source
    from skilltotal.engine import analyze
    from skilltotal.report import render_json, render_text
    from skilltotal.sarif import render_sarif

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
    # A large package takes minutes (thousands of files): on a terminal, say what is happening so
    # the wait does not read as a hang. Never in a pipe or a CI log.
    progress = _ProgressLine(sys.stderr) if sys.stderr.isatty() else None
    try:
        if progress is not None:
            progress("Fetching")
        report = analyze(
            args.source, suppress=suppress, ignore_rules=config.ignored_rules(), exclude=exclude,
            # A `skilltotal:ignore` marker is the code owner's decision. Only a local directory
            # (a checkout, as in CI) is the person's own code; a fetched package or repository
            # must not be able to silence its own findings.
            inline_ignores=(classify_source(args.source) == "local"
                            and Path(args.source).expanduser().is_dir()),
            progress=progress,
        )
    except CollectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        if progress is not None:
            progress.close()

    if args.provenance:
        # Provenance is deliberately a CLI-layer add-on: the engine stays component-only,
        # and registry metadata lands in needs_review, which never affects the score.
        from skilltotal.provenance import ProvenanceError, collect_provenance

        try:
            signals = collect_provenance(args.source)
        except ProvenanceError as exc:
            print(f"warning: {exc}", file=sys.stderr)
        else:
            report.needs_review.extend(signals)
            report.metadata["provenance_checked"] = True
            if not signals and not args.source.strip().lower().startswith(("npm:", "pypi:")):
                print(
                    "warning: --provenance only applies to npm:/pypi: sources",
                    file=sys.stderr,
                )

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

    # The file first: whatever happens to the console, the report the caller asked for exists.
    if args.output:
        Path(args.output).write_text(structured, encoding="utf-8")
        print(f"Report written to {args.output}", file=sys.stderr)

    if args.sarif or args.json:
        print(structured)
    else:
        print(render_text(report))

    level = args.fail_on or ("high" if args.fail_on_high else None) or config.fail_on
    score = args.fail_on_score if args.fail_on_score is not None else config.fail_on_score
    gaps = _unanalyzed(report) if args.fail_on_unanalyzed or config.fail_on_unanalyzed else []
    if gaps:
        # With --json or --sarif the report is all stdout carries: say in the log why it failed.
        print(f"Not everything was analyzed: {'; '.join(gaps)}. See needs_review in the report.",
              file=sys.stderr)
    if gaps or _fails_gate(report, level, score, config.policy):
        return EXIT_FAIL_ON_HIGH
    return EXIT_OK


def _unanalyzed(report) -> list[str]:
    """The titles of the needs_review notes that say a file, or a part of one, was not analyzed."""
    from skilltotal.models import UNANALYZED_TITLES

    return list(dict.fromkeys(n.title for n in report.needs_review if n.title in UNANALYZED_TITLES))


def _cmd_diff(args: argparse.Namespace) -> int:
    from skilltotal.collector import CollectionError
    from skilltotal.diff import diff_reports, max_new_severity
    from skilltotal.models import Severity
    from skilltotal.report import render_diff_json, render_diff_text

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

    if args.output:
        Path(args.output).write_text(render_diff_json(diff), encoding="utf-8")
        print(f"Diff report written to {args.output}", file=sys.stderr)

    if args.json:
        print(render_diff_json(diff))
    else:
        print(render_diff_text(diff))

    if args.fail_on_new:
        worst = max_new_severity(diff)
        if worst is not None and worst.rank >= Severity[args.fail_on_new.upper()].rank:
            return EXIT_FAIL_ON_HIGH
    return EXIT_OK


def _resolve_diff_side(source: str, config: Config, exclude: list[str]) -> dict:
    """Resolve one diff side: a saved JSON report is loaded, anything else is scanned."""
    from skilltotal.engine import analyze

    path = Path(source)
    if path.is_file() and path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and {"component", "risk_score", "findings"} <= data.keys():
            return data
        # A .json file that is not a saved report (e.g. a bare package.json) is scanned
        # like any other single-file source.
    report = analyze(source, ignore_rules=config.ignored_rules(), exclude=exclude)
    return report.to_dict()


def _cmd_guard(args: argparse.Namespace) -> int:
    from skilltotal.collector import CollectionError
    from skilltotal.engine import analyze
    from skilltotal.report import render_guard_json, render_guard_text

    if args.installed == bool(args.source):
        print("error: pass a source to check, or --installed (not both)", file=sys.stderr)
        return EXIT_ERROR
    if args.installed:
        return _guard_installed(args)

    try:
        report = analyze(args.source).to_dict()
    except CollectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    decision = evaluate(report, args.block_on)
    if args.json:
        print(render_guard_json(args.source, report, decision))
    else:
        print(render_guard_text(args.source, report, decision))
    return EXIT_OK if decision.allow else EXIT_FAIL_ON_HIGH


def _guard_installed(args: argparse.Namespace) -> int:
    """Guard every installed AI component; block if any of them blocks."""
    from skilltotal.engine import analyze
    from skilltotal.inventory import discover
    from skilltotal.report import _terminal_safe, render_inventory_json

    components = discover(project=Path(args.project) if args.project else None)
    items: list[dict] = []
    blocked: list[str] = []
    for c in components:
        item: dict = {"host": c.host, "name": c.name, "kind": c.kind, "source": c.source}
        if not (c.scannable and c.source):
            item["decision"] = "not scanned"
            item["note"] = c.note
            items.append(item)
            continue
        try:
            report = analyze(c.source).to_dict()
        except Exception as exc:  # noqa: BLE001 - one bad item must not abort the sweep
            item["decision"] = "error"
            item["note"] = str(exc)
            items.append(item)
            continue
        decision = evaluate(report, args.block_on)
        item["decision"] = "allow" if decision.allow else "block"
        item["risk_level"] = report.get("risk_level", "")
        item["reasons"] = decision.reasons
        if not decision.allow:
            blocked.append(c.name)
        items.append(item)

    if args.json:
        print(render_inventory_json(items))
    else:
        lines: list[str] = []
        for it in items:
            marker = {"allow": "ok", "block": "BLOCK"}.get(it["decision"], it["decision"])
            risk = f"  risk={it['risk_level']}" if it.get("risk_level") else ""
            lines.append(f"[{marker}] {it['name']} ({it['host']}, {it['kind']}){risk}")
            lines.extend(f"      - {reason}" for reason in it.get("reasons", []))
        lines.append("")
        if blocked:
            lines.append(f"BLOCK: {len(blocked)} component(s) failed the guard: "
                         f"{', '.join(blocked)}")
        else:
            lines.append(f"ALLOW: all {len(items)} component(s) passed the guard.")
        # Names come from config files anyone can write (a repository's `.mcp.json`): their
        # escape sequences must not reach the terminal, as in every other text report.
        print(_terminal_safe("\n".join(lines)))
    return EXIT_FAIL_ON_HIGH if blocked else EXIT_OK


def _cmd_inventory(args: argparse.Namespace) -> int:
    from skilltotal.collector import CollectionError
    from skilltotal.engine import analyze
    from skilltotal.inventory import discover
    from skilltotal.report import render_inventory_json, render_inventory_text

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

    if args.sbom:
        from skilltotal.sbom import build_aibom

        print(json.dumps(build_aibom(items), indent=2, ensure_ascii=False))
    elif args.json:
        print(render_inventory_json(items))
    else:
        print(render_inventory_text(items))
    return EXIT_OK


def _cmd_mcp() -> int:
    from skilltotal.mcp_server import serve

    # The MCP stdio transport is UTF-8, but Windows consoles default to a legacy codepage
    # (e.g. cp1251), which would mojibake any non-ASCII snippet in a report and crash the
    # client's decoder. newline="\n" keeps the transport's one-message-per-LF framing free
    # of CRLF translation.
    if hasattr(sys.stdin, "reconfigure"):  # real stdio; absent on injected test streams
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    serve(sys.stdin, sys.stdout)
    return EXIT_OK


# The answer when the hook cannot finish its own check. Exiting with an error would let the plugin's
# wrapper pass the command with only a warning, and denying would block for SkillTotal's own fault:
# the person decides. In CI strict mode nobody is there to decide, so the command is denied.
HOOK_FAILED = {
    "systemMessage": "SkillTotal could not check this command.",
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": "SkillTotal could not check this command.",
    },
}
# CI strict mode for the hook: SKILLTOTAL_STRICT=1/true/yes/on turns it on and 0/false/no/off off;
# otherwise it is on when CI, or the marker of a CI service that does not always set CI, is set to
# anything but empty or a false value. The plugin's wrapper reads them the same way (a shared test
# table keeps the two in step): only ASCII letters are lowercased, and only spaces, tabs and line
# ends are removed.
HOOK_STRICT_ENV = "SKILLTOTAL_STRICT"
HOOK_CI_MARKERS = ("CI", "TF_BUILD", "JENKINS_URL", "TEAMCITY_VERSION", "CODEBUILD_BUILD_ID",
                   "BUILDKITE", "GITLAB_CI")
_ENV_TRUE = frozenset({"1", "true", "yes", "on"})
_ENV_FALSE = frozenset({"0", "false", "no", "off"})
_ENV_SPACE = re.compile(r"[ \t\r\n]")
_ENV_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _env_word(value: str) -> str:
    return _ENV_SPACE.sub("", value).translate(_ENV_LOWER)


def _hook_strict(environ) -> str:
    """The variable that turns CI strict mode on (where what the hook would ask about is denied),
    or "" when it is off."""
    value = _env_word(environ.get(HOOK_STRICT_ENV, ""))
    if value in _ENV_TRUE:
        return HOOK_STRICT_ENV
    if value in _ENV_FALSE:
        return ""
    return next((name for name in HOOK_CI_MARKERS
                 if _env_word(environ.get(name, "")) not in _ENV_FALSE | {""}), "")


def _hook_failed_strict(strict_by: str) -> dict:
    """The hook's own failure in CI strict mode, where nobody is there to decide: denied."""
    from skilltotal.agent_hook import strict_note

    reason = "(CI rule) SkillTotal blocked this command: it could not check it."
    return {
        "systemMessage": f"{reason} {strict_note(strict_by)}",
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }


def _hook_allowed_unchecked(environ) -> frozenset[str]:
    """The kinds of unchecked install strict mode lets through (SKILLTOTAL_ALLOW_UNCHECKED)."""
    from skilltotal.agent_hook import ALLOW_UNCHECKED_ENV, UNCHECKED_KINDS

    named = {part.strip().lower() for part in environ.get(ALLOW_UNCHECKED_ENV, "").split(",")}
    return frozenset(named & set(UNCHECKED_KINDS))


def _cmd_hook(args: argparse.Namespace) -> int:
    if args.supervise or args.scan_into:  # one of the processes of a check the hook started
        from skilltotal import hook_scan

        if args.scan_into:
            return hook_scan.scan_into(Path(args.scan_into))
        return hook_scan.supervise(Path(args.supervise), remember=_hook_remember)
    strict_by = _hook_strict(os.environ)
    try:
        answer = _hook_answer(strict_by)
    except Exception:  # noqa: BLE001 - a failure of ours asks (in CI denies), never passes silently
        answer = _hook_failed_strict(strict_by) if strict_by else HOOK_FAILED
    if answer is not None:
        print(json.dumps(answer))
    return EXIT_OK


def _hook_answer(strict_by: str = "") -> dict | None:
    from skilltotal.agent_hook import BUDGET_ENV, hook_response

    if hasattr(sys.stdin, "reconfigure"):  # Windows consoles default to a legacy codepage
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    raw = sys.stdin.read()
    try:
        event = json.loads(raw or "{}")
    except json.JSONDecodeError:
        # Not a hook event at all: stay out of the agent's way, except in CI, where a command the
        # hook could not read must not pass.
        return _hook_failed_strict(strict_by) if strict_by else None
    try:
        budget = float(os.environ.get(BUDGET_ENV, HOOK_BUDGET_S))
    except ValueError:
        budget = HOOK_BUDGET_S
    # Claude Code lets a command through when its hook outlives the hook's timeout (120 s in the
    # plugin's hooks.json), so a budget past it would turn every slow check into a silent pass.
    budget = max(1.0, min(budget, HOOK_MAX_BUDGET_S))
    return hook_response(event, scan=_hook_scan_cached, budget_s=budget,
                         strict=bool(strict_by), strict_by=strict_by,
                         allow_unchecked=_hook_allowed_unchecked(os.environ))


# How long the agent waits for the checks of one install command (a check that needs longer goes
# on in the background), and how long a verdict is reused: a week for an exact npm/PyPI release
# (its files never change), an hour for anything that can change under the same name (a git
# repository, or a package whose release could not be resolved).
HOOK_BUDGET_S = 60.0
HOOK_MAX_BUDGET_S = 100.0
HOOK_RELEASE_TTL_S = 7 * 24 * 3600
HOOK_MOVING_TTL_S = 3600
HOOK_CACHE_MAX_ENTRIES = 500


def _hook_cache_path() -> Path:
    from skilltotal.hook_scan import cache_file

    return cache_file()


def _hook_scan_cached(source: str, timeout: float) -> dict:
    """``_hook_scan``, reusing a verdict. Agents run the same ``npx tsc`` again and again, and each
    must not cost a scan.

    A verdict belongs to one artifact. ``npm:x`` is first resolved to the release the registry
    serves now (``npm:x@1.2.3``; on PyPI, also the file pip would install) and that is what is
    scanned and remembered, so a clean verdict from this morning never vouches for a release, or a
    file, published this afternoon. A new engine version rescans everything.

    One artifact is checked once at a time: while a check of it runs, the answer says so instead
    of starting another. A check that outlasts the wait goes on in the background and keeps its
    verdict itself (``_hook_hand_over``), and the same command run again is answered from it.
    """
    from skilltotal.agent_hook import CheckInBackground
    from skilltotal.hook_scan import GRACE_S, AlreadyRunning, Pending, ScanContinues

    started = time.monotonic()
    # Claude Code lets the command run when the hook outlives its timeout: nothing on this path
    # waits past the budget and a short grace.
    hard = started + timeout + GRACE_S
    release = _hook_lookup(source, max(1.0, min(5.0, timeout / 2)))
    key = release.key if release else source
    target = release.source if release else source
    ttl = _hook_cache_ttl(key)
    path = _hook_cache_path()
    now = time.time()
    hit = _hook_cache_read(path).get(key)
    if isinstance(hit, dict) and hit.get("engine") == __version__ and _fresh(hit, now, ttl):
        return hit["report"]
    # What the verdict is kept under, and for which file: everything that keeps it needs to know.
    job = {"key": key, "ttl": ttl, "artifact": release.artifact if release else "", "at": now,
           "engine": __version__}
    pending = Pending(path.parent / "hook-pending")
    try:
        marker = pending.claim(key, now, wait_s=min(2.0, max(0.0, hard - time.monotonic())))
    except AlreadyRunning as running:
        raise CheckInBackground(running.seconds_left, started_ago=running.age) from None
    # The check takes what its verdict is recorded under along, in case this hook goes away; with
    # no marker to track it by, it never runs on alone.
    check = {**job, "token": marker.token} if marker is not None else None
    try:
        report = _hook_scan(target, timeout - (time.monotonic() - started), check)
    except ScanContinues as late:
        try:
            # Raises unless the check ended in the meantime.
            report = _hook_hand_over(late, pending, marker, job, hard, target)
        except CheckInBackground:
            raise  # handed over: the marker is the check's now
        except BaseException:
            # Whatever went wrong, the check is not left half handed over. A failure to stop it
            # is not reported: the error being raised is the one that matters.
            with contextlib.suppress(Exception):
                late.scan.stop()
            pending.release(marker)
            raise
    except BaseException:
        pending.release(marker)
        raise  # a failed or late scan: nothing is cached
    pending.release(marker)
    return _hook_remember(job, report, deadline=hard)


def _hook_lookup(source: str, timeout: float):
    """The release ``source`` resolves to, or None when the registry has not answered within
    ``timeout`` seconds, as for a registry that did not answer. A lookup's own timeout covers each
    network step, not a slow name lookup or a trickle of data, so it runs in a thread that this
    process does not wait for past ``timeout``."""
    from skilltotal.collector import resolve_release

    found: list = []
    lookup = threading.Thread(
        target=lambda: found.append(resolve_release(source, timeout=timeout)), daemon=True)
    lookup.start()
    lookup.join(timeout)
    return found[0] if found else None


def _hook_hand_over(
    late: ScanContinues, pending: Pending, marker: Marker | None, job: dict, deadline: float,
    target: str,
) -> dict:
    """Decide the fate of a check the hook stops waiting for.

    It goes on in the background and keeps its verdict itself, unless its size says it cannot end
    before the ceiling, it could not be tracked (no marker could be written), or
    ``MAX_BACKGROUND`` checks already go on without a hook: then it is stopped, and records nothing.
    Raises what the answer then says; returns the report instead when the check ended in the
    meantime.
    """
    from skilltotal.agent_hook import BackgroundFull, CheckInBackground, TooLargeToCheck
    from skilltotal.hook_scan import CEILING_S, MAX_BACKGROUND

    scan = late.scan
    if late.too_large:
        report = scan.stop(deadline)
        if report is not None:
            return report
        pending.release(marker)
        raise TooLargeToCheck(target, CEILING_S)
    running: int | None = None
    if marker is not None:
        try:
            # Counting the others and joining them is one step.
            with pending.lock(max(0.0, min(5.0, deadline - time.monotonic()))):
                running = pending.background(time.time(), exclude=marker)
                ends = None if late.seconds_left is None else time.time() + late.seconds_left
                # The marker goes to the background before the check is handed over: a check that
                # ends right after frees a marker already in its final state (written after, it
                # would come back for a check that is over).
                if running < MAX_BACKGROUND and pending.go_background(marker, ends):
                    report = scan.hand_over(deadline)
                    if report is not None:
                        return report
                    raise CheckInBackground(late.seconds_left, large=late.large)
                if running < MAX_BACKGROUND:
                    running = None  # its marker is gone: it cannot be tracked
        except CheckInBackground:
            raise
        except (TimeoutError, OSError):
            running = None  # the markers cannot be kept safely: start nothing more
    report = scan.stop(deadline)
    if report is not None:
        return report
    pending.release(marker)
    if running is None:
        raise TimeoutError(job["key"])  # answered as a check that ran out of time
    raise BackgroundFull(running)


def _hook_cache_read(path: Path) -> dict:
    """The verdict cache; a missing or corrupt file is an empty one."""
    try:
        cache = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return cache if isinstance(cache, dict) else {}


def _hook_remember(job: dict, report: dict, deadline: float | None = None) -> dict:
    """The verdict of a scan as the cache keeps it, kept under ``job["key"]``; returns it.

    The one way a verdict is kept, whoever keeps it: the hook, for a scan that finished while it
    waited, or the check itself, for one that finished after the hook had stopped waiting.
    """
    from skilltotal.models import NOTHING_READ, UNANALYZED_INSTALL_SCRIPT

    verdict = report.get("verdict") or {}
    entry = {
        "engine": job["engine"],
        "at": job["at"],
        "ttl": job["ttl"],
        "report": {
            "risk_level": report.get("risk_level"),
            "risk_score": report.get("risk_score"),
            "component": {"version": (report.get("component") or {}).get("version", "")},
            "verdict": {
                "has_malicious_indicators": bool(verdict.get("has_malicious_indicators")),
                "headline": verdict.get("headline", ""),
            },
            # The scored findings, trimmed to what a reason names (title, file:line), so a
            # cached answer says what was found exactly like the first one did.
            "findings": [
                {
                    "id": f.get("id"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "threat_class": f.get("threat_class"),
                    "evidence": [
                        {"file": e.get("file"), "line_start": e.get("line_start")}
                        for e in (f.get("evidence") or [])[:1]
                    ],
                }
                for f in report.get("findings") or []
                if f.get("threat_class") in ("malicious_indicator", "risky_construct")
            ],
            # What the scan could not read decides the answer as much as a finding: an install
            # script it could not analyze, or a component nothing of which was read.
            "needs_review": [
                {"category": n.get("category"), "title": n.get("title"), "file": n.get("file")}
                for n in report.get("needs_review") or []
                if n.get("title") in (UNANALYZED_INSTALL_SCRIPT, NOTHING_READ)
            ],
        },
    }
    scanned = str((report.get("component") or {}).get("download_url") or "").rsplit("/", 1)[-1]
    if job["artifact"] and scanned != job["artifact"]:
        # A file was added to the release between the lookup and the scan: the verdict is good
        # for what was scanned, but it is not the artifact the key names, so it is not kept.
        return entry["report"]
    # The hook's own cache, wherever the check that found the verdict ran.
    _hook_cache_store(_hook_cache_path(), job["key"], entry, deadline)
    return entry["report"]


def _hook_cache_store(path: Path, key: str, entry: dict, deadline: float | None = None) -> None:
    """Add ``entry`` to the cache file. Every writer holds the cache's lock from reading the file to
    writing it back: two checks that finish at once must both be kept. A hook waits for the lock
    until ``deadline`` at most (a check in the background, up to 15 seconds)."""
    from skilltotal.hook_scan import file_lock, write_atomic

    wait_s = 15.0 if deadline is None else max(0.0, deadline - time.monotonic())
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(path.with_name(path.name + ".lock"), wait_s=wait_s):
            now = time.time()
            cache = _hook_cache_read(path)
            # Keep the file small: drop what has expired, then the oldest past the cap.
            live = {k: v for k, v in cache.items()
                    if isinstance(v, dict) and _fresh(v, now, _hook_cache_ttl(k))}
            newest = sorted(live, key=lambda k: _number(live[k].get("at")), reverse=True)
            kept = {key: entry,
                    **{k: live[k] for k in newest[: HOOK_CACHE_MAX_ENTRIES - 1] if k != key}}
            write_atomic(path, json.dumps(kept), deadline)
    except (OSError, TimeoutError):
        pass  # no cache this time; the verdict itself is still good


# A key that names one exact artifact: an npm release, or a PyPI release with the file pip installs
# (and a digest of every file in the release). Anything else can change under the same name.
_RELEASE_KEY = re.compile(
    r"npm:(?:@[^/\s@]+/)?[^/\s@]+@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?"
    r"|pypi:[^\s=]+==\S+ \S+(?: [0-9a-f]{16})?"
)


def _hook_cache_ttl(key: str) -> float:
    """How long a verdict kept under ``key`` may be reused: a week for one exact release, an hour
    for anything else. It is worked out from the key, never taken from the cache file."""
    return HOOK_RELEASE_TTL_S if _RELEASE_KEY.fullmatch(key) else HOOK_MOVING_TTL_S


def _fresh(entry: dict, now: float, ttl: float) -> bool:
    """Whether a cache entry is still good: younger than its key allows. An entry dated in the
    future, or claiming a longer life than its key allows, is not."""
    stored = _number(entry.get("ttl", ttl))
    return stored <= ttl and 0 <= now - _number(entry.get("at")) < stored


def _number(value: object) -> float:
    """A cache timestamp or TTL as a float; anything malformed counts as 0 (expired)."""
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def _hook_scan(source: str, timeout: float, job: dict | None = None) -> dict:
    """Scan ``source`` in processes of its own and wait up to ``timeout`` seconds for the report.

    The scan outlives the wait: past it, this raises ``ScanContinues`` (a TimeoutError) with the
    running check, and the caller hands it over or stops it. ``job`` (what the verdict is recorded
    under, and the check's marker token) lets the check keep its verdict even if this hook goes
    away. The check runs in an empty directory with a temp directory of its own, never in the
    agent's project (see ``RunningScan.start``).
    """
    from skilltotal.hook_scan import GRACE_S, RunningScan

    deadline = time.monotonic() + timeout + GRACE_S
    return RunningScan.start(source, job, deadline).wait(timeout)


def _cmd_rules(args: argparse.Namespace) -> int:
    from skilltotal.report import render_rules_json, render_rules_text
    from skilltotal.rules import get_rules

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
    from skilltotal.config import Config, find_config, load_config

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

    The severity gate counts what the score counts as risk. A malicious indicator trips any
    level (a prompt-injection hit is medium severity, and its verdict is still malicious); a
    risky construct or a shipped secret trips at its severity; a capability, which is what a
    component can do (run a shell, reach the network), never trips it on its own. Counting
    capabilities failed CI for most honest tools: a shell call is high severity.

    What the scan could not read fails the severity gate closed, as it does in `guard`: a script
    that runs at install time and was not analyzed, or a component nothing of which was read.
    Counting capabilities used to cover the first by accident (an install hook is a high
    capability), so a dropper padded past the size limit failed CI; it must still.

    Per-rule policy actions refine the severity gate: a `block` rule trips it whenever it
    fires (even with no `fail_on` configured, capabilities included: the way to forbid one);
    a `warn` rule is exempt from the severity threshold (explicit accept-but-show). The
    aggregate `fail_on_score` gate is unaffected — warn findings still count toward the
    risk score.
    """
    from skilltotal.models import NOTHING_READ, UNANALYZED_INSTALL_SCRIPT, Severity, ThreatClass

    policy = policy or {}
    if any(policy.get(f.id) == "block" for f in report.findings):
        return True
    if level:
        if any(n.title in (UNANALYZED_INSTALL_SCRIPT, NOTHING_READ) for n in report.needs_review):
            return True
        threshold = Severity[level.upper()].rank
        for f in report.findings:
            if policy.get(f.id) == "warn" or f.threat_class is ThreatClass.CAPABILITY:
                continue
            if f.threat_class is ThreatClass.MALICIOUS_INDICATOR or f.severity.rank >= threshold:
                return True
    if score is not None and report.risk_score >= score:
        return True
    return False
