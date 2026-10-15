"""The composite action runs in the consumer's checkout, which may be an untrusted pull request.

Read with the engine's own decoder of `run:` steps, so each check sees the commands the way the
runner's shell receives them.
"""

from __future__ import annotations

import json
import os
import re
import subprocess  # nosec B404 - runs the action's own step snippets with this interpreter
import sys
import tempfile
from pathlib import Path

from skilltotal import __version__
from skilltotal.scanners.shell_script import _RUN_KEY, _action_commands, _indent, _yaml_value

ACTION = Path(__file__).resolve().parent.parent / "action.yml"


def _commands() -> list[str]:
    return [command for command, _ in _action_commands(ACTION.read_text(encoding="utf-8"))]


def test_inputs_reach_the_shell_only_through_env():
    # `${{ inputs.source }}` inside `run:` is pasted into the script before bash parses it, so
    # untrusted text such as `$(…)` would run in the consumer's runner.
    commands = _commands()
    assert commands
    for command in commands:
        assert "${{" not in command, command


def test_every_python_keeps_the_scanned_repository_off_sys_path():
    # `python -m x` and `python -c` put the working directory (the scanned repo) first on
    # sys.path, where a planted `skilltotal/`, `pip/` or `json.py` would run instead.
    calls = [m for command in _commands() for m in re.finditer(r"\bpython3?\b(\s+\S+)?", command)]
    assert calls
    for call in calls:
        assert (call.group(1) or "").strip() in ("-I", "-P"), call.group(0)


def test_an_unknown_fail_on_level_fails_instead_of_disabling_the_gate():
    text = ACTION.read_text(encoding="utf-8")
    assert "fail-on must be low, medium, high, critical or none" in text
    assert 'GATE+=(--fail-on "' in text


def test_the_pull_request_comment_puts_malicious_indicators_first():
    # A dropper can score 20/100 (low): the icon must not go green over malicious indicators.
    script = _summary_script()
    assert "icon = '🔴' if verdict.get('has_malicious_indicators') is True else" in script
    report = {"risk_level": "low", "risk_score": 20, "verdict": {"has_malicious_indicators": True},
              "findings": []}
    assert _run_summary(report).startswith("## 🔴 ")


def test_sarif_from_a_source_outside_the_repository_is_not_uploaded():
    # Alerts for an npm:/pypi: package or a git URL would point at files the repository lacks.
    text = ACTION.read_text(encoding="utf-8")
    assert "npm:*|pypi:*|http://*|https://*|git@*|ssh://*|git://*|git+*) SARIF_UPLOAD=false" in text
    upload = text.split("- name: Upload SARIF to Code Scanning", 1)[1].split("- name:", 1)[0]
    assert "steps.scan.outputs.sarif-upload == 'true'" in upload


def test_the_pull_request_comment_counts_risk_apart_from_capabilities_and_says_the_gate():
    text = ACTION.read_text(encoding="utf-8")
    comment = text.split("- name: Comment on PR", 1)[1].split("- name:", 1)[0]
    # The Scan step writes the comment's Markdown; the comment step posts it, in place.
    assert "COMMENT_MD: ${{ steps.scan.outputs.comment-file }}" in comment
    assert "github.rest.issues.updateComment" in comment
    findings = [_finding("ST-A", "high", "risky_construct"),
                _finding("ST-CAP", "low", "capability")]
    body = _run_summary({"risk_level": "high", "risk_score": 40, "findings": findings})
    assert "**Gate:** **failed**" in body
    assert "**Findings:** 1 risk finding(s) · 1 capability finding(s), not scored" in body
    assert "ST-CAP" not in body


# --- The Scan step's Python, run on its own with this interpreter -------------------------------

def _scan_script() -> str:
    """The Scan step's `run:` value as the runner gets it (comments kept)."""
    text = ACTION.read_text(encoding="utf-8")
    for match in _RUN_KEY.finditer(text):
        key_line = text.rfind("\n", 0, match.start()) + 1
        command = "".join(_yaml_value(text, match.end(), _indent(text, key_line))[0])
        if "GATE_EXIT=0" in command:
            return command
    raise AssertionError("no Scan step in action.yml")


def _heredoc(after: str) -> str:
    script = _scan_script()
    start = script.index(after)
    body = script[script.index("<<'PY'", start):].split("\n", 1)[1]
    return body.split("\nPY\n", 1)[0]


def _summary_script() -> str:
    return _heredoc('python -I - "$REPORT_JSON"')


def _finding(rule: str, severity: str, threat_class: str, file: str = "a.py", line: int = 1,
             title: str = "t") -> dict:
    return {"id": rule, "severity": severity, "threat_class": threat_class, "title": title,
            "evidence": [{"file": file, "line_start": line}]}


def _run_summary(report: dict | None, gate_exit: str = "2", log: str = "",
                 env: dict[str, str] | None = None) -> str:
    """Run the summary script; return the comment Markdown (the job summary is checked apart)."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        report_path = tmp_path / "report.json"
        if report is not None:
            report_path.write_text(json.dumps(report), encoding="utf-8")
        (tmp_path / "scan.log").write_text(log, encoding="utf-8")
        run_env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("GITHUB_", "RUNNER_"))}
        run_env.update(env or {})
        subprocess.run(  # nosec B603 - this interpreter, the action's own snippet
            [sys.executable, "-I", "-c", _summary_script(), str(report_path),
             str(tmp_path / "scan.log"), gate_exit, "src", str(tmp_path / "comment.md"),
             str(tmp_path / "annotations.txt")],
            capture_output=True, text=True, encoding="utf-8", check=True, env=run_env)
        return (tmp_path / "comment.md").read_text(encoding="utf-8")


def test_scanned_text_in_the_summary_cannot_render_html_links_or_mentions():
    # File names and titles come from the scanned component: in the job summary and the pull
    # request comment they must stay text.
    evil = "<img src=x onerror=alert(1)> [click](https://evil.example) @octocat **b** | x"
    findings = [_finding("ST-A", "high", "risky_construct", file=evil + ".py", title=evil)]
    body = _run_summary({"risk_level": "high", "risk_score": 40, "findings": findings})
    row = next(line for line in body.splitlines() if "ST-A" in line)
    # The location is a code span (no Markdown, HTML or mention inside one); its | is escaped,
    # since a table cell ends at a bare | even inside a code span.
    assert "| ` " + evil.replace("|", "\\|") + ".py:1 ` |" in row
    # The title: every punctuation mark escaped, and no @mention.
    title = row.rsplit(".py:1 ` | ", 1)[1]
    assert title.startswith("\\<img src\\=x onerror\\=alert\\(1\\)\\> \\[click\\]\\(https\\:\\/\\/")
    assert re.search(r"(?<!\\)[<>\[\]()*|]", title[:-1]) is None
    assert "@\u200boctocat" in title
    assert row.count("|") - row.count("\\|") == 5  # four cells
    # A bidi override in a file name cannot reorder what the reader sees.
    spoof = [_finding("ST-B", "high", "risky_construct", file="a" + chr(0x202E) + "txt.exe")]
    body = _run_summary({"risk_level": "high", "risk_score": 40, "findings": spoof})
    assert "` a<U+202E>txt.exe:1 `" in body
    assert chr(0x202E) not in body


def test_the_comment_lists_the_top_findings_and_links_the_run():
    findings = [_finding(f"ST-{i}", "medium", "risky_construct", line=i) for i in range(8)]
    findings.append(_finding("ST-MAL", "low", "malicious_indicator", file="x.js", line=9))
    report = {"risk_level": "high", "risk_score": 60, "findings": findings,
              "capabilities": {"network_egress": [], "shell_execution": []},
              "metadata": {"suppressed_count": 3}}
    env = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r",
           "GITHUB_RUN_ID": "7"}
    log = "gate: fail-on high (action default) tripped by ST-MAL (x.js:9)\n"
    body = _run_summary(report, log=log, env=env)
    rows = [line for line in body.splitlines() if line.startswith("| ") and "ST-" in line]
    assert len(rows) == 5  # the top five; malicious indicators first, at any severity
    assert "malicious indicator" in rows[0] and "` x.js:9 `" in rows[0]
    assert "_…and 4 more risk finding(s)" in body
    assert "- ` fail-on high (action default) tripped by ST-MAL (x.js:9) `" in body
    assert "**Capabilities:** network\\_egress, shell\\_execution" in body
    assert "**Suppressed:** 3 finding(s)" in body
    assert "[Workflow run](https://github.com/o/r/actions/runs/7)" in body


def test_a_scan_that_could_not_run_says_why_in_the_summary():
    body = _run_summary(None, gate_exit="1", log="error: cannot read config x.toml: missing\n")
    assert ("**SkillTotal could not run the scan** (exit 1): "
            "cannot read config x\\.toml\\: missing") in body
    assert "**Gate:**" not in body


def test_an_older_version_input_warns():
    script = _heredoc('python -I - "$INPUT_VERSION"')
    init = Path(__file__).resolve().parent.parent / "skilltotal" / "__init__.py"

    def warn(version: str) -> str:
        return subprocess.run(  # nosec B603 - this interpreter, the action's own snippet
            [sys.executable, "-I", "-c", script, version, str(init)],
            capture_output=True, text=True, encoding="utf-8", check=True).stdout

    assert warn("0.1.0").startswith("::warning::SkillTotal version 0.1.0 is older than this action")
    assert warn(__version__) == ""
    assert warn("999.0.0") == ""
    assert warn("not-a-version") == ""


def test_the_sarif_run_of_a_registry_package_is_pinned_to_the_scanned_version():
    script = _scan_script()
    code = script.split('SARIF_SOURCE="$(python -I -c \'', 1)[1].split("' \"$INPUT_SOURCE\"", 1)[0]

    def pin(source: str, version: str) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "r.json"
            report.write_text(json.dumps({"component": {"version": version}}), encoding="utf-8")
            return subprocess.run(  # nosec B603 - this interpreter, the action's own snippet
                [sys.executable, "-I", "-c", code, source, str(report)],
                capture_output=True, text=True, encoding="utf-8", check=True).stdout.strip()

    assert pin("npm:left-pad", "1.3.0") == "npm:left-pad@1.3.0"
    assert pin("npm:@scope/pkg@latest", "2.0.1") == "npm:@scope/pkg@2.0.1"
    assert pin("PyPI:requests==2", "2.32.3") == "pypi:requests==2.32.3"
    assert pin("pypi:requests", "1!2.0+local") == "pypi:requests==1!2.0+local"
    # A git URL is not pinned, and neither is a version that is not a plain version string.
    assert pin("https://github.com/o/r", "1.0.0") == "https://github.com/o/r"
    assert pin("npm:left-pad", "1.0.0 --config x") == "npm:left-pad"
    assert pin("npm:left-pad", "") == "npm:left-pad"


def test_new_inputs_reach_the_cli_through_env():
    text = ACTION.read_text(encoding="utf-8")
    for name in ("fail-on-score", "exclude", "config", "sarif-category"):
        env = "INPUT_" + name.upper().replace("-", "_")
        assert f"{env}: ${{{{ inputs.{name} }}}}" in text, name
    fail_on = text.split("  fail-on:\n", 1)[1].split("\n  fail-on-score:", 1)[0]
    assert 'default: ""' in fail_on
    assert '"") GATE+=(--fail-on-default high) ;;' in text
