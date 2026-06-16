"""CLI integration: commands, flags, and exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.cli import (
    EXIT_ERROR,
    EXIT_FAIL_ON_HIGH,
    EXIT_OK,
    main,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_text_output(capsys):
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg")])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "SkillTotal Security Report" in out


def test_scan_json_output(capsys):
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--json"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    data = json.loads(out)
    # Sensitive-path access (.js) + network egress -> ST-COMBO-EXFIL (critical risky) + the
    # sensitive-path finding => high. Plain capabilities (shell/install/fs) no longer score.
    assert data["risk_level"] == "high"


def test_scan_output_file(tmp_path: Path, capsys):
    target = tmp_path / "report.json"
    code = main(["scan", str(FIXTURES / "clean_pkg"), "--output", str(target)])
    capsys.readouterr()
    assert code == EXIT_OK
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["component"]["name"] == "cleanlib"


def test_fail_on_high_triggers_for_malicious(capsys):
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--fail-on-high"])
    capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH


def test_fail_on_high_ok_for_clean(capsys):
    code = main(["scan", str(FIXTURES / "clean_pkg"), "--fail-on-high"])
    capsys.readouterr()
    assert code == EXIT_OK


def test_scan_missing_path_errors(capsys):
    code = main(["scan", str(FIXTURES / "does_not_exist_xyz")])
    err = capsys.readouterr().err
    assert code == EXIT_ERROR
    assert "error:" in err


def test_scan_sarif_output(capsys):
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--sarif"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    data = json.loads(out)
    assert data["version"] == "2.1.0"


def test_scan_sarif_output_file(tmp_path: Path, capsys):
    target = tmp_path / "out.sarif"
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--sarif", "--output", str(target)])
    capsys.readouterr()
    assert code == EXIT_OK
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["runs"][0]["tool"]["driver"]["name"] == "SkillTotal"


def test_write_baseline_then_suppress(tmp_path: Path, capsys):
    target = str(FIXTURES / "malicious_npm_pkg")
    baseline = tmp_path / "bl.json"

    # 1. Snapshot current findings into a baseline.
    main(["scan", target, "--write-baseline", str(baseline)])
    capsys.readouterr()
    assert baseline.exists()

    # 2. Re-scan with the baseline: findings are suppressed, score drops below critical.
    main(["scan", target, "--baseline", str(baseline), "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["metadata"]["suppressed_count"] > 0
    assert data["risk_score"] < 100


def test_baseline_with_fail_on_high_passes_after_suppression(tmp_path: Path, capsys):
    target = str(FIXTURES / "malicious_npm_pkg")
    baseline = tmp_path / "bl.json"
    main(["scan", target, "--write-baseline", str(baseline)])
    capsys.readouterr()
    code = main(["scan", target, "--baseline", str(baseline), "--fail-on-high"])
    capsys.readouterr()
    assert code == EXIT_OK


def test_missing_baseline_file_errors(capsys):
    code = main(["scan", str(FIXTURES / "clean_pkg"), "--baseline", "nope_xyz.json"])
    err = capsys.readouterr().err
    assert code == EXIT_ERROR
    assert "baseline" in err


def test_rules_list_text(capsys):
    code = main(["rules", "list"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "ST-SHELL-PY" in out
    assert "ST-COMBO-EXFIL" in out


def test_rules_list_json(capsys):
    code = main(["rules", "list", "--json"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    rules = json.loads(out)
    ids = {r["id"] for r in rules}
    assert "ST-MCP-DANGEROUS-TOOL" in ids


def test_fail_on_level_critical_triggers(capsys):
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--fail-on", "critical"])
    capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH  # ST-COMBO-EXFIL is a critical finding


def test_fail_on_score_triggers(capsys):
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--fail-on-score", "1"])
    capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH


def test_fail_on_score_high_threshold_passes(capsys):
    code = main(["scan", str(FIXTURES / "clean_pkg"), "--fail-on-score", "50"])
    capsys.readouterr()
    assert code == EXIT_OK


def test_exclude_flag_drops_findings(capsys):
    # Excluding the stealer .js removes the sensitive-path + network egress -> no exfil combo.
    main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--exclude", "*.js", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["risk_level"] == "low"


def test_config_drives_gate(tmp_path: Path, capsys):
    cfg = tmp_path / ".skilltotal.toml"
    cfg.write_text('fail_on = "high"\n', encoding="utf-8")
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--config", str(cfg)])
    capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH


def test_config_ignore_rule(tmp_path: Path, capsys):
    cfg = tmp_path / ".skilltotal.toml"
    cfg.write_text('ignore = ["ST-COMBO-EXFIL"]\n', encoding="utf-8")
    main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--config", str(cfg), "--json"])
    out = capsys.readouterr().out
    ids = {f["id"] for f in json.loads(out)["findings"]}
    assert "ST-COMBO-EXFIL" not in ids


def test_no_command_errors():
    with pytest.raises(SystemExit):
        main([])
