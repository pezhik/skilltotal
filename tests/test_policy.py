"""Per-rule policy actions (block / warn / ignore) from the [policy] config table.

The eval()/shell=True snippets below are inert *detection fixtures*: string literals
written to temp files for the scanner to flag. They are never executed.
"""

from __future__ import annotations

import json
from pathlib import Path

from skilltotal.cli import EXIT_FAIL_ON_HIGH, EXIT_OK, main
from skilltotal.config import load_config

# A single high-severity capability finding (ST-DYN-PY) and nothing else.
DYN_ONLY = "eval(user_input)\n"


def _component(tmp_path: Path, code: str = DYN_ONLY) -> Path:
    root = tmp_path / "component"
    root.mkdir()
    (root / "m.py").write_text(code, encoding="utf-8", newline="")
    return root


def _config(tmp_path: Path, body: str) -> Path:
    p = tmp_path / ".skilltotal.toml"
    p.write_text(body, encoding="utf-8")
    return p


# --- config parsing -----------------------------------------------------------------

def test_policy_table_parses_valid_actions(tmp_path: Path):
    p = _config(
        tmp_path,
        '[policy]\n'
        '"ST-SHELL-PIPE-EXEC" = "block"\n'
        '"ST-DYN-PY" = "WARN"\n'          # actions are case-insensitive
        '"ST-SENS-WORD" = "ignore"\n'
        '"ST-BOGUS" = "explode"\n',       # unknown action -> dropped, not fatal
    )
    c = load_config(p)
    assert c.policy == {
        "ST-SHELL-PIPE-EXEC": "block",
        "ST-DYN-PY": "warn",
        "ST-SENS-WORD": "ignore",
    }


def test_ignored_rules_merges_ignore_list_and_policy(tmp_path: Path):
    p = _config(
        tmp_path,
        'ignore = ["ST-NET-PY"]\n[policy]\n"ST-SENS-WORD" = "ignore"\n"ST-DYN-PY" = "warn"\n',
    )
    c = load_config(p)
    assert c.ignored_rules() == {"ST-NET-PY", "ST-SENS-WORD"}


# --- gate behavior ------------------------------------------------------------------

def test_block_trips_gate_without_fail_on(tmp_path: Path, capsys):
    root = _component(tmp_path)
    cfg = _config(tmp_path, '[policy]\n"ST-DYN-PY" = "block"\n')
    code = main(["scan", str(root), "--config", str(cfg)])
    capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH


def test_warn_exempts_rule_from_severity_gate(tmp_path: Path, capsys):
    root = _component(tmp_path)

    # Control: the high-severity finding trips --fail-on high.
    code = main(["scan", str(root), "--fail-on", "high"])
    capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH

    # With a warn policy the same finding is reported but no longer gates.
    cfg = _config(tmp_path, '[policy]\n"ST-DYN-PY" = "warn"\n')
    code = main(["scan", str(root), "--fail-on", "high", "--config", str(cfg), "--json"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "ST-DYN-PY" in {f["id"] for f in json.loads(out)["findings"]}


def test_warn_does_not_shield_other_rules(tmp_path: Path, capsys):
    root = _component(
        tmp_path, DYN_ONLY + "import subprocess\nsubprocess.run(cmd, shell=True)\n"
    )
    cfg = _config(tmp_path, '[policy]\n"ST-DYN-PY" = "warn"\n')
    code = main(["scan", str(root), "--fail-on", "high", "--config", str(cfg)])
    capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH  # ST-SHELL-PY (high) still gates


def test_policy_ignore_suppresses_finding(tmp_path: Path, capsys):
    root = _component(tmp_path)
    cfg = _config(tmp_path, '[policy]\n"ST-DYN-PY" = "ignore"\n')
    code = main(["scan", str(root), "--config", str(cfg), "--json"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "ST-DYN-PY" not in {f["id"] for f in json.loads(out)["findings"]}
