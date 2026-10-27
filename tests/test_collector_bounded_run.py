"""run_bounded returns on time even when a grandchild keeps the output pipe open.

Git for Windows' git.exe is a launcher; killing it on a timeout leaves the real git and a
credential helper holding its stdout, and subprocess.run then read that pipe for four hours
(tripwire, 2026-10-27). The child here starts a grandchild that inherits the pipes and outlives
the kill, which is the same shape on every platform.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - the test starts its own fixed Python children
import sys
import time

import pytest

from skilltotal.collector import noninteractive_git_env, run_bounded

_PARENT = (
    "import pathlib, subprocess, sys, time\n"
    "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
    "pathlib.Path(sys.argv[1]).write_text(str(g.pid))\n"
    "time.sleep(30)\n"
)


def test_a_timeout_returns_while_a_grandchild_still_holds_the_pipe(tmp_path):
    pid_file = tmp_path / "grandchild.pid"
    started = time.monotonic()
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            run_bounded([sys.executable, "-c", _PARENT, str(pid_file)], env=dict(os.environ),
                        timeout=3)
        assert time.monotonic() - started < 20
    finally:
        if pid_file.exists():  # do not leave the grandchild running
            try:
                os.kill(int(pid_file.read_text()), 9)
            except (ValueError, OSError):
                pass


def test_a_finished_command_returns_its_output_and_code():
    done = run_bounded(
        [sys.executable, "-c",
         "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"],
        env=dict(os.environ), timeout=30,
    )
    assert (done.returncode, done.stdout.strip(), done.stderr.strip()) == (3, "out", "err")


def test_git_never_asks_for_credentials():
    env = noninteractive_git_env()
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GCM_INTERACTIVE"] == "never"
