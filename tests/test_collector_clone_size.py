"""The size guard measures what will be scanned: the working tree (or the linked subfolder),
never the repository's history.

A week of hosted scans (2026-09-14..20) rejected 15 repositories as "too large"; measured
afterwards, deepseek-harness had a 24 MB checkout behind a 202 MB history, and a user who
linked a 300 KB ``skills/`` folder four times was refused four times because the whole
repository was cloned and measured."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from skilltotal import collector
from skilltotal.collector import SourceTooLargeError

MB = 1024 * 1024


class _Resp:
    def __init__(self, payload: dict):
        self._p = json.dumps(payload).encode()

    def read(self, _n: int = -1) -> bytes:
        return self._p

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def _mock_github(monkeypatch, *, history_kb: int, tree: list[dict] | None, truncated=False,
                 default_branch="main"):
    """Route the two GitHub API calls: /repos/{o}/{r} and /repos/{o}/{r}/git/trees/{ref}."""
    seen: list[str] = []

    def urlopen(req, timeout=None):  # noqa: ARG001
        url = req.full_url if hasattr(req, "full_url") else str(req)
        seen.append(url)
        if "/git/trees/" in url:
            if tree is None:
                raise OSError("trees API unavailable")
            return _Resp({"tree": tree, "truncated": truncated})
        return _Resp({"size": history_kb, "default_branch": default_branch})

    monkeypatch.setattr(collector.urllib.request, "urlopen", urlopen)
    return seen


def _blob(path: str, size: int) -> dict:
    return {"path": path, "type": "blob", "size": size}


def test_small_tree_behind_a_big_history_is_allowed(monkeypatch):
    cap = collector._MAX_CLONE_MB
    seen = _mock_github(monkeypatch, history_kb=(cap + 50) * 1024,
                        tree=[_blob("src/a.py", 10 * MB), {"path": "src", "type": "tree"}])
    collector._reject_if_too_large("https://github.com/o/r.git")  # no raise
    assert any(url.endswith("/git/trees/main?recursive=1") for url in seen)


def test_big_tree_is_rejected_by_its_own_size(monkeypatch):
    cap = collector._MAX_CLONE_MB
    _mock_github(monkeypatch, history_kb=10 * 1024,
                 tree=[_blob("assets/video.mp4", (cap + 1) * MB)])
    with pytest.raises(SourceTooLargeError, match="working tree"):
        collector._reject_if_too_large("https://github.com/o/r.git")


def test_subfolder_link_is_measured_by_the_subfolder(monkeypatch):
    cap = collector._MAX_CLONE_MB
    tree = [
        _blob("media/big.bin", (cap + 1) * MB),
        _blob("skills/x/SKILL.md", 2048),
        _blob("skills/x/run.py", 4096),
        _blob("skillsX/decoy.bin", 5 * MB),  # a sibling whose name merely starts the same
    ]
    _mock_github(monkeypatch, history_kb=1024, tree=tree)
    collector._reject_if_too_large("https://github.com/o/r.git", ref="main", subpath="skills/x")
    with pytest.raises(SourceTooLargeError):
        collector._reject_if_too_large("https://github.com/o/r.git", ref="main", subpath="media")


def test_requested_ref_is_the_tree_that_is_measured(monkeypatch):
    seen = _mock_github(monkeypatch, history_kb=1024, tree=[_blob("a", 1)])
    collector._reject_if_too_large("https://github.com/o/r.git", ref="v2.1")
    assert any(url.endswith("/git/trees/v2.1?recursive=1") for url in seen)


def test_history_size_is_the_fallback_when_the_tree_is_unavailable(monkeypatch):
    """Rate-limited or truncated trees answer -> the old, conservative check still applies."""
    cap = collector._MAX_CLONE_MB
    _mock_github(monkeypatch, history_kb=(cap + 50) * 1024, tree=None)
    with pytest.raises(SourceTooLargeError):
        collector._reject_if_too_large("https://github.com/o/r.git")
    _mock_github(monkeypatch, history_kb=(cap + 50) * 1024, tree=[_blob("a", 1)], truncated=True)
    with pytest.raises(SourceTooLargeError):
        collector._reject_if_too_large("https://github.com/o/r.git")
    _mock_github(monkeypatch, history_kb=1024, tree=None)
    collector._reject_if_too_large("https://github.com/o/r.git")  # small history, no tree: ok


def test_unsafe_ref_never_reaches_the_api_path(monkeypatch):
    seen = _mock_github(monkeypatch, history_kb=1024, tree=[_blob("a", 1)])
    collector._reject_if_too_large("https://github.com/o/r.git", ref="../../evil?x=1")
    assert not any("/git/trees/" in url for url in seen)


# --- what the watchdog and the post-clone check count -----------------------------------------
def test_dir_size_can_leave_out_the_git_metadata(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_bytes(b"x" * 1000)
    (tmp_path / ".git" / "objects").mkdir(parents=True)
    (tmp_path / ".git" / "objects" / "pack").write_bytes(b"y" * 5000)
    assert collector._dir_size_bytes(tmp_path) == 6000
    assert collector._dir_size_bytes(tmp_path, skip_git=True) == 1000


# --- sparse checkout of a linked subfolder ----------------------------------------------------
def _make_repo(root: Path) -> Path:
    """A local repository with a small skill folder and a 1 MB blob beside it."""
    repo = root / "origin"
    repo.mkdir()
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}

    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                       env={**__import__("os").environ, **env})

    git("init", "-q", "-b", "main")
    git("config", "uploadpack.allowfilter", "true")
    (repo / "skills" / "x").mkdir(parents=True)
    (repo / "skills" / "x" / "SKILL.md").write_text("# skill\n")
    (repo / "media").mkdir()
    (repo / "media" / "big.bin").write_bytes(b"\0" * MB)
    (repo / "README.md").write_text("root\n")
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    return repo


@pytest.mark.skipif(collector.shutil.which("git") is None, reason="git not on PATH")
def test_subfolder_link_checks_out_only_that_folder(tmp_path, monkeypatch):
    repo = _make_repo(tmp_path)
    dest = tmp_path / "clone"
    collector._clone(repo.as_uri(), None, "skills/x", dest, dict(__import__("os").environ),
                     "https://example.test/o/r/tree/main/skills/x")
    assert (dest / "skills" / "x" / "SKILL.md").is_file()
    assert not (dest / "media" / "big.bin").exists()  # never checked out


@pytest.mark.skipif(collector.shutil.which("git") is None, reason="git not on PATH")
def test_partial_clone_skips_the_blobs_outside_the_subfolder(tmp_path, monkeypatch):
    """On hosts that support partial clone, the 1 MB blob is not even downloaded."""
    repo = _make_repo(tmp_path)
    monkeypatch.setattr(collector, "_PARTIAL_CLONE_HOSTS", {*collector._PARTIAL_CLONE_HOSTS, ""})
    dest = tmp_path / "clone"
    collector._clone(repo.as_uri(), None, "skills/x", dest, dict(__import__("os").environ),
                     "https://example.test/o/r/tree/main/skills/x")
    assert (dest / "skills" / "x" / "SKILL.md").is_file()
    assert collector._dir_size_bytes(dest) < MB // 2  # .git holds no copy of media/big.bin


@pytest.mark.skipif(collector.shutil.which("git") is None, reason="git not on PATH")
def test_whole_repository_clone_is_unchanged(tmp_path):
    repo = _make_repo(tmp_path)
    dest = tmp_path / "clone"
    collector._clone(repo.as_uri(), None, None, dest, dict(__import__("os").environ),
                     "https://example.test/o/r")
    assert (dest / "media" / "big.bin").is_file()
    assert (dest / "skills" / "x" / "SKILL.md").is_file()
