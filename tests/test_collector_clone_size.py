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


# --- Windows path limits ----------------------------------------------------------------
# A real repository can hold a file name past Windows' ~260-character path limit (one result file
# per model combination gets there in a single name). Without core.longpaths the clone dies with
# "unable to create file" and the scan looks broken, while the same repository scans fine on Linux
# — observed 2026-09-21 on elder-plinius/GLOSSOPETRAE.


def _captured_git_args(monkeypatch, tmp_path, subpath=None, ref=None):
    """Every git argv the collector would run for a clone."""
    seen: list[list[str]] = []

    def fake_run_git(args, dest, env, url):
        seen.append(list(args))
        Path(dest).mkdir(parents=True, exist_ok=True)

    def fake_git(dest, args, env, *, timeout):
        seen.append(["git", *collector._GIT_LONG_PATHS, "-C", str(dest), *args])

    monkeypatch.setattr(collector, "_run_git", fake_run_git)
    monkeypatch.setattr(collector, "_git", fake_git)
    collector._clone("https://github.com/o/r", ref, subpath, tmp_path / "repo", {}, "url")
    return seen


def test_clone_asks_git_to_accept_long_paths(monkeypatch, tmp_path):
    args = _captured_git_args(monkeypatch, tmp_path)[0]
    assert args[:3] == ["git", "-c", "core.longpaths=true"]
    assert "clone" in args


def test_the_option_comes_before_the_subcommand(monkeypatch, tmp_path):
    # `-c` is a git-level flag: after the subcommand it is an argument to that subcommand instead.
    args = _captured_git_args(monkeypatch, tmp_path)[0]
    assert args.index("-c") < args.index("clone")


def test_every_command_that_writes_files_carries_it(monkeypatch, tmp_path):
    # sparse-checkout and checkout create the working tree too, so the clone alone is not enough.
    for cmds in (_captured_git_args(monkeypatch, tmp_path, subpath="skills/x"),
                 _captured_git_args(monkeypatch, tmp_path, ref="a" * 40)):
        assert len(cmds) > 1
        for argv in cmds:
            assert "core.longpaths=true" in argv, argv


def test_the_machines_own_git_configuration_is_never_written(monkeypatch, tmp_path):
    # A scanner changes no settings on the machine it runs on: the option is per command.
    for argv in _captured_git_args(monkeypatch, tmp_path, subpath="a"):
        assert "--global" not in argv
        assert "config" not in argv

# --- what a scan will actually read -------------------------------------------------------
#
# Measured on five real repositories (2026-09-22): tree size does not predict scan time at all
# -- 257 MB scanned in 47 s while 104 MB took 326 s -- but readable bytes predict it to within a
# factor of two across a 36x range. That is the number a caller can turn into "about a minute
# left"; it is deliberately NOT the number the size limit is applied to.


def _sizes(monkeypatch, tree):
    """Run the pre-clone check over ``tree`` and return the TreeSize handed to the callback."""
    _mock_github(monkeypatch, history_kb=1024, tree=tree)
    seen: list[collector.TreeSize] = []
    collector._reject_if_too_large("https://github.com/o/r.git", on_size=seen.append)
    return seen


def test_media_does_not_count_as_work_to_be_done(monkeypatch):
    seen = _sizes(monkeypatch, [
        _blob("assets/clip.mp4", 40 * MB),
        _blob("assets/font.woff2", 5 * MB),
        _blob("src/main.py", 300_000),
        _blob("README.md", 2_000),
    ])
    assert len(seen) == 1
    assert seen[0].total == 45 * MB + 302_000
    assert seen[0].readable == 302_000


def test_a_file_the_index_would_skip_is_not_counted(monkeypatch):
    """Over MAX_FILE_BYTES the index skips the file whatever it holds, so it is free."""
    seen = _sizes(monkeypatch, [
        _blob("data/huge.jsonl", collector._MAX_INDEXED_FILE_BYTES + 1),
        _blob("data/small.jsonl", 1_000),
    ])
    assert seen[0].readable == 1_000


def test_an_extensionless_file_is_assumed_readable(monkeypatch):
    # LICENSE, Dockerfile, Makefile: no suffix, all text, all scanned.
    seen = _sizes(monkeypatch, [_blob("Dockerfile", 900), _blob("LICENSE", 1_100)])
    assert seen[0].readable == 2_000


def test_the_measurement_is_reported_only_for_a_scan_that_will_run(monkeypatch):
    """A refused repository reports nothing: there is no progress to show for it."""
    cap = collector._MAX_CLONE_MB
    _mock_github(monkeypatch, history_kb=1024, tree=[_blob("assets/v.mp4", (cap + 1) * MB)])
    seen: list[collector.TreeSize] = []
    with pytest.raises(SourceTooLargeError):
        collector._reject_if_too_large("https://github.com/o/r.git", on_size=seen.append)
    assert seen == []


def test_nothing_is_reported_when_the_api_cannot_answer(monkeypatch):
    """Rate-limited or truncated: the scan still runs, the caller simply gets no estimate."""
    _mock_github(monkeypatch, history_kb=1024, tree=None)
    seen: list[collector.TreeSize] = []
    collector._reject_if_too_large("https://github.com/o/r.git", on_size=seen.append)
    assert seen == []


def test_the_limit_is_still_applied_to_the_whole_tree(monkeypatch):
    """Guards the boundary between the two numbers.

    A repository of video is cheap to SCAN and still too big to CLONE. If the gate ever starts
    reading `readable`, this repository would be admitted and the 200 MB clone bound would mean
    nothing -- so the gate keeps reading `total` until that is a decision someone made on purpose.
    """
    cap = collector._MAX_CLONE_MB
    _mock_github(monkeypatch, history_kb=1024, tree=[
        _blob("assets/clip.mp4", (cap + 1) * MB),
        _blob("src/main.py", 1_000),
    ])
    with pytest.raises(SourceTooLargeError, match="working tree"):
        collector._reject_if_too_large("https://github.com/o/r.git")


def test_the_callback_is_optional_and_failure_free_without_it(monkeypatch):
    """The default path must behave exactly as it did before the callback existed."""
    _mock_github(monkeypatch, history_kb=1024, tree=[_blob("src/a.py", 10 * MB)])
    collector._reject_if_too_large("https://github.com/o/r.git")  # no raise, nothing to report
