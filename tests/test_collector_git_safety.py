"""A repository being cloned for a scan cannot steer git: no LFS downloads it names, and a
folder name from a URL is always a path, never an option."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from skilltotal import collector
from skilltotal.collector import CollectionError


def test_a_clone_never_runs_the_lfs_download_filter(monkeypatch):
    # With git-lfs installed, checking out a repository fetches its LFS objects from wherever the
    # repository's own .lfsconfig says: a URL the scanned project chooses, fetched by the scanner.
    seen: dict = {}

    def fake_run_git(args, dest, env, url):
        seen["env"] = env
        raise CollectionError("stop here")

    monkeypatch.setattr(collector.shutil, "which", lambda name: "git")
    monkeypatch.setattr(collector, "_reject_if_too_large", lambda *a, **k: None)
    monkeypatch.setattr(collector, "_run_git", fake_run_git)
    with pytest.raises(CollectionError, match="stop here"):
        collector.collect("https://github.com/owner/repo")
    assert seen["env"]["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0"


def test_every_git_command_of_a_clone_gets_the_same_environment(monkeypatch, tmp_path):
    envs = []

    def fake_run_git(args, dest, env, url):
        envs.append(env)
        Path(dest).mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(collector, "_run_git", fake_run_git)
    monkeypatch.setattr(collector, "_git", lambda dest, args, env, *, timeout: envs.append(env))
    env = {"GIT_LFS_SKIP_SMUDGE": "1"}
    collector._clone("https://github.com/o/r", "a" * 40, "skills/x", tmp_path / "repo", env, "u")
    assert len(envs) == 4 and all(e is env for e in envs)


@pytest.mark.parametrize("subpath", ["-x", "--output=/tmp/x", "skills/x"])
def test_a_subfolder_is_passed_to_git_as_a_path_not_an_option(monkeypatch, tmp_path, subpath):
    seen = []
    monkeypatch.setattr(collector, "_run_git",
                        lambda args, dest, env, url: Path(dest).mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(collector, "_git", lambda dest, args, env, *, timeout: seen.append(args))
    collector._clone("https://github.com/o/r", None, subpath, tmp_path / "repo", {}, "url")
    assert seen == [["sparse-checkout", "set", "--end-of-options", subpath]]


def _repo_with_dash_folder(root: Path) -> Path:
    repo = root / "origin"
    repo.mkdir()
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}

    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)

    git("init", "-q", "-b", "main")
    (repo / "-x").mkdir()
    (repo / "-x" / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    (repo / "other").mkdir()
    (repo / "other" / "y.txt").write_text("y\n", encoding="utf-8")
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    return repo


@pytest.mark.skipif(shutil.which("git") is None, reason="git not on PATH")
def test_a_folder_named_like_an_option_is_checked_out(tmp_path):
    # `github.com/o/r/tree/main/-x` links a folder called "-x"; git used to read it as a switch.
    repo = _repo_with_dash_folder(tmp_path)
    dest = tmp_path / "clone"
    collector._clone(repo.as_uri(), None, "-x", dest, dict(os.environ),
                     "https://example.test/o/r/tree/main/-x")
    assert (dest / "-x" / "SKILL.md").is_file()
    assert not (dest / "other" / "y.txt").exists()
