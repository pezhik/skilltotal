"""Browser-URL parsing + big-repo guards in the collector."""

from __future__ import annotations

import json

import pytest

from skilltotal import collector
from skilltotal.collector import (
    CollectionError,
    SourceTooLargeError,
    npm_package_name,
    parse_git_url,
    pypi_package_name,
)


# --- parse_git_url ------------------------------------------------------------
def test_repo_root():
    assert parse_git_url("https://github.com/owner/repo") == (
        "https://github.com/owner/repo.git", None, None, None
    )


def test_repo_root_with_git_suffix_passes_through():
    # Already a clone URL -> unchanged, nothing to parse.
    assert parse_git_url("https://github.com/owner/repo.git") == (
        "https://github.com/owner/repo.git", None, None, None
    )


def test_tree_branch_and_subpath():
    clone, ref, sub, note = parse_git_url("https://github.com/owner/repo/tree/dev/src/pkg")
    assert clone == "https://github.com/owner/repo.git"
    assert ref == "dev" and sub == "src/pkg" and note is None


def test_blob_file_scans_its_folder():
    clone, ref, sub, note = parse_git_url("https://github.com/owner/repo/blob/main/a/b/x.py")
    assert ref == "main" and sub == "a/b" and note is None


def test_commit_sha():
    clone, ref, sub, note = parse_git_url("https://github.com/o/r/commit/abc123def456")
    assert ref == "abc123def456" and sub is None and note is None


def test_non_code_page_reduced_to_repo_root_with_note():
    clone, ref, sub, note = parse_git_url("https://github.com/pezhik/skilltotal/issues")
    assert clone == "https://github.com/pezhik/skilltotal.git"
    assert ref is None and sub is None
    assert note and "issues" in note and "default branch" in note


def test_gitlab_tree():
    clone, ref, sub, note = parse_git_url("https://gitlab.com/grp/proj/-/tree/main/lib")
    assert clone == "https://gitlab.com/grp/proj.git" and ref == "main" and sub == "lib"


def test_ssh_and_bare_urls_pass_through():
    assert parse_git_url("git@github.com:owner/repo.git")[0] == "git@github.com:owner/repo.git"
    assert parse_git_url("https://example.com/x/y")[0] == "https://example.com/x/y"


# --- pre-clone size guard -----------------------------------------------------
class _FakeResp:
    def __init__(self, payload: bytes):
        self._p = payload

    def read(self, _n: int = -1) -> bytes:
        return self._p

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def _mock_github_size(monkeypatch, size_kb: int):
    payload = json.dumps({"size": size_kb}).encode()
    monkeypatch.setattr(
        collector.urllib.request, "urlopen", lambda *_a, **_k: _FakeResp(payload)
    )


def test_pre_check_rejects_oversized_repo(monkeypatch):
    _mock_github_size(monkeypatch, (collector._MAX_CLONE_MB + 50) * 1024)
    with pytest.raises(SourceTooLargeError):  # a CollectionError subclass
        collector._reject_if_too_large("https://github.com/o/r.git")


# --- ASCII-only package-name validation (stops input reflection at the registry) -------------
def test_ascii_package_names_accepted():
    assert npm_package_name("npm:azure-iothub-service-client") == "azure-iothub-service-client"
    assert pypi_package_name("pypi:requests") == "requests"


def test_non_ascii_package_names_rejected():
    # cyrillic / specials must NOT pass validation (so they never reach the registry URL)
    assert npm_package_name("npm:azure-iothub-service-clientпав") is None
    assert pypi_package_name("pypi:requestsпав") is None


def test_pre_check_allows_small_repo(monkeypatch):
    _mock_github_size(monkeypatch, 2048)  # ~2 MB
    collector._reject_if_too_large("https://github.com/o/r.git")  # no raise


def test_pre_check_skips_non_github():
    # No network call should happen for non-GitHub hosts.
    collector._reject_if_too_large("https://gitlab.com/o/r.git")


def test_pre_check_silent_on_api_error(monkeypatch):
    def boom(*_a, **_k):
        raise OSError("rate limited")

    monkeypatch.setattr(collector.urllib.request, "urlopen", boom)
    collector._reject_if_too_large("https://github.com/o/r.git")  # swallowed -> watchdog covers


# --- mid-clone watchdog -------------------------------------------------------
def test_watchdog_aborts_oversized_clone(monkeypatch, tmp_path):
    monkeypatch.setattr(collector, "_CLONE_POLL_SECONDS", 0.01)
    monkeypatch.setattr(
        collector, "_dir_size_bytes", lambda _root: collector._MAX_CLONE_MB * 1024 * 1024 + 1
    )

    class _FakeProc:
        def __init__(self):
            self._alive = True
            self.returncode = 0

        def poll(self):
            return None if self._alive else self.returncode

        def kill(self):
            self._alive = False
            self.returncode = -9

        def communicate(self, timeout=None):
            import time as _t

            for _ in range(500):
                if not self._alive:
                    break
                _t.sleep(0.01)
            return ("", "killed by watchdog")

    monkeypatch.setattr(collector.subprocess, "Popen", lambda *_a, **_k: _FakeProc())
    dest = tmp_path / "repo"
    dest.mkdir()
    with pytest.raises(CollectionError, match="exceeds"):
        collector._run_git(["git", "clone", "x", str(dest)], dest, {}, "https://github.com/o/r")
