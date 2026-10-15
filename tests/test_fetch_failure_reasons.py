"""Why a source could not be fetched, said in fixed words: no git, no such package, no such
repository. The hook used to say only "the scan failed", and the CLI printed git's own "could not
read Username" for a repository that does not exist."""

from __future__ import annotations

import pytest

from skilltotal import hook_scan
from skilltotal.agent_hook import hook_response
from skilltotal.collector import FAILURE_CATEGORIES, CollectionError, failure_category


@pytest.mark.parametrize(("message", "category"), [
    ("git is required to analyze remote URLs but was not found on PATH.", "git-missing"),
    ("failed to fetch https://registry.npmjs.org/nope: HTTP Error 404: Not Found", "not-found"),
    ("npm package 'left-pad' has no version '9.9.9'", "not-found"),
    ("PyPI project 'x' has no downloadable distribution", "not-found"),
    ("git clone failed for https://github.com/o/r: fatal: could not read Username for "
     "'https://github.com': terminal prompts disabled", "repo-not-found"),
    ("git clone failed for https://github.com/o/r: remote: Repository not found.",
     "repo-not-found"),
    # Offline or a registry that does not answer: the network reason, briefly (audit 2026-10-15).
    ("failed to fetch https://example.invalid/x: timed out", "timeout"),
    ("failed to fetch https://registry.npmjs.org/x: <urlopen error [Errno 11001] getaddrinfo "
     "failed>", "offline"),
    ("failed to fetch https://pypi.org/pypi/x/json: <urlopen error [Errno -3] Temporary failure "
     "in name resolution>", "offline"),
    ("failed to fetch https://registry.npmjs.org/x: <urlopen error [WinError 10061] No "
     "connection could be made because the target machine actively refused it>", "offline"),
    ("failed to fetch https://registry.npmjs.org/x: <urlopen error [Errno 111] Connection "
     "refused>", "offline"),
    ("git clone failed for https://github.com/o/r: fatal: unable to access "
     "'https://github.com/o/r/': Could not resolve host: github.com", "offline"),
    ("failed to fetch https://registry.npmjs.org/x: HTTP Error 503: Service Unavailable",
     "registry-error"),
    ("failed to fetch https://registry.npmjs.org/x: HTTP Error 429: Too Many Requests",
     "registry-error"),
    ("archive could not be read: it is damaged", None),
])
def test_a_fetch_failure_has_a_fixed_category(message, category):
    assert failure_category(CollectionError(message)) == category


def test_the_hook_reads_only_categories_it_knows(tmp_path):
    (tmp_path / "why").write_text("not-found", encoding="ascii")
    assert hook_scan._read_why(tmp_path / "why") == "not-found"
    (tmp_path / "why").write_text("$(rm -rf ~)", encoding="ascii")
    assert hook_scan._read_why(tmp_path / "why") is None
    assert hook_scan._read_why(tmp_path / "missing") is None


@pytest.mark.parametrize("category", sorted(FAILURE_CATEGORIES))
def test_the_person_is_told_why_instead_of_the_scan_failed(category):
    def scan(source, timeout):
        raise hook_scan.ScanFailed(category)

    out = hook_response({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                         "tool_input": {"command": "npm install left-pad"}}, scan=scan)
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert FAILURE_CATEGORIES[category] in reason
    assert "the scan failed" not in reason
