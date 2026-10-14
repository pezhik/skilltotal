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
    ("failed to fetch https://example.invalid/x: timed out", None),
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
