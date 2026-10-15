"""Regexes that backtracked superlinearly on crafted input (found by fuzzing).

A scanned component chooses its own text, so a pattern that is quadratic (or worse) in the length
of a whitespace run, a name or a dotted chain lets a 2 MiB file hold a scan for hours. Each case
below is the shape that was slow, at 200,000 characters, called the way the scanner calls it; each
took seconds to minutes (or, for the list element, grew exponentially) before the pattern was
bounded. The limit is generous so a busy machine does not make the test flaky.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import Component
from skilltotal.scanners import (
    agent_config,
    exposure,
    npm_supply,
    secret_exfil,
    secrets,
    sensitive_paths,
)

N = 200_000
LIMIT = 2.0

CASES = {
    "secret_exfil._JS_MEMBER_READ": lambda: secret_exfil._JS_MEMBER_READ.match(
        "e" + "\n" * N + ";", 1
    ),
    "secret_exfil._JS_CALLEE (long name)": lambda: secret_exfil._JS_CALLEE.search(
        "a" * N + "!", 0, N + 1
    ),
    "secret_exfil._JS_CALLEE (long blank run)": lambda: secret_exfil._JS_CALLEE.search(
        "a " * (N // 2) + "!", 0, N + 1
    ),
    "agent_config._CALLEE": lambda: agent_config._CALLEE.search("a." * (N // 2) + "!", 0, N + 1),
    "exposure._BIND_KEYWORD": lambda: exposure._BIND_KEYWORD.search("host" * (N // 4) + "_"),
    "npm_supply._SHELL_PUBLISH (blanks)": lambda: list(
        npm_supply._SHELL_PUBLISH.finditer(";" + " " * N + "x")
    ),
    "npm_supply._SHELL_PUBLISH (newlines)": lambda: list(
        npm_supply._SHELL_PUBLISH.finditer("\n" * N + "x")
    ),
    "npm_supply._SHELL_PUBLISH (path)": lambda: list(
        npm_supply._SHELL_PUBLISH.finditer("|" + "a/" * (N // 2) + "x")
    ),
    "sensitive_paths._BARE_LIST_ELEMENT (trailing blanks)": lambda: (
        sensitive_paths._BARE_LIST_ELEMENT.match('"~/.ssh/id_rsa"' + " " * N + "!")
    ),
    "sensitive_paths._BARE_LIST_ELEMENT (numbers)": lambda: (
        sensitive_paths._BARE_LIST_ELEMENT.match("01," * (N // 3) + "x")
    ),
    "sensitive_paths._BARE_REGEX_ELEMENT": lambda: (
        sensitive_paths._BARE_REGEX_ELEMENT.match("/a/" + " " * N + "!")
    ),
    "secrets._TELEMETRY_INGEST_CTX": lambda: secrets._TELEMETRY_INGEST_CTX.search(
        "telemetry" + "a." * (N // 2)
    ),
    "secrets._TELEMETRY_INGEST_CTX (repeated)": lambda: secrets._TELEMETRY_INGEST_CTX.search(
        "telemetry." * (N // 10)
    ),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_pattern_is_linear_on_crafted_input(name):
    started = time.perf_counter()
    CASES[name]()
    elapsed = time.perf_counter() - started
    assert elapsed < LIMIT, f"{name}: {elapsed:.2f}s on {N:,} characters"


def test_a_name_followed_by_many_blank_lines_does_not_stall_the_scan(tmp_path: Path):
    # The audit's reproduction: a JavaScript environment alias, 40,000 newlines, then a request.
    body = "const e = process.env;\nconst u = e" + "\n" * 40_000 + ";fetch(u);\n"
    (tmp_path / "index.js").write_text(body, encoding="utf-8")
    started = time.perf_counter()
    analyze_directory(tmp_path, Component(name="x", type="local", source=str(tmp_path)))
    assert time.perf_counter() - started < 20


def test_bounded_patterns_still_match_what_they_matched():
    assert secret_exfil._JS_MEMBER_READ.match(" .TOKEN", 0)
    assert secret_exfil._JS_MEMBER_READ.match("?.['TOKEN']", 0)
    assert secret_exfil._JS_MEMBER_READ.match(" [k]", 0)
    assert not secret_exfil._JS_MEMBER_READ.match(".toString()", 0)
    text = "x = JSON.stringify("
    m = secret_exfil._JS_CALLEE.search(text, 0, len(text) - 1)
    assert m and m.group(1) == "stringify"
    text = "fs . writeFileSync ("
    m = agent_config._CALLEE.search(text, 0, len(text) - 1)
    assert m and m.group(1) == "fs . writeFileSync"
    assert exposure._BIND_KEYWORD.search("server_hostname")
    assert not exposure._BIND_KEYWORD.search("port")
    assert npm_supply._SHELL_PUBLISH.search("  npm publish --access public")
    assert npm_supply._SHELL_PUBLISH.search("cd pkg && ./node_modules/.bin/npm publish")
    assert npm_supply._SHELL_PUBLISH.search("if ok; then npm publish; fi")
    for line in ('"~/.ssh/id_rsa",', "['~/.ssh', '~/.aws'],", "0x1f, 012, 7: '~/.ssh/x'",
                 "'~/.ssh/id_rsa'.to_string(),", "('~/.ssh', 1) => deny,"):
        assert sensitive_paths._BARE_LIST_ELEMENT.match(line), line
    assert not sensitive_paths._BARE_LIST_ELEMENT.match('open("~/.ssh/id_rsa")')
    assert sensitive_paths._BARE_REGEX_ELEMENT.match(r"/\.ssh\/id_rsa/i ,")
    assert secrets._TELEMETRY_INGEST_CTX.search("https://x.client-telemetry.example/enqueue")
    assert secrets._TELEMETRY_INGEST_CTX.search("https://telemetry-in.example.test/ingest")
