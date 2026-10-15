"""A static scanner must not be DoS-able by the component it scans: a crafted input must never
make a detection regex backtrack catastrophically (which would both hang the hosted scanner and
let the input evade analysis by timing out). These inputs target the bounded quantifiers added
with the 2026 evasion rules. Most of these scans take milliseconds; the largest input (a 400 KB
line) takes about two seconds of linear regex work.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from skilltotal.concat_normalize import fold_string_concats
from skilltotal.engine import analyze_directory
from skilltotal.models import Component

# Generous ceiling: bounded quantifiers finish in milliseconds (the 400 KB line in about two
# seconds), and a pattern that backtracked on the crafted length would run for minutes or wedge.
# Three seconds failed on a busy machine (a release gate running beside other jobs, 2026-10-15)
# without any pattern having changed.
_BUDGET_S = 8.0


def _scan_fast(tmp_path: Path, filename: str, text: str) -> None:
    (tmp_path / filename).write_text(text, encoding="utf-8")
    start = time.perf_counter()
    analyze_directory(tmp_path, Component(name="x", type="directory", source=str(tmp_path)))
    assert time.perf_counter() - start < _BUDGET_S, f"{filename} scan exceeded {_BUDGET_S}s"


def test_env_secret_name_pathological(tmp_path: Path):
    # process.env. + a long identifier run that never contains a wallet word.
    _scan_fast(tmp_path, "a.js", "const k = process.env." + "A" * 200_000 + ";\n")


def test_concat_gate_pathological_whitespace(tmp_path: Path):
    # A quote followed by a megabyte of whitespace and no closing quote: the fold pre-check must
    # not backtrack over it.
    _scan_fast(tmp_path, "b.js", 'const s = "' + " " * 500_000 + "\n")


def test_fold_pathological_whitespace_is_fast():
    # Exercise the normalizer directly as well.
    text = '"' + " " * 500_000 + '"'
    start = time.perf_counter()
    fold_string_concats(text, ".js")
    assert time.perf_counter() - start < _BUDGET_S


def test_git_persist_pathological_long_line(tmp_path: Path):
    # `git config` followed by a very long line that never reaches core.hooksPath/templateDir.
    _scan_fast(tmp_path, "c.js", "git config " + "x " * 200_000 + "\n")


def test_client_config_codeium_pathological(tmp_path: Path):
    # `.codeium/` + a long non-space run that never ends in mcp*.json.
    _scan_fast(tmp_path, "d.js", "writeFileSync('.codeium/" + "x" * 200_000 + "');\n")


def test_skill_dynamic_command_pathological_long_line(tmp_path: Path):
    md = "---\nname: x\nallowed-tools: Bash(*)\n---\n# x\n\n!" + "a " * 200_000 + "\n"
    _scan_fast(tmp_path, "SKILL.md", md)


@pytest.mark.parametrize("n", [50_000, 200_000])
def test_write_sink_open_pathological(tmp_path: Path, n: int):
    _scan_fast(tmp_path, f"e{n}.js", "open(" + "x" * n + "\n")
