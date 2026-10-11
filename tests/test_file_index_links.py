"""The index never follows a link out of the component, and it says what it could not read.

A symbolic link or a Windows junction inside a component can point anywhere on the machine that
runs the scan -- the home directory of whoever runs it -- so the walk does not enter or read one;
it records the link instead. A file the walk finds but cannot open is listed too: a report that
quietly skips it reads as "checked and clean".
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path

import pytest

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.file_index import FileIndex
from skilltotal.scanners.encrypted_archive import EncryptedArchiveScanner

SECRET_LINE = 'TOKEN = open(os.path.expanduser("~/.ssh/id_rsa")).read()'


def _layout(tmp_path: Path) -> tuple[Path, Path]:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.py").write_text("import os\n" + SECRET_LINE + "\n", encoding="utf-8")
    comp = tmp_path / "comp"
    comp.mkdir()
    (comp / "main.py").write_text("print('hello')\n", encoding="utf-8")
    return comp, outside


def _junction(target: Path, link: Path) -> None:
    if os.name != "nt":
        pytest.skip("junctions are a Windows feature")
    import _winapi

    _winapi.CreateJunction(str(target), str(link))


def _symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create symlinks here: {exc}")


def _report(comp: Path):
    return analyze_directory(comp, detect_component(comp, source=str(comp)))


def _assert_nothing_from_outside(report) -> None:
    for finding in report.findings:
        for evidence in finding.evidence:
            assert "private" not in evidence.file
            assert SECRET_LINE not in evidence.snippet


# --- 6. links ----------------------------------------------------------------------------------
def test_a_junction_out_of_the_component_is_not_followed(tmp_path):
    comp, outside = _layout(tmp_path)
    _junction(outside, comp / "vendor_link")
    index = FileIndex.build(comp)
    assert [f.relpath for f in index.files] == ["main.py"]
    assert index.links == ["vendor_link"]
    report = _report(comp)
    _assert_nothing_from_outside(report)
    notes = [n for n in report.needs_review if n.title == "Links not followed"]
    assert len(notes) == 1
    assert "vendor_link" in notes[0].reason


def test_symlinks_out_of_the_component_are_not_followed(tmp_path):
    comp, outside = _layout(tmp_path)
    _symlink(outside / "private.py", comp / "linked.py")
    _symlink(outside, comp / "linked_dir")
    index = FileIndex.build(comp)
    assert [f.relpath for f in index.files] == ["main.py"]
    assert index.links == ["linked.py", "linked_dir"]
    report = _report(comp)
    _assert_nothing_from_outside(report)
    notes = [n for n in report.needs_review if n.title == "Links not followed"]
    assert len(notes) == 1
    assert "linked.py" in notes[0].reason and "linked_dir" in notes[0].reason


def test_links_inside_a_skipped_directory_are_neither_walked_nor_reported(tmp_path):
    # pnpm fills node_modules with links; the directory is never read, so neither are they.
    comp, outside = _layout(tmp_path)
    (comp / "node_modules").mkdir()
    _junction(outside, comp / "node_modules" / "dep")
    index = FileIndex.build(comp)
    assert index.links == []
    assert [f.relpath for f in index.files] == ["main.py"]


def test_an_excluded_link_is_not_reported(tmp_path):
    comp, outside = _layout(tmp_path)
    _junction(outside, comp / "fixtures_link")
    assert FileIndex.build(comp, exclude=["fixtures_link"]).links == []


def test_a_linked_manifest_is_not_read(tmp_path):
    comp, outside = _layout(tmp_path)
    (outside / "package.json").write_text('{"name": "name-from-outside", "version": "6.6.6"}',
                                          encoding="utf-8")
    _symlink(outside / "package.json", comp / "package.json")
    component = detect_component(comp, source=str(comp))
    assert (component.name, component.version, component.type) == ("comp", "", "directory")


def test_a_manifest_name_on_a_junction_is_not_a_manifest(tmp_path):
    # `exists()` is true for a junction (or a directory) called SKILL.md; only a regular file of
    # that name makes the component an agent skill.
    comp, outside = _layout(tmp_path)
    _junction(outside, comp / "SKILL.md")
    assert detect_component(comp, source=str(comp)).type == "directory"


def test_the_encrypted_archive_check_does_not_follow_a_junction(tmp_path):
    import zipfile

    comp, outside = _layout(tmp_path)
    with zipfile.ZipFile(outside / "locked.zip", "w") as zf:
        zf.writestr("a.txt", "x")
    data = bytearray((outside / "locked.zip").read_bytes())
    data[data.find(b"PK\x03\x04") + 6] |= 0x01
    data[data.find(b"PK\x01\x02") + 8] |= 0x01
    (outside / "locked.zip").write_bytes(bytes(data))
    _junction(outside, comp / "vendor_link")
    assert EncryptedArchiveScanner().scan(FileIndex.build(comp)).findings == []


def test_a_deep_directory_tree_is_walked_without_recursion(tmp_path):
    # Built and removed one level at a time: pathlib's own mkdir(parents=True) and older
    # shutil.rmtree recurse, and would hit the recursion limit before the code under test does.
    comp = tmp_path / "c"
    comp.mkdir()
    levels = [comp]
    try:
        try:
            for _ in range(1100):
                levels.append(levels[-1] / "d")
                levels[-1].mkdir()
            (levels[-1] / "x.py").write_text("x = 1\n", encoding="utf-8")
        except OSError as exc:  # a Windows path past MAX_PATH without long-path support
            pytest.skip(f"cannot create a tree this deep here: {exc}")
        index = FileIndex.build(comp)
        assert [f.relpath for f in index.files] == ["/".join(["d"] * 1100 + ["x.py"])]
    finally:
        (levels[-1] / "x.py").unlink(missing_ok=True)
        for level in reversed(levels[1:]):
            if level.exists():
                level.rmdir()


# --- 3. files the walk found but could not read -------------------------------------------------
@contextmanager
def _unreadable(path: Path):
    """Make ``path`` unreadable to this process for the duration, with a real OS-level denial."""
    if os.name == "nt":
        import msvcrt

        fd = os.open(path, os.O_RDWR)
        size = max(1, path.stat().st_size)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, size)  # another handle can no longer read it
        try:
            yield
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, size)
            os.close(fd)
    else:
        if os.geteuid() == 0:
            pytest.skip("root reads a file whatever its mode")
        path.chmod(0)
        try:
            yield
        finally:
            path.chmod(0o644)


def test_an_unreadable_file_is_reported_not_passed_as_clean(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    locked = tmp_path / "locked.py"
    locked.write_text("import os\nos.system('id')\n", encoding="utf-8")
    with _unreadable(locked):
        index = FileIndex.build(tmp_path)
        report = _report(tmp_path)
    assert index.unreadable == ["locked.py"]
    notes = [n for n in report.needs_review if n.title == "Files could not be read"]
    assert len(notes) == 1
    assert "locked.py" in notes[0].reason


def test_unreadable_files_are_one_note_naming_the_first_few(tmp_path, monkeypatch):
    for i in range(8):
        (tmp_path / f"f{i}.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "readable.py").write_text("y = 2\n", encoding="utf-8")
    real_read = Path.read_bytes

    def deny(self: Path) -> bytes:
        if self.name.startswith("f"):
            raise PermissionError(13, "Permission denied", str(self))
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", deny)
    report = _report(tmp_path)
    notes = [n for n in report.needs_review if n.title == "Files could not be read"]
    assert len(notes) == 1
    assert notes[0].reason.startswith("8 file(s)")
    assert "f0.py" in notes[0].reason and "and 3 more" in notes[0].reason
    assert notes[0].file == "f0.py"


def test_a_directory_that_cannot_be_listed_is_reported(tmp_path, monkeypatch):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "private").mkdir()
    (tmp_path / "private" / "a.py").write_text("x = 2\n", encoding="utf-8")
    real_scandir = os.scandir

    def deny(path="."):
        if Path(path).name == "private":
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", deny)
    index = FileIndex.build(tmp_path)
    assert [f.relpath for f in index.files] == ["ok.py"]
    assert index.unreadable == ["private/"]
