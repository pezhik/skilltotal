"""Local source collection: project archives (zip/tar.gz) and single code files."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from skilltotal import collector
from skilltotal.collector import CollectionError, collect
from skilltotal.engine import analyze_directory


def _zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _tgz_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _write(tmp_path: Path, name: str, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_collect_zip_project_and_scan(tmp_path):
    data = _zip_bytes(
        {
            "shop/package.json": '{"name":"shop","version":"1.0.0"}',
            "shop/index.js": "const cp=require('child_process'); cp.exec('whoami')\n",
        }
    )
    src = _write(tmp_path, "shop.zip", data)
    with collect(src) as ctx:
        assert ctx.root.is_dir()
        report = analyze_directory(ctx.root, ctx.component)
    # Display source is the archive filename, never the temp path.
    assert ctx.component.source == "shop.zip"
    # The existing Node scanner runs on the extracted project.
    assert any(f.id == "ST-SHELL-NODE" for f in report.findings)


def test_collect_targz_python_project(tmp_path):
    data = _tgz_bytes({"app/main.py": "import subprocess\nsubprocess.run(['id'])\n"})
    src = _write(tmp_path, "app.tar.gz", data)
    with collect(src) as ctx:
        report = analyze_directory(ctx.root, ctx.component)
    assert any(f.id == "ST-SHELL-PY" for f in report.findings)


def test_collect_single_file(tmp_path):
    src = _write(tmp_path, "evil.py", b"import os\nos.system('rm -rf /tmp/x')\n")
    with collect(src) as ctx:
        assert ctx.component.source == "evil.py"
        assert ctx.component.type == "project"
        report = analyze_directory(ctx.root, ctx.component)
    assert any(f.id == "ST-SHELL-PY" for f in report.findings)


def test_zip_slip_is_rejected(tmp_path):
    src = _write(tmp_path, "evil.zip", _zip_bytes({"../escape.txt": "x"}))
    with pytest.raises(CollectionError):
        collect(src)


def test_too_many_members_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "_MAX_ARCHIVE_MEMBERS", 3)
    files = {f"p/f{i}.txt": "x" for i in range(10)}
    src = _write(tmp_path, "many.zip", _zip_bytes(files))
    with pytest.raises(CollectionError):
        collect(src)


def test_oversize_archive_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "_MAX_ARCHIVE_BYTES", 16)
    src = _write(tmp_path, "big.zip", _zip_bytes({"a/x.txt": "hello world " * 50}))
    with pytest.raises(CollectionError):
        collect(src)


def test_project_type_labels(tmp_path):
    go = _write(tmp_path, "g.zip", _zip_bytes({"svc/go.mod": "module svc\n"}))
    with collect(go) as ctx:
        assert ctx.component.type == "go_project"
    java = _write(tmp_path, "j.zip", _zip_bytes({"api/pom.xml": "<project/>"}))
    with collect(java) as ctx:
        assert ctx.component.type == "java_project"
