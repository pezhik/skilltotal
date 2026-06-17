"""Install-time dropper correlation (ST-INSTALL-DROPPER)."""

from __future__ import annotations

from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory

_MALICIOUS = Path(__file__).parent / "manual_eval" / "malicious"


def _analyze(root: Path):
    return analyze_directory(root, detect_component(root, source=str(root)))


def _ids(report) -> set[str]:
    return {f.id for f in report.findings}


def test_postinstall_plus_credential_access_is_dropper():
    # npm-postinstall-exfil: package.json postinstall (ST-INSTALL-NPM) + collect.js reads ~/.aws
    # (ST-SENS-PATH) -> install-time dropper correlation.
    report = _analyze(_MALICIOUS / "npm-postinstall-exfil")
    assert "ST-INSTALL-DROPPER" in _ids(report)


def test_postinstall_plus_decode_exec_is_dropper(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"name":"x","version":"1.0.0","scripts":{"postinstall":"node s.js"}}\n',
        encoding="utf-8",
        newline="",
    )
    (tmp_path / "s.js").write_text("eval(atob('Zm9v'))\n", encoding="utf-8", newline="")
    assert "ST-INSTALL-DROPPER" in _ids(_analyze(tmp_path))


def test_install_hook_alone_is_not_dropper(tmp_path: Path):
    # A bare postinstall build step (no payload) must not be flagged a dropper.
    (tmp_path / "package.json").write_text(
        '{"name":"x","version":"1.0.0","scripts":{"postinstall":"node-gyp rebuild"}}\n',
        encoding="utf-8",
        newline="",
    )
    assert "ST-INSTALL-DROPPER" not in _ids(_analyze(tmp_path))


def test_decode_exec_without_install_hook_is_not_dropper(tmp_path: Path):
    (tmp_path / "s.js").write_text("eval(atob('Zm9v'))\n", encoding="utf-8", newline="")
    assert "ST-INSTALL-DROPPER" not in _ids(_analyze(tmp_path))
