"""The npm package (npm/) is a thin runner for this engine and must stay in step with it."""

from __future__ import annotations

import json
from pathlib import Path

import skilltotal

ROOT = Path(__file__).resolve().parents[1]
NPM = ROOT / "npm"
PKG = json.loads((NPM / "package.json").read_text(encoding="utf-8"))


def test_the_npm_version_is_the_engine_version():
    # uvx/pipx run `skilltotal==<npm version>` from PyPI, so the two must name the same release.
    assert PKG["version"] == skilltotal.__version__


def test_it_ships_no_install_scripts_and_no_dependencies():
    # A security tool must not run anything at install time or pull a dependency tree.
    scripts = PKG.get("scripts", {})
    for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
        assert hook not in scripts, hook
    for key in ("dependencies", "optionalDependencies", "peerDependencies", "bundleDependencies"):
        assert key not in PKG, key


def test_it_publishes_only_the_runner():
    assert PKG["files"] == ["bin/", "lib/", "README.md", "LICENSE"]
    assert PKG["bin"] == {"skilltotal": "bin/skilltotal.js"}
    for rel in ("bin/skilltotal.js", "lib/runner.js", "README.md", "LICENSE"):
        assert (NPM / rel).is_file(), rel


def test_the_license_is_the_repository_license():
    assert (NPM / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    assert PKG["license"] == "Apache-2.0"
