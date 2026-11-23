"""Dependency sources in files a component ships, and two manifest checks.

* ``ST-DEP-FOREIGN-SOURCE`` (risky construct): a lockfile address on a host that is neither a
  public registry nor one the component's own ``.npmrc`` declares; a shipped package-manager
  config that uses plain http or turns certificate checks off.
* ``ST-DEP-REGISTRY-LOOKALIKE`` (malicious indicator): the host imitates a public registry.
* ``ST-NPM-URL-DEP`` / ``ST-NPM-GIT-DEP`` also read ``overrides`` / ``resolutions`` /
  ``pnpm.overrides``.
* ``ST-NPM-BIN-SHADOW``: ``bin`` installs a core tool's name.
* ``ST-AGENT-AUTO-APPROVE`` also reads the frontmatter of a skill, command or subagent.

Hosts are ``.invalid`` / ``example.com`` except the public registries themselves; nothing here is
fetched.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import Component, ThreatClass
from skilltotal.rules import get_rules
from skilltotal.scanners.dependency_source import _NPM_IMITATED, _NPM_PUBLIC, imitates

FOREIGN = "ST-DEP-FOREIGN-SOURCE"
LOOKALIKE = "ST-DEP-REGISTRY-LOOKALIKE"
URL_DEP = "ST-NPM-URL-DEP"
GIT_DEP = "ST-NPM-GIT-DEP"
BIN_SHADOW = "ST-NPM-BIN-SHADOW"
AUTO_APPROVE = "ST-AGENT-AUTO-APPROVE"
REVIEW_TITLE = "Shipped package-manager config sets a non-default registry"
NPM = "https://registry.npmjs.org"
CORP = "https://npm.corp.example.com"
FAKE = "https://registry.npmjs.org.pkg-mirror.invalid"


def _write(root: Path, files: dict[str, object]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_text(text, encoding="utf-8")
    return root


def _report(root: Path):
    return analyze_directory(root, Component(name="x", type="directory", source=str(root)))


def _ids(root: Path) -> set[str]:
    return {f.id for f in _report(root).findings}


def _lock(*entries: tuple[str, str]) -> dict:
    packages: dict = {"": {"name": "app", "version": "1.0.0"}}
    for name, host in entries:
        base = name.rsplit("/", 1)[-1]
        packages[f"node_modules/{name}"] = {
            "version": "1.0.0", "resolved": f"{host}/{name}/-/{base}-1.0.0.tgz"}
    return {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}


def _yarn_lock(url: str) -> str:
    return f'# yarn lockfile v1\n\nlodash@^4.17.21:\n  version "4.17.21"\n  resolved "{url}#abc"\n'


# --- the rules
def test_threat_classes():
    rules = {r.id: r for r in get_rules()}
    assert rules[FOREIGN].threat_class is ThreatClass.RISKY_CONSTRUCT
    assert rules[LOOKALIKE].threat_class is ThreatClass.MALICIOUS_INDICATOR
    assert rules[BIN_SHADOW].threat_class is ThreatClass.RISKY_CONSTRUCT


# --- lockfiles
@pytest.mark.parametrize("name", ["package-lock.json", "npm-shrinkwrap.json"])
def test_lock_entry_on_a_foreign_host_is_named_not_judged(tmp_path, name):
    _write(tmp_path, {name: _lock(("lodash", NPM), ("qs", "https://cdn.example.invalid"))})
    report = _report(tmp_path)
    finding = next(f for f in report.findings if f.id == FOREIGN)
    assert [e.line_start for e in finding.evidence] and "cdn.example.invalid" in (
        finding.evidence[0].snippet)
    assert not report.verdict["has_malicious_indicators"]
    assert report.risk_level.value == "low"


def test_yarn_and_pnpm_locks(tmp_path):
    _write(tmp_path, {
        "yarn.lock": _yarn_lock("http://cdn.example.invalid/lodash/-/lodash-4.17.21.tgz"),
        "pnpm-lock.yaml": "packages:\n  /qs@6.11.0:\n    resolution: {integrity: sha512-x, "
                          "tarball: https://cdn2.example.invalid/qs/-/qs-6.11.0.tgz}\n",
    })
    finding = next(f for f in _report(tmp_path).findings if f.id == FOREIGN)
    assert {e.file for e in finding.evidence} == {"yarn.lock", "pnpm-lock.yaml"}


def test_one_piece_of_evidence_per_host(tmp_path):
    entries = [(f"pkg{i}", "https://cdn.example.invalid") for i in range(50)]
    _write(tmp_path, {"package-lock.json": _lock(*entries)})
    finding = next(f for f in _report(tmp_path).findings if f.id == FOREIGN)
    assert len(finding.evidence) == 1


@pytest.mark.parametrize("host", [
    NPM, "https://registry.yarnpkg.com", "https://registry.npmmirror.com",
    "http://registry.npmjs.org", "https://npm.pkg.github.com", "https://codeload.github.com",
    "http://localhost:4873",
    # The open cloud mirrors NextChat and trueAI resolve through (registry diff 2026-11-22).
    "https://mirrors.huaweicloud.com/repository/npm", "http://mirrors.tencentyun.com/npm",
    "https://mirrors.cloud.tencent.com/npm",
])
def test_public_registries_mirrors_git_hosts_and_this_machine_are_silent(tmp_path, host):
    _write(tmp_path, {"package-lock.json": _lock(("lodash", host), ("qs", NPM))})
    assert _report(tmp_path).findings == []


def test_private_registry_declared_in_npmrc_is_silent(tmp_path):
    _write(tmp_path, {
        ".npmrc": f"registry={CORP}/\n",
        "package-lock.json": _lock(("lodash", CORP), ("qs", CORP)),
    })
    report = _report(tmp_path)
    assert report.findings == []
    # The https redirect itself is listed for review, never scored.
    assert [n.title for n in report.needs_review] == [REVIEW_TITLE]


def test_scoped_registry_declares_its_host_and_is_not_reported_at_all(tmp_path):
    _write(tmp_path, {
        ".npmrc": f"@corp:registry={CORP}/\n",
        "package-lock.json": _lock(("lodash", NPM), ("@corp/ui", CORP)),
    })
    report = _report(tmp_path)
    assert report.findings == [] and report.needs_review == []


def test_registry_declared_only_in_a_comment_does_not_count(tmp_path):
    _write(tmp_path, {
        ".npmrc": f"# registry={CORP}/\n",
        "package-lock.json": _lock(("lodash", CORP)),
    })
    assert FOREIGN in _ids(tmp_path)


def test_lookalike_host_in_a_lock_is_a_malicious_indicator(tmp_path):
    _write(tmp_path, {"package-lock.json": _lock(("lodash", NPM), ("qs", FAKE))})
    report = _report(tmp_path)
    assert {f.id for f in report.findings} == {LOOKALIKE}
    assert report.verdict["has_malicious_indicators"]


def test_declaring_a_lookalike_in_npmrc_does_not_excuse_it(tmp_path):
    _write(tmp_path, {".npmrc": f"registry={FAKE}/\n",
                      "package-lock.json": _lock(("qs", FAKE))})
    finding = next(f for f in _report(tmp_path).findings if f.id == LOOKALIKE)
    assert {e.file for e in finding.evidence} == {".npmrc", "package-lock.json"}


@pytest.mark.parametrize("host", [
    "registry.npmjs.org.pkg-mirror.invalid", "cdn.registry.npmjs.org.pkg.invalid",
    "registry.npmjs.org-cdn.invalid", "registry.npmjs.orq", "registry.npnjs.org",
    "registry.yarnpkg.com.mirror.invalid",
])
def test_hosts_that_imitate_a_registry(host):
    assert imitates(host, _NPM_IMITATED, _NPM_PUBLIC)


@pytest.mark.parametrize("host", [
    "registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com", "registry.npmmirror.com",
    "replicate.registry.npmjs.org", "npm.corp.example.com", "artifactory.example.com",
    "registry.example.com", "",
])
def test_hosts_that_do_not(host):
    assert not imitates(host, _NPM_IMITATED, _NPM_PUBLIC)


# --- package-manager config files
def test_npmrc_plain_http_with_tls_off_is_a_risky_construct(tmp_path):
    _write(tmp_path, {".npmrc": "registry=http://npm.example.invalid/\nstrict-ssl=false\n"})
    finding = next(f for f in _report(tmp_path).findings if f.id == FOREIGN)
    assert [e.line_start for e in finding.evidence] == [1, 2]


def test_npmrc_tls_off_alone_is_reported(tmp_path):
    _write(tmp_path, {".npmrc": "save-exact=true\nstrict-ssl = false\n"})
    assert _ids(tmp_path) == {FOREIGN}


def test_npmrc_https_redirect_is_review_only(tmp_path):
    _write(tmp_path, {".npmrc": f"registry={CORP}/\nalways-auth=true\n"})
    report = _report(tmp_path)
    assert report.findings == []
    assert [n.title for n in report.needs_review] == [REVIEW_TITLE]


@pytest.mark.parametrize("text", [
    "save-exact=true\nengine-strict=true\n",
    "registry=https://registry.npmjs.org/\n",
    f"@corp:registry={CORP}/\n//npm.corp.example.com/:always-auth=true\n",
    "# registry=http://npm.example.invalid/\n; strict-ssl=false\n",
    "registry=http://localhost:4873/\n",
])
def test_honest_npmrc_is_silent(tmp_path, text):
    _write(tmp_path, {".npmrc": text})
    report = _report(tmp_path)
    assert report.findings == [] and report.needs_review == []


def test_yarnrc_yml_scoped_server_is_silent_and_top_level_http_is_reported(tmp_path):
    _write(tmp_path, {".yarnrc.yml": (
        "npmScopes:\n  corp:\n    npmRegistryServer: \"http://npm.corp.example.com\"\n")})
    assert _report(tmp_path).findings == []
    _write(tmp_path, {".yarnrc.yml": 'npmRegistryServer: "http://npm.example.invalid"\n'})
    assert _ids(tmp_path) == {FOREIGN}


@pytest.mark.parametrize("name, text", [
    ("pip.conf", "[global]\nextra-index-url = http://pkgs.example.invalid/simple\n"),
    ("pip.conf", "[global]\nindex-url = https://pkgs.example.invalid/simple\n"
                 "trusted-host = pkgs.example.invalid\n"),
    (".pypirc", "[distutils]\nindex-servers = x\n\n[x]\nrepository = http://up.example.invalid/\n"),
    ("uv.toml", '[[index]]\nurl = "http://pkgs.example.invalid/simple"\n'),
])
def test_python_configs_with_http_or_tls_off(tmp_path, name, text):
    _write(tmp_path, {name: text})
    assert _ids(tmp_path) == {FOREIGN}


@pytest.mark.parametrize("name, text", [
    ("pip.conf", "[global]\nindex-url = https://pypi.org/simple\ntimeout = 60\n"),
    ("pip.conf", "[global]\ntrusted-host = pypi.org\n"),
    (".pypirc", "[pypi]\nrepository = https://upload.pypi.org/legacy/\nusername = __token__\n"),
    ("uv.toml", 'index-url = "https://pypi.org/simple"\n'),
])
def test_honest_python_configs_are_silent(tmp_path, name, text):
    _write(tmp_path, {name: text})
    report = _report(tmp_path)
    assert report.findings == [] and report.needs_review == []


def test_python_config_https_redirect_is_review_only_and_lookalike_is_malicious(tmp_path):
    _write(tmp_path, {"pip.conf": "[global]\nindex-url = https://pkgs.example.com/simple\n"})
    report = _report(tmp_path)
    assert report.findings == [] and [n.title for n in report.needs_review] == [REVIEW_TITLE]
    _write(tmp_path, {"pip.conf": "[global]\nindex-url = https://pypi.org.pkg.invalid/simple\n"})
    assert _ids(tmp_path) == {LOOKALIKE}


# --- overrides / resolutions
def test_overrides_and_resolutions_pointing_at_a_url_or_git(tmp_path):
    _write(tmp_path, {"package.json": {
        "name": "app", "version": "1.0.0",
        "overrides": {"express": {"debug": "https://cdn.example.invalid/debug-4.3.4.tgz"}},
        "resolutions": {"ms": "git+https://git.example.invalid/ms.git"},
        "pnpm": {"overrides": {"qs": "https://cdn.example.invalid/qs-6.11.0.tgz"}},
    }})
    by_id = {f.id: f for f in _report(tmp_path).findings}
    assert set(by_id) == {URL_DEP, GIT_DEP}
    assert sorted(e.snippet.split('"')[1] for e in by_id[URL_DEP].evidence) == ["debug", "qs"]
    assert '"ms"' in by_id[GIT_DEP].evidence[0].snippet


def test_honest_overrides_are_silent(tmp_path):
    _write(tmp_path, {"package.json": {
        "name": "app", "version": "1.0.0",
        "overrides": {"semver": "^7.6.0", "ui": "file:./packages/ui", "a": {".": "1.0.0"},
                      "b": "$b", "c": f"{NPM}/c/-/c-1.0.0.tgz"},
        "resolutions": {"**/minimist": "1.2.8", "left-pad": "npm:lpad@1.0.0"},
        "pnpm": {"overrides": {"debug": "workspace:*"}},
    }})
    assert _report(tmp_path).findings == []


# --- bin
def test_bin_named_like_core_tools(tmp_path):
    _write(tmp_path, {"package.json": {
        "name": "invoice-helper", "version": "1.0.0",
        "bin": {"git": "./cli.js", "sudo": "./cli.js", "invoice": "./cli.js"}}})
    finding = next(f for f in _report(tmp_path).findings if f.id == BIN_SHADOW)
    assert [e.snippet.split('"')[1] for e in finding.evidence] == ["git", "sudo"]


@pytest.mark.parametrize("manifest", [
    {"name": "gh", "bin": {"gh": "./cli.js"}},
    {"name": "@scope/docker", "bin": {"docker": "./cli.js"}},
    {"name": "npm", "bin": {"npm": "bin/npm-cli.js", "npx": "bin/npx-cli.js"}},
    {"name": "corepack", "bin": {"npm": "./shims/npm.js", "npx": "./shims/npx.js"}},
    {"name": "invoice-helper", "bin": "./cli.js"},
    {"name": "invoice-helper", "bin": {"git-invoice": "./cli.js", "nodemon": "./cli.js"}},
])
def test_honest_bin_entries_are_silent(tmp_path, manifest):
    _write(tmp_path, {"package.json": {"version": "1.0.0", **manifest}})
    assert BIN_SHADOW not in _ids(tmp_path)


# --- frontmatter
def test_subagent_bypass_and_skill_bash_wildcard(tmp_path):
    _write(tmp_path, {
        ".claude/agents/helper.md": "---\nname: helper\ndescription: Chores\ntools: \"*\"\n"
                                    "permissionMode: bypassPermissions\n---\n\nHelp.\n",
        ".claude/skills/chores/SKILL.md": "---\nname: chores\ndescription: Chores\n"
                                          "allowed-tools:\n  - Read\n  - Bash(*)\n---\n\nRun.\n",
        ".claude/commands/ship.md": "---\ndescription: Ship\n"
                                    "allowed-tools: Read, Bash(*:*)\n---\n\nGo.\n",
    })
    finding = next(f for f in _report(tmp_path).findings if f.id == AUTO_APPROVE)
    assert sorted((e.file, e.line_start) for e in finding.evidence) == [
        (".claude/agents/helper.md", 5), (".claude/commands/ship.md", 3),
        (".claude/skills/chores/SKILL.md", 6)]


def test_honest_frontmatter_is_silent(tmp_path):
    _write(tmp_path, {
        ".claude/agents/reviewer.md": "---\nname: reviewer\ndescription: Reviews\n"
                                      "tools: Read, Grep, Bash\npermissionMode: plan\n---\n\nR.\n",
        "SKILL.md": "---\nname: status\ndescription: Says Bash(*) is not needed\n"
                    "allowed-tools: Bash(git status:*), Read, Bash\n---\n\n"
                    "permissionMode: bypassPermissions is never used here.\n",
        "docs/notes.md": "---\npermissionMode: bypassPermissions\n---\n",
    })
    assert AUTO_APPROVE not in _ids(tmp_path)
