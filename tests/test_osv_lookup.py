"""The lockfile lookup in OSV: what may leave the machine, and what the answer may claim."""

from __future__ import annotations

import ast
import io
import json
from pathlib import Path

import pytest

from skilltotal import cli, osv_lookup
from skilltotal.agent_hook import UNCHECKED_KINDS, hook_response
from skilltotal.osv_lookup import Package, lookup, read_lockfile

REPO = Path(__file__).resolve().parent.parent
NPMJS = "https://registry.npmjs.org"


def npm_entry(name: str, version: str, host: str = NPMJS) -> dict:
    return {"version": version, "resolved": f"{host}/{name}/-/{name}-{version}.tgz"}


def package_lock(entries: dict) -> str:
    return json.dumps({"name": "secret-project", "lockfileVersion": 3, "packages": {
        "": {"name": "secret-project"}, **entries}})


class Osv:
    """A stand-in for api.osv.dev."""

    def __init__(self, malicious: dict | None = None, fail: Exception | None = None):
        self.malicious = malicious or {}
        self.fail = fail
        self.bodies: list[dict] = []

    def __call__(self, body: bytes) -> bytes:
        query = json.loads(body)
        self.bodies.append(query)
        if self.fail:
            raise self.fail
        results = []
        for item in query["queries"]:
            ids = self.malicious.get(item["package"]["name"], [])
            results.append({"vulns": [{"id": i, "modified": "2026-01-01T00:00:00Z"}
                                      for i in ids]})
        return json.dumps({"results": results}).encode()

    def names(self) -> list[str]:
        return [q["package"]["name"] for body in self.bodies for q in body["queries"]]


def project(tmp_path: Path, name: str, text: str) -> Path:
    (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def run(tmp_path, file="package-lock.json", transport=None, **options):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    settings = {"environ": {}, "home": home, **options}
    return lookup([file], str(tmp_path), transport or Osv(), tmp_path / "cache.json", **settings)


# --- 2. What may leave the machine ---------------------------------------------------------------


def test_only_public_entries_are_sent_with_exactly_name_ecosystem_and_version(tmp_path):
    project(tmp_path, "package-lock.json", package_lock({
        "node_modules/left-pad": npm_entry("left-pad", "1.3.0")}))
    osv = Osv()
    run(tmp_path, transport=osv)
    assert osv.bodies == [{"queries": [
        {"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.3.0"}]}]


@pytest.mark.parametrize("entry", [
    {"version": "1.0.0", "resolved": "https://npm.corp.example/x/-/x-1.0.0.tgz"},
    {"version": "1.0.0", "resolved": "https://registry.npmjs.org.evil.test/x/-/x-1.0.0.tgz"},
    {"version": "1.0.0", "resolved": "https://registry.npmjs.org@evil.test/x/-/x-1.0.0.tgz"},
    {"version": "1.0.0", "resolved": "http://registry.npmjs.org/x/-/x-1.0.0.tgz"},
    {"version": "1.0.0", "resolved": "https://registry.npmjs.org:8443/x/-/x-1.0.0.tgz"},
    {"version": "1.0.0", "resolved": "https://user:pw@registry.npmjs.org/x/-/x-1.0.0.tgz"},
    {"version": "1.0.0", "resolved": "git+ssh://git@github.com/acme/x.git#abcdef"},
    {"version": "1.0.0", "resolved": "file:../x"},
    {"version": "1.0.0", "link": True, "resolved": "../x"},
    {"version": "1.0.0"},
    {"version": "1.0.0", "resolved": None},
    {"version": "1.0.0", "resolved": "https://registry.npmjs.org/other/-/other-1.0.0.tgz"},
    {"version": "1.0.0", "resolved": "https://registry.npmjs.org/x/-/x-2.0.0.tgz"},
])
def test_an_entry_the_lockfile_does_not_prove_public_is_never_sent(tmp_path, entry):
    project(tmp_path, "package-lock.json", package_lock({"node_modules/x": entry}))
    osv = Osv()
    result = run(tmp_path, transport=osv)
    assert osv.bodies == []
    assert result.withheld == 1


def scoped_lock(tmp_path):
    entry = {"version": "1.0.0",
             "resolved": f"{NPMJS}/@acme/tool/-/tool-1.0.0.tgz"}
    project(tmp_path, "package-lock.json", package_lock({"node_modules/@acme/tool": entry}))


def test_a_scoped_entry_from_the_public_registry_is_public(tmp_path):
    scoped_lock(tmp_path)
    osv = Osv()
    result = run(tmp_path, transport=osv)
    assert osv.names() == ["@acme/tool"] and result.withheld == 0


def test_a_scoped_url_may_spell_its_slash(tmp_path):
    entry = {"version": "1.0.0", "resolved": f"{NPMJS}/@acme%2ftool/-/tool-1.0.0.tgz"}
    project(tmp_path, "package-lock.json", package_lock({"node_modules/@acme/tool": entry}))
    osv = Osv()
    run(tmp_path, transport=osv)
    assert osv.names() == ["@acme/tool"]


@pytest.mark.parametrize("where", ["project", "user"])
@pytest.mark.parametrize("line", [
    "@acme:registry=https://npm.corp.example/",
    "@acme:_authToken=synthetic",
    "//registry.npmjs.org/:_authToken=synthetic",
])
def test_a_scope_mapped_elsewhere_or_holding_a_token_is_not_sent(tmp_path, where, line):
    scoped_lock(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    (tmp_path if where == "project" else home).joinpath(".npmrc").write_text(
        line + "\n", encoding="utf-8")
    osv = Osv()
    result = run(tmp_path, transport=osv)
    assert osv.bodies == [] and result.withheld == 1


def test_another_scopes_mapping_leaves_this_scope_public(tmp_path):
    scoped_lock(tmp_path)
    project(tmp_path, ".npmrc", "@other:registry=https://npm.corp.example/\n")
    osv = Osv()
    run(tmp_path, transport=osv)
    assert osv.names() == ["@acme/tool"]


def test_a_scope_mapped_in_the_environment_is_not_sent(tmp_path):
    scoped_lock(tmp_path)
    osv = Osv()
    environ = {"npm_config_@acme:registry": "https://npm.corp.example/"}
    assert run(tmp_path, transport=osv, environ=environ).withheld == 1
    assert osv.bodies == []


def test_a_scope_mapped_to_the_public_registry_is_public(tmp_path):
    scoped_lock(tmp_path)
    project(tmp_path, ".npmrc", "@acme:registry=https://registry.npmjs.org/\n")
    osv = Osv()
    run(tmp_path, transport=osv)
    assert osv.names() == ["@acme/tool"]


def test_with_no_home_nothing_scoped_or_unproven_is_sent(tmp_path):
    scoped_lock(tmp_path)
    project(tmp_path, "requirements.txt", "requests==2.32.0\n")
    osv = Osv()
    assert run(tmp_path, transport=osv, home=None).withheld == 1
    assert run(tmp_path, "requirements.txt", osv, home=None).withheld == 1
    assert osv.bodies == []


def test_a_workspace_link_and_the_project_itself_are_not_sent(tmp_path):
    project(tmp_path, "package-lock.json", package_lock({
        "packages/a": {"version": "1.0.0"},
        "node_modules/a": {"resolved": "packages/a", "link": True}}))
    osv = Osv()
    result = run(tmp_path, transport=osv)
    assert "secret-project" not in json.dumps(osv.bodies)
    assert osv.bodies == [] and result.withheld == 2


def test_a_custom_registry_on_the_machine_leaves_a_proven_public_entry_public(tmp_path):
    project(tmp_path, ".npmrc", "registry=https://npm.corp.example/\n")
    project(tmp_path, "package-lock.json", package_lock({
        "node_modules/pub": npm_entry("pub", "1.0.0"),
        "node_modules/corp": npm_entry("corp", "1.0.0", "https://npm.corp.example")}))
    osv = Osv()
    result = run(tmp_path, transport=osv)
    assert osv.names() == ["pub"] and result.withheld == 1


def test_a_version_1_lockfile_nests(tmp_path):
    project(tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {**npm_entry("a", "1.0.0"), "dependencies": {"b": npm_entry("b", "2.0.0")}},
        "c": {"version": "1.0.0", "resolved": "https://npm.corp.example/c/-/c-1.0.0.tgz"},
    }}))
    osv = Osv()
    assert run(tmp_path, transport=osv).withheld == 1
    assert osv.names() == ["a", "b"]


def test_a_nested_npm_path_names_the_inner_package(tmp_path):
    project(tmp_path, "package-lock.json", package_lock({
        "node_modules/a/node_modules/b": npm_entry("b", "1.0.0")}))
    osv = Osv()
    run(tmp_path, transport=osv)
    assert osv.names() == ["b"]


def test_npms_held_placeholder_is_dropped(tmp_path):
    project(tmp_path, "package-lock.json", package_lock({
        "node_modules/held": npm_entry("held", "0.0.1-security")}))
    osv = Osv()
    result = run(tmp_path, transport=osv)
    assert osv.bodies == [] and result.withheld == 0 and result.not_checked == 0


YARN_V1 = """# yarn lockfile v1

left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc"
  integrity sha512-x

"@acme/internal@^1.0.0":
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/@acme/internal/-/internal-1.0.0.tgz#abc"

corp@^1.0.0, corp@^1.1.0:
  version "1.1.0"
  resolved "https://npm.corp.example/corp/-/corp-1.1.0.tgz#abc"

git-dep@acme/git-dep:
  version "1.0.0"
  resolved "https://codeload.github.com/acme/git-dep/tar.gz/abc"
"""


def test_yarn_v1_sends_only_what_its_url_proves(tmp_path):
    project(tmp_path, "yarn.lock", YARN_V1)
    osv = Osv()
    result = run(tmp_path, "yarn.lock", osv)
    assert sorted(osv.names()) == ["@acme/internal", "left-pad"]
    assert result.withheld == 2


BERRY = """__metadata:
  version: 8

"left-pad@npm:^1.3.0":
  version: 1.3.0
  resolution: "left-pad@npm:1.3.0"

"@acme/tool@npm:^1.0.0":
  version: 1.0.0
  resolution: "@acme/tool@npm:1.0.0"

"my-project@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-project@workspace:."

"gitdep@https://github.com/acme/gitdep.git":
  version: 1.0.0
  resolution: "gitdep@https://github.com/acme/gitdep.git#commit=abc"
"""

PNPM = """lockfileVersion: '9.0'

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-x}

  '@acme/tool@1.0.0':
    resolution: {integrity: sha512-y}

  with-peer@2.0.0(react@18.0.0):
    resolution: {integrity: sha512-z}

  corp@1.0.0:
    resolution: {integrity: sha512-z, tarball: https://npm.corp.example/corp/-/corp-1.0.0.tgz}

  gitdep@https://codeload.github.com/acme/gitdep/tar.gz/abc:
    resolution: {tarball: https://codeload.github.com/acme/gitdep/tar.gz/abc}

  localdep@file:../local:
    resolution: {directory: ../local, type: directory}

snapshots:

  left-pad@1.3.0: {}
"""


def test_yarn_berry_records_no_url_so_it_is_sent_with_no_custom_registry(tmp_path):
    project(tmp_path, "yarn.lock", BERRY)
    osv = Osv()
    result = run(tmp_path, "yarn.lock", osv)
    assert sorted(osv.names()) == ["@acme/tool", "left-pad"]
    assert result.withheld == 1  # the git dependency; the project itself is not counted


def test_pnpm_records_no_url_so_it_is_sent_with_no_custom_registry(tmp_path):
    project(tmp_path, "pnpm-lock.yaml", PNPM)
    osv = Osv()
    result = run(tmp_path, "pnpm-lock.yaml", osv)
    assert sorted(osv.names()) == ["@acme/tool", "left-pad", "with-peer"]
    assert result.withheld == 3  # a private tarball, a git source, a folder


NPM_CONFIGS = [
    (".npmrc", "registry=https://npm.corp.example/\n", {}),
    (".npmrc", "@acme:registry=https://npm.corp.example/\n", {}),
    (".yarnrc.yml", 'npmRegistryServer: "https://npm.corp.example"\n', {}),
    (".yarnrc.yml", "npmScopes:\n  acme:\n    npmRegistryServer: https://npm.corp.example\n", {}),
    (".yarnrc", 'registry "https://npm.corp.example/"\n', {}),
    ("pnpm-workspace.yaml", "registry: https://npm.corp.example/\n", {}),
    ("bunfig.toml", '[install]\nregistry = "https://npm.corp.example/"\n', {}),
    (None, None, {"NPM_CONFIG_REGISTRY": "https://npm.corp.example/"}),
    (None, None, {"npm_config_registry": "https://npm.corp.example/"}),
    (None, None, {"YARN_NPM_REGISTRY_SERVER": "https://npm.corp.example/"}),
]


@pytest.mark.parametrize("file, text, environ", NPM_CONFIGS)
@pytest.mark.parametrize("lockfile, body, entries", [("pnpm-lock.yaml", PNPM, 6),
                                                     ("yarn.lock", BERRY, 3)])
def test_any_custom_npm_registry_holds_every_entry_with_no_url(tmp_path, file, text, environ,
                                                               lockfile, body, entries):
    project(tmp_path, lockfile, body)
    if file:
        project(tmp_path, file, text)
    osv = Osv()
    result = run(tmp_path, lockfile, osv, environ=environ)
    assert osv.bodies == []
    assert result.withheld == entries
    assert f"{entries} lockfile entries were not sent to OSV" in result.line()


def test_a_custom_registry_in_the_users_npmrc_counts_too(tmp_path):
    project(tmp_path, "pnpm-lock.yaml", PNPM)
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / ".npmrc").write_text("registry=https://npm.corp.example/\n",
                                              encoding="utf-8")
    osv = Osv()
    run(tmp_path, "pnpm-lock.yaml", osv)
    assert osv.bodies == []


def test_a_public_registry_named_in_npmrc_is_no_custom_registry(tmp_path):
    project(tmp_path, "pnpm-lock.yaml", PNPM)
    project(tmp_path, ".npmrc", "registry=https://registry.npmjs.org/\n")
    osv = Osv()
    run(tmp_path, "pnpm-lock.yaml", osv)
    assert "left-pad" in osv.names()


def test_a_custom_npm_registry_does_not_hold_python_entries(tmp_path):
    project(tmp_path, "requirements.txt", "requests==2.32.0\n")
    project(tmp_path, ".npmrc", "registry=https://npm.corp.example/\n")
    osv = Osv()
    run(tmp_path, "requirements.txt", osv)
    assert osv.names() == ["requests"]


def test_a_url_still_proves_an_entry_under_a_custom_registry(tmp_path):
    project(tmp_path, ".npmrc", "registry=https://npm.corp.example/\n")
    project(tmp_path, "package-lock.json", package_lock({
        "node_modules/pub": npm_entry("pub", "1.0.0")}))
    osv = Osv()
    run(tmp_path, transport=osv)
    assert osv.names() == ["pub"]


UV_LOCK = """version = 1

[[package]]
name = "my-project"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "requests"
version = "2.32.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "corp-lib"
version = "1.0.0"
source = { registry = "https://pypi.corp.example/simple" }

[[package]]
name = "gitdep"
version = "1.0.0"
source = { git = "https://github.com/acme/gitdep" }

[[package]]
name = "local"
version = "1.0.0"
source = { path = "../local" }

[[package]]
name = "lookalike"
version = "1.0.0"
source = { registry = "https://pypi.org.evil.test/simple" }
"""


def test_uv_sends_only_what_resolved_from_pypi(tmp_path):
    project(tmp_path, "uv.lock", UV_LOCK)
    osv = Osv()
    result = run(tmp_path, "pyproject.toml", osv)
    assert osv.bodies == [{"queries": [
        {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.32.0"}]}]
    assert result.withheld == 4


POETRY_LOCK = """[[package]]
name = "requests"
version = "2.32.0"

[[package]]
name = "corp-lib"
version = "1.0.0"

[package.source]
type = "legacy"
url = "https://pypi.corp.example/simple"
reference = "corp"

[[package]]
name = "explicit"
version = "1.0.0"

[package.source]
type = "legacy"
url = "https://pypi.org/simple"
reference = "pypi"
"""


def test_poetry_sends_what_has_no_source_and_what_names_pypi(tmp_path):
    project(tmp_path, "poetry.lock", POETRY_LOCK)
    osv = Osv()
    result = run(tmp_path, "poetry.lock", osv)
    assert sorted(osv.names()) == ["explicit", "requests"]
    assert result.withheld == 1


def test_poetry_sources_in_pyproject_hold_entries_with_no_source(tmp_path):
    project(tmp_path, "poetry.lock", POETRY_LOCK)
    project(tmp_path, "pyproject.toml",
            '[[tool.poetry.source]]\nname = "corp"\nurl = "https://pypi.corp.example/simple"\n')
    osv = Osv()
    result = run(tmp_path, "poetry.lock", osv)
    assert osv.names() == ["explicit"]
    assert result.withheld == 2


def test_a_requirements_pin_is_sent_and_an_unpinned_line_is_counted(tmp_path):
    project(tmp_path, "requirements.txt",
            "requests==2.32.0\nflask[async]==3.0.0 ; python_version > '3.9'\nnumpy>=2\n"
            "tool==1.*\n# note\n\n")
    osv = Osv()
    result = run(tmp_path, "requirements.txt", osv)
    assert sorted(osv.names()) == ["flask", "requests"]
    assert result.not_checked == 2
    assert "2 lockfile entries were not checked" in result.line()


@pytest.mark.parametrize("line", [
    "--index-url https://pypi.corp.example/simple", "--index-url=https://pypi.corp.example/simple",
    "-i https://pypi.corp.example/simple", "--extra-index-url https://pypi.corp.example/simple",
    "--find-links https://pypi.corp.example/links",
])
def test_an_index_in_the_requirements_file_holds_its_pins(tmp_path, line):
    project(tmp_path, "requirements.txt", f"{line}\nrequests==2.32.0\n")
    osv = Osv()
    assert run(tmp_path, "requirements.txt", osv).withheld == 1
    assert osv.bodies == []


@pytest.mark.parametrize("command", [
    "pip install -r requirements.txt --index-url https://pypi.corp.example/simple",
    "pip install -i https://pypi.corp.example/simple -r requirements.txt",
    "pip install -r requirements.txt --extra-index-url https://pypi.corp.example/simple",
])
def test_an_index_on_the_command_holds_the_pins(tmp_path, command):
    project(tmp_path, "requirements.txt", "requests==2.32.0\n")
    osv = Osv()
    assert run(tmp_path, "requirements.txt", osv, command=command).withheld == 1
    assert osv.bodies == []


@pytest.mark.parametrize("environ", [{"PIP_INDEX_URL": "https://pypi.corp.example/simple"},
                                     {"PIP_EXTRA_INDEX_URL": "https://pypi.corp.example/simple"},
                                     {"UV_INDEX_URL": "https://pypi.corp.example/simple"}])
def test_an_index_in_the_environment_holds_the_pins(tmp_path, environ):
    project(tmp_path, "requirements.txt", "requests==2.32.0\n")
    osv = Osv()
    assert run(tmp_path, "requirements.txt", osv, environ=environ).withheld == 1
    assert osv.bodies == []


def test_an_index_in_pip_conf_holds_the_pins(tmp_path):
    project(tmp_path, "requirements.txt", "requests==2.32.0\n")
    conf = tmp_path / "pip.ini"
    conf.write_text("[global]\nindex-url = https://pypi.corp.example/simple\n", encoding="utf-8")
    osv = Osv()
    result = run(tmp_path, "requirements.txt", osv, environ={"PIP_CONFIG_FILE": str(conf)})
    assert (result.withheld, osv.bodies) == (1, [])


def test_the_public_index_named_is_no_custom_index(tmp_path):
    project(tmp_path, "requirements.txt", "requests==2.32.0\n")
    osv = Osv()
    run(tmp_path, "requirements.txt", osv, environ={"PIP_INDEX_URL": "https://pypi.org/simple"})
    assert osv.names() == ["requests"]


@pytest.mark.parametrize("name, version", [("a b", "1.0.0"), ("a", "1 0"), ("a", "1;rm"),
                                           ("a\nb", "1")])
def test_a_name_or_version_that_is_not_plain_is_not_sent(tmp_path, name, version):
    entry = {"version": version, "resolved": f"{NPMJS}/{name}/-/{name}-{version}.tgz"}
    project(tmp_path, "package-lock.json", package_lock({f"node_modules/{name}": entry}))
    osv = Osv()
    run(tmp_path, transport=osv)
    assert osv.bodies == []


# --- 3. What the answer may claim ----------------------------------------------------------------


def clean_lock(tmp_path, count=1):
    project(tmp_path, "package-lock.json", package_lock({
        f"node_modules/p{i}": npm_entry(f"p{i}", "1.0.0") for i in range(count)}))


def test_a_clean_result_says_only_what_it_is(tmp_path):
    clean_lock(tmp_path, 3)
    line = run(tmp_path).line()
    assert "No known-malicious version in OSV for the 3 package(s)" in line
    assert "not a scan" in line
    for word in ("safe", "clean", "verified"):
        assert word not in line.lower()


def test_a_hit_names_package_version_and_id(tmp_path):
    clean_lock(tmp_path)
    result = run(tmp_path, transport=Osv({"p0": ["MAL-2026-1234", "GHSA-xxxx-yyyy-zzzz"]}))
    assert result.hit_lines() == ["p0 1.0.0 (MAL-2026-1234)"]


def test_other_advisories_are_not_malware(tmp_path):
    clean_lock(tmp_path)
    assert run(tmp_path, transport=Osv({"p0": ["GHSA-xxxx-yyyy-zzzz", "CVE-2026-1"]})).known == []


@pytest.mark.parametrize("fail", [TimeoutError("late"), OSError("no route"), ValueError("bad")])
def test_osv_unreachable_is_not_checked_with_the_number_and_never_a_pass(tmp_path, fail):
    clean_lock(tmp_path, 4)
    result = run(tmp_path, transport=Osv(fail=fail))
    assert result.failed and result.incomplete and result.not_checked == 4
    line = result.line()
    assert "not checked" in line and "4 package(s)" in line
    assert "No known-malicious" not in line


@pytest.mark.parametrize("answer", [b"not json", b"{}", b'{"results": []}', b'{"results": 3}',
                                    b"[]"])
def test_an_unusable_answer_is_not_checked(tmp_path, answer):
    clean_lock(tmp_path, 2)
    result = run(tmp_path, transport=lambda body: answer)
    assert result.failed and result.not_checked == 2


def test_an_answer_of_the_wrong_length_is_not_checked(tmp_path):
    clean_lock(tmp_path, 2)
    result = run(tmp_path, transport=lambda body: b'{"results": [{}]}')
    assert result.failed


def test_a_result_that_cannot_be_read_counts_as_not_checked(tmp_path):
    clean_lock(tmp_path, 2)
    result = run(tmp_path, transport=lambda body: b'{"results": [{}, 3]}')
    assert (result.asked, result.not_checked) == (1, 1)
    assert "1 lockfile entries were not checked" in result.line()


def test_a_further_page_of_ids_counts_as_not_checked(tmp_path):
    clean_lock(tmp_path)
    answer = b'{"results": [{"vulns": [{"id": "GHSA-1"}], "next_page_token": "x"}]}'
    result = run(tmp_path, transport=lambda body: answer)
    assert result.not_checked == 1 and result.incomplete


def test_an_entry_that_could_not_be_parsed_is_counted(tmp_path):
    project(tmp_path, "package-lock.json", package_lock({
        "node_modules/a": npm_entry("a", "1.0.0"), "node_modules/b": "not an object"}))
    result = run(tmp_path)
    assert (result.asked, result.not_checked) == (1, 1)
    assert result.incomplete


def test_withheld_entries_are_counted_but_are_not_a_failure(tmp_path):
    project(tmp_path, "package-lock.json", package_lock({
        "node_modules/a": npm_entry("a", "1.0.0"),
        "node_modules/b": npm_entry("b", "1.0.0", "https://npm.corp.example")}))
    result = run(tmp_path)
    assert "1 lockfile entries were not sent to OSV" in result.line()
    assert not result.incomplete


@pytest.mark.parametrize("text", ["{broken", "[1]", "{}"])
def test_a_lockfile_that_cannot_be_read_is_not_checked(tmp_path, text):
    project(tmp_path, "package-lock.json", text)
    result = run(tmp_path)
    assert result.incomplete and "could not be read" in result.line()


def test_no_lockfile_says_transitive_packages_are_unknown(tmp_path):
    result = run(tmp_path, "package.json")
    assert result.no_lockfile
    assert "not known until the installer resolves them" in result.line()
    assert not result.incomplete


def test_a_format_it_does_not_read_is_not_checked(tmp_path):
    project(tmp_path, "bun.lock", "{}")
    assert "bun.lock could not be read" in run(tmp_path, "bun.lock").line()


# --- 5. No storms ---------------------------------------------------------------------------------


def test_one_batch_per_lookup_and_the_overflow_is_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(osv_lookup, "MAX_QUERIES", 2)
    clean_lock(tmp_path, 5)
    osv = Osv()
    result = run(tmp_path, transport=osv)
    assert len(osv.bodies) == 1 and len(osv.names()) == 2
    assert (result.asked, result.not_checked) == (2, 3)


def test_a_failure_is_not_retried(tmp_path):
    clean_lock(tmp_path)
    osv = Osv(fail=OSError("down"))
    run(tmp_path, transport=osv)
    assert len(osv.bodies) == 1


def test_the_cache_answers_within_its_time_and_not_after(tmp_path):
    clean_lock(tmp_path)
    osv = Osv()
    run(tmp_path, transport=osv, now=1000.0)
    run(tmp_path, transport=osv, now=1000.0 + osv_lookup.CACHE_TTL_S - 1)
    assert len(osv.bodies) == 1
    run(tmp_path, transport=osv, now=1000.0 + osv_lookup.CACHE_TTL_S + 1)
    assert len(osv.bodies) == 2


def test_a_cached_hit_is_still_a_hit(tmp_path):
    clean_lock(tmp_path)
    run(tmp_path, transport=Osv({"p0": ["MAL-2026-1"]}), now=1.0)
    assert run(tmp_path, transport=Osv(), now=2.0).hit_lines() == ["p0 1.0.0 (MAL-2026-1)"]


def test_a_failed_lookup_leaves_nothing_in_the_cache(tmp_path):
    clean_lock(tmp_path)
    run(tmp_path, transport=Osv(fail=OSError("down")), now=1.0)
    osv = Osv()
    run(tmp_path, transport=osv, now=2.0)
    assert len(osv.bodies) == 1


def test_a_poisoned_cache_entry_is_asked_about_again(tmp_path):
    clean_lock(tmp_path)
    cache = tmp_path / "cache.json"
    cache.write_text(json.dumps({"npm|p0|1.0.0": {"at": True, "ids": []}}), encoding="utf-8")
    osv = Osv()
    run(tmp_path, transport=osv, now=2.0)
    assert len(osv.bodies) == 1


def test_the_request_carries_nothing_but_the_query(monkeypatch):
    seen: dict = {}

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    class Opener:
        def open(self, request, timeout):
            seen.update(url=request.full_url, headers=dict(request.header_items()),
                        timeout=timeout, method=request.get_method())
            return Response(b'{"results": []}')

    monkeypatch.setattr("urllib.request.build_opener", lambda *handlers: Opener())
    assert osv_lookup.post(b"{}") == b'{"results": []}'
    assert seen["url"] == "https://api.osv.dev/v1/querybatch" and seen["method"] == "POST"
    assert seen["timeout"] == 5.0
    assert {k.lower(): v for k, v in seen["headers"].items()} == {
        "content-type": "application/json", "user-agent": "skilltotal"}


def test_a_lookup_that_hangs_ends_at_the_limit(monkeypatch):
    import threading
    import time

    release = threading.Event()

    class Opener:
        def open(self, request, timeout):
            release.wait(10)
            raise OSError("gone")

    monkeypatch.setattr("urllib.request.build_opener", lambda *handlers: Opener())
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        osv_lookup.post(b"{}", timeout=0.05)
    release.set()
    assert time.monotonic() - started < 2


def test_a_redirect_is_not_followed():
    assert osv_lookup._NoRedirects().redirect_request() is None


# --- Off by default? On by default ----------------------------------------------------------------


@pytest.mark.parametrize("value, on", [("", True), ("1", True), ("garbage", True), ("0", False),
                                       ("off", False), ("FALSE", False), (" no ", False)])
def test_it_is_on_unless_turned_off(value, on):
    assert osv_lookup.enabled({"SKILLTOTAL_OSV": value}) is on


def test_it_is_on_with_no_setting():
    assert osv_lookup.enabled({}) is True


def test_the_cli_passes_no_lookup_when_turned_off(monkeypatch):
    monkeypatch.setenv("SKILLTOTAL_OSV", "0")
    assert cli._hook_osv() is None
    monkeypatch.delenv("SKILLTOTAL_OSV")
    assert callable(cli._hook_osv())


# --- In the hook ----------------------------------------------------------------------------------


def stand_in(hits=(), *, failed=False, not_checked=0, no_lockfile=False, asked=1):
    def check(files, cwd, command):
        found = osv_lookup.Lookup(asked=asked, failed=failed, not_checked=not_checked,
                                  no_lockfile=no_lockfile)
        found.known = [(Package("npm", name, version), [mal]) for name, version, mal in hits]
        return found
    return check


def event(command="npm ci", cwd="/work"):
    return {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd}


def no_scan(*args, **kwargs):
    raise AssertionError("a lockfile install names nothing to scan")


def decision(answer):
    return answer["hookSpecificOutput"].get("permissionDecision")


@pytest.mark.parametrize("strict", [False, True])
def test_a_listed_version_is_denied_in_and_out_of_ci(strict):
    answer = hook_response(event(), no_scan, strict=strict,
                           allow_unchecked=frozenset({"lockfile"}),
                           osv=stand_in([("evil", "1.0.0", "MAL-2026-9")]))
    assert decision(answer) == "deny"
    reason = answer["hookSpecificOutput"]["permissionDecisionReason"]
    assert "evil 1.0.0 (MAL-2026-9)" in reason and "OSV lists" in reason


def test_outside_ci_a_failed_lookup_lets_the_install_go_on_and_says_not_checked():
    answer = hook_response(event(), no_scan, osv=stand_in(failed=True, not_checked=7, asked=0))
    assert decision(answer) is None
    assert "not checked" in answer["systemMessage"] and "7 package(s)" in answer["systemMessage"]


def test_in_ci_a_failed_lookup_only_says_so():
    answer = hook_response(event(), no_scan, strict=True,
                           allow_unchecked=frozenset({"lockfile"}),
                           osv=stand_in(failed=True, not_checked=7, asked=0))
    assert decision(answer) is None
    assert "not checked" in answer["systemMessage"]


@pytest.mark.parametrize("gap", [{"failed": True, "not_checked": 7, "asked": 0},
                                 {"not_checked": 2}])
def test_strict_osv_denies_an_incomplete_lookup_in_ci(gap):
    answer = hook_response(event(), no_scan, strict=True, deny_osv_gap=True,
                           allow_unchecked=frozenset({"lockfile"}), osv=stand_in(**gap))
    assert decision(answer) == "deny"
    reason = answer["hookSpecificOutput"]["permissionDecisionReason"]
    assert "lockfile lookup in OSV was incomplete" in reason and "SKILLTOTAL_STRICT_OSV" in reason


def test_strict_osv_changes_nothing_when_the_lookup_was_complete():
    answer = hook_response(event(), no_scan, strict=True, deny_osv_gap=True,
                           allow_unchecked=frozenset({"lockfile"}), osv=stand_in())
    assert decision(answer) is None


def test_strict_osv_is_a_ci_setting():
    answer = hook_response(event(), no_scan, deny_osv_gap=True,
                           osv=stand_in(failed=True, not_checked=7, asked=0))
    assert decision(answer) is None


def test_a_hit_still_denies_with_lockfile_allowed_and_strict_osv_off():
    answer = hook_response(event(), no_scan, strict=True,
                           allow_unchecked=frozenset({"lockfile"}), deny_osv_gap=False,
                           osv=stand_in([("evil", "1.0.0", "MAL-2026-9")]))
    assert decision(answer) == "deny"
    assert "evil 1.0.0 (MAL-2026-9)" in answer["hookSpecificOutput"]["permissionDecisionReason"]


def test_osv_is_no_kind_of_unchecked_install():
    assert "osv" not in UNCHECKED_KINDS


@pytest.mark.parametrize("value, on", [("", False), ("0", False), ("off", False), ("1", True),
                                       ("true", True), ("ture", True)])
def test_strict_osv_reads_as_strict_partial_does(value, on):
    assert cli._hook_strict_osv({"SKILLTOTAL_STRICT_OSV": value}) is on


def test_a_typo_in_strict_osv_is_said():
    note = cli._hook_settings_note({"SKILLTOTAL_STRICT_OSV": "ture"}, 600.0)
    assert "SKILLTOTAL_STRICT_OSV is 'ture', read as on; use 1 or 0." in note


def test_without_a_lookup_a_lockfile_install_is_as_before():
    answer = hook_response(event(), no_scan)
    assert decision(answer) is None
    assert "OSV" not in answer["systemMessage"]


def test_a_command_with_no_lockfile_asks_osv_nothing():
    calls: list = []

    def check(files, cwd, command):
        calls.append(files)
        return stand_in()(files, cwd, command)

    hook_response(event("ls"), no_scan, osv=check)
    assert calls == []


def test_the_lookup_gets_the_lockfile_the_command_reads():
    calls: list = []

    def check(files, cwd, command):
        calls.append((files, cwd))
        return stand_in()(files, cwd, command)

    hook_response(event("pip install -r requirements.txt"), no_scan, osv=check)
    hook_response(event("npm install"), no_scan, osv=check)
    hook_response(event("uv sync"), no_scan, osv=check)
    assert calls == [(["requirements.txt"], "/work"), (["package.json"], "/work"),
                     (["pyproject.toml"], "/work")]


def test_a_real_lockfile_end_to_end_through_the_cli(tmp_path, monkeypatch, capsys):
    project(tmp_path, "package-lock.json", package_lock({
        "node_modules/evil": npm_entry("evil", "1.0.0")}))
    monkeypatch.delenv("SKILLTOTAL_OSV")
    monkeypatch.setenv("SKILLTOTAL_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(osv_lookup, "post", Osv({"evil": ["MAL-2026-9"]}))
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event("npm ci", str(tmp_path)))))
    assert cli.main(["hook", "claude-code"]) == 0
    assert "MAL-2026-9" in capsys.readouterr().out


# --- 6. Out of the engine, and of everything that says it is offline ------------------------------


@pytest.mark.parametrize("module", ["engine", "guard", "collector", "inventory", "report",
                                    "mcp_server", "sentinel", "agent_hook"])
def test_nothing_but_the_cli_reaches_the_lookup(module):
    tree = ast.parse((REPO / "skilltotal" / f"{module}.py").read_text(encoding="utf-8"))
    imported = [alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                for alias in node.names] + [
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any("osv_lookup" in name for name in imported)


def test_the_guard_and_inventory_commands_never_build_a_lookup():
    source = (REPO / "skilltotal" / "cli.py").read_text(encoding="utf-8")
    assert source.count("osv=_hook_osv()") == 1  # the hook's decision, and nothing else


def test_the_disclosure_is_where_a_reader_looks():
    for doc in ("docs/agent-hooks.md", "docs/plugin.md", "README.md", "SECURITY.md"):
        text = (REPO / doc).read_text(encoding="utf-8")
        assert "api.osv.dev" in text and "SKILLTOTAL_OSV=0" in text and "Google" in text, doc


def test_a_nested_requirements_file_counts_as_not_checked(tmp_path):
    project(tmp_path, "requirements.txt", "-r other.txt\n")
    assert run(tmp_path, "requirements.txt").not_checked == 1


def test_a_setting_it_cannot_read_is_said_and_stays_on():
    note = cli._hook_settings_note({"SKILLTOTAL_OSV": "maybe"}, 100.0)
    assert "SKILLTOTAL_OSV" in note and "on" in note


def test_read_lockfile_ignores_what_it_cannot_name(tmp_path):
    assert read_lockfile(project(tmp_path, "notes.md", "x") / "notes.md") is None
