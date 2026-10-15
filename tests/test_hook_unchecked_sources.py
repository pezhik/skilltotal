"""What the hook cannot check is said, never passed in silence (audit 2026-10-15, C2 and C3).

* An MCP server an agent CLI registers that is no package: a remote server reached at a URL
  (`claude mcp add --transport http x URL`, `codex mcp add x --url URL`) or one that runs in a
  container (`claude mcp add x -- docker run ... image`). Nothing is downloaded where the hook could
  read it, so it is said in the console; in CI it is denied unless SKILLTOTAL_ALLOW_UNCHECKED
  names `remote` or `container`.
* A registry or index configured outside the command line (NPM_CONFIG_REGISTRY, an `.npmrc`,
  PIP_INDEX_URL, a `pip.conf`/`pip.ini`, UV_DEFAULT_INDEX): the hook used to scan the public copy
  and say "checked", though the installer fetched from elsewhere. It is asked about now, like
  `--registry` on the command line (denied in CI).

URLs are reserved `.invalid` names; nothing is fetched or run.
"""

from __future__ import annotations

import io
import json
import sys

import pytest

from skilltotal import cli
from skilltotal.agent_hook import ALLOW_UNCHECKED_ENV, hook_response, parse_installs

NAMES_ONLY = "and SkillTotal checks only the packages a command names."
STRICT_ON = "Strict mode is on because CI is set (SKILLTOTAL_STRICT=0 turns it off)."


def _bash(command, cwd=None):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": command}}
    if cwd is not None:
        event["cwd"] = str(cwd)
    return event


def _report():
    return {"risk_level": "low", "risk_score": 0, "findings": [],
            "verdict": {"has_malicious_indicators": False}}


def _no_scan(command, **options):
    calls = []
    out = hook_response(_bash(command, options.pop("cwd", None)),
                        scan=lambda s, t: calls.append(s) or _report(), **options)
    assert calls == []
    return out


# --- C2: remote MCP servers and container images ------------------------------------------------

REMOTE = "it adds the remote MCP server at https://mcp.example.invalid"
SERVERS = [
    ("claude mcp add --transport http notion https://mcp.example.invalid/mcp", "remote", REMOTE),
    ("claude mcp add --transport=sse x https://mcp.example.invalid/sse", "remote", REMOTE),
    ("claude mcp add -s user -t http x https://mcp.example.invalid", "remote", REMOTE),
    ("codex mcp add x --url https://mcp.example.invalid/mcp", "remote", REMOTE),
    ("gemini mcp add x https://mcp.example.invalid/mcp --transport http", "remote", REMOTE),
    ("""claude mcp add-json x '{"type": "http", "url": "https://mcp.example.invalid/mcp"}'""",
     "remote", REMOTE),
    ("""claude mcp add-json x '{"type": "sse"}'""", "remote", "it adds a remote MCP server"),
    ("claude mcp add github -- docker run -i --rm -e GITHUB_TOKEN ghcr.io/github/mcp-server",
     "container", "it runs the container image ghcr.io/github/mcp-server"),
    ("claude mcp add x -- podman run -it --name x -p8080:80 -v a:/b mcp/fetch:1.0", "container",
     "it runs the container image mcp/fetch:1.0"),
    ("claude mcp add x -- docker --context ci container run --pull always mcp/time", "container",
     "it runs the container image mcp/time"),
    ("""claude mcp add-json x '{"command": "docker", "args": ["run", "-i", "mcp/fetch"]}'""",
     "container", "it runs the container image mcp/fetch"),
]


@pytest.mark.parametrize(("command", "kind", "what"), SERVERS)
def test_a_server_that_is_no_package_is_said_in_the_console(command, kind, what):
    out = _no_scan(command)
    assert out["hookSpecificOutput"] == {"hookEventName": "PreToolUse"}  # no decision
    assert out["systemMessage"] == f"SkillTotal did not check this install: {what}, {NAMES_ONLY}"


@pytest.mark.parametrize(("command", "kind", "what"), SERVERS)
def test_in_ci_a_server_that_is_no_package_is_denied_unless_its_kind_is_allowed(command, kind,
                                                                                 what):
    out = _no_scan(command, strict=True, strict_by="CI")
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "deny"
    reason = f"(CI rule) SkillTotal blocked this install: {what}, {NAMES_ONLY}"
    assert spec["permissionDecisionReason"] == reason
    assert out["systemMessage"] == (
        f"{reason} To allow it in CI, set {ALLOW_UNCHECKED_ENV}={kind}. {STRICT_ON}")
    allowed = _no_scan(command, strict=True, allow_unchecked=frozenset({kind}))
    assert allowed["hookSpecificOutput"] == {"hookEventName": "PreToolUse"}
    assert allowed["systemMessage"].startswith("SkillTotal did not check this install: ")


def test_a_credential_in_a_server_url_is_never_echoed():
    out = _no_scan("claude mcp add --transport http x "
                   "https://user:s3cret@mcp.example.invalid/k/T0KEN?key=K3Y")
    assert "https://mcp.example.invalid," in out["systemMessage"]
    for secret in ("s3cret", "T0KEN", "K3Y", "user"):
        assert secret not in out["systemMessage"]


def test_a_package_the_container_server_also_names_is_still_checked():
    out = hook_response(_bash("claude mcp add x -- docker run -i node:22 npx -y some-mcp"),
                        scan=lambda s, t: _report())
    assert out["systemMessage"].startswith("SkillTotal checked npm:some-mcp: risk 0/100 (low).")
    assert "it runs the container image node:22" in out["systemMessage"]


@pytest.mark.parametrize("command", [
    # A server started as a command: its packages are checked as before.
    "claude mcp add fetch -- npx -y some-mcp",
    # gemini's default transport is stdio: the URL is the command, which installs nothing.
    "gemini mcp add x https://mcp.example.invalid/mcp",
    # A server named docker is not a container.
    "claude mcp add docker -- uvx some-mcp",
    # docker outside `mcp add` registers nothing.
    "docker run --rm alpine true",
])
def test_other_servers_and_commands_are_unchanged(command):
    kinds = {item.unchecked for item in parse_installs(command)}
    assert not kinds & {"remote", "container"}


# --- C3: a registry or index configured outside the command line ---------------------------------

CORP = "https://npm.corp.invalid"
CORP_PY = "https://pypi.corp.invalid"


def _asked(out) -> str:
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask"
    return spec["permissionDecisionReason"]


def _checked(command, **options):
    calls = []
    hook_response(_bash(command, options.pop("cwd", None)),
                  scan=lambda s, t: calls.append(s) or _report(), **options)
    return calls


@pytest.mark.parametrize(("variable", "command", "name"), [
    ("NPM_CONFIG_REGISTRY", "npm install lodash", "lodash"),
    ("npm_config_registry", "npx -y some-mcp", "some-mcp"),
    ("YARN_REGISTRY", "yarn add lodash", "lodash"),
    ("BUN_CONFIG_REGISTRY", "bun add lodash", "lodash"),
])
def test_an_npm_registry_in_the_environment_is_asked_about(tmp_path, variable, command, name):
    out = _no_scan(command, environ={variable: f"{CORP}/repo/"}, home=tmp_path)
    assert _asked(out) == (
        f"SkillTotal needs your approval for this install. {name} from {CORP} (set by "
        f"{variable}): SkillTotal can't check what this would install.")


@pytest.mark.parametrize(("variable", "command", "name"), [
    ("PIP_INDEX_URL", "pip install requests", "requests"),
    ("PIP_EXTRA_INDEX_URL", "pip install requests", "requests"),
    ("UV_DEFAULT_INDEX", "uvx ruff", "ruff"),
    ("UV_INDEX_URL", "uv tool install ruff", "ruff"),
])
def test_a_python_index_in_the_environment_is_asked_about(tmp_path, variable, command, name):
    out = _no_scan(command, environ={variable: f"{CORP_PY}/simple"}, home=tmp_path)
    assert f"{name} from {CORP_PY} (set by {variable})" in _asked(out)


def test_the_public_registry_configured_is_still_checked(tmp_path):
    environ = {"NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/",
               "PIP_INDEX_URL": "https://pypi.org/simple/"}
    assert _checked("npm i lodash && pip install requests", environ=environ, home=tmp_path) == [
        "npm:lodash", "pypi:requests"]


def test_a_project_npmrc_is_read_from_the_project_root(tmp_path):
    project = tmp_path / "project"
    (project / "src" / "deep").mkdir(parents=True)
    (project / "package.json").write_text("{}", encoding="utf-8")
    (project / ".npmrc").write_text(f"; mirror\nregistry = {CORP}/\n", encoding="utf-8")
    out = _no_scan("npm install lodash", cwd=project / "src" / "deep", environ={},
                   home=tmp_path / "home")
    assert f"lodash from {CORP} (set in {(project / '.npmrc').as_posix()})" in _asked(out)


def test_a_user_npmrc_is_read_and_a_project_setting_wins(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".npmrc").write_text(f"registry={CORP}\n//npm.corp.invalid/:_authToken=T0KEN\n",
                                 encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_text("{}", encoding="utf-8")
    reason = _asked(_no_scan("npx some-mcp", cwd=project, environ={}, home=home))
    assert f"some-mcp from {CORP} (set in " in reason and "T0KEN" not in reason
    (project / ".npmrc").write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")
    assert _checked("npx some-mcp", cwd=project, environ={}, home=home) == ["npm:some-mcp"]


def test_npm_userconfig_names_the_user_file(tmp_path):
    config = tmp_path / "ci.npmrc"
    config.write_text(f"registry={CORP}\n", encoding="utf-8")
    out = _no_scan("npm i lodash", environ={"NPM_CONFIG_USERCONFIG": str(config)},
                   home=tmp_path)
    assert f"lodash from {CORP}" in _asked(out)


def test_a_scoped_registry_matters_only_for_its_scope(tmp_path):
    (tmp_path / ".npmrc").write_text(f"@corp:registry={CORP}/\n", encoding="utf-8")
    out = hook_response(_bash("npm i @corp/tool lodash"), scan=lambda s, t: _report(),
                        environ={}, home=tmp_path)
    assert f"@corp/tool from {CORP}" in _asked(out)
    assert _checked("npm i lodash @other/x", environ={}, home=tmp_path) == [
        "npm:lodash", "npm:@other/x"]
    environ = {"npm_config_@corp:registry": CORP}
    assert f"@corp/tool from {CORP} (set by npm_config_@corp:registry)" in _asked(
        _no_scan("npx @corp/tool", environ=environ, home=tmp_path / "none"))


def test_a_credential_in_a_configured_registry_is_never_echoed(tmp_path):
    (tmp_path / ".npmrc").write_text(
        "registry=https://user:s3cret@npm.corp.invalid/T0KEN/\n", encoding="utf-8")
    reason = _asked(_no_scan("npm i lodash", environ={}, home=tmp_path))
    assert f"lodash from {CORP} (" in reason
    for secret in ("s3cret", "T0KEN", "user@"):
        assert secret not in reason


@pytest.mark.parametrize(("text", "shown"), [
    (f"[global]\nindex-url = {CORP_PY}/simple\n", CORP_PY),
    (f"[install]\nextra-index-url={CORP_PY}/simple\n", CORP_PY),
    (f"[global]\nindex_url: {CORP_PY}/simple\n", CORP_PY),
    (f"[global]\nextra-index-url =\n    {CORP_PY}/simple\n", "a registry"),
])
def test_a_pip_config_file_is_read(tmp_path, text, shown):
    folder = tmp_path / "appdata" / "pip"
    folder.mkdir(parents=True)
    (folder / "pip.ini").write_text(text, encoding="utf-8")
    out = _no_scan("pip install requests", environ={"APPDATA": str(tmp_path / "appdata")},
                   home=tmp_path / "home")
    assert f"requests from {shown} (set in " in _asked(out)


def test_pip_index_url_in_the_environment_wins_over_the_files(tmp_path):
    (tmp_path / "pip.conf").write_text(f"[global]\nindex-url = {CORP_PY}/simple\n",
                                       encoding="utf-8")
    environ = {"PIP_CONFIG_FILE": str(tmp_path / "pip.conf"),
               "PIP_INDEX_URL": "https://pypi.org/simple"}
    assert _checked("pip install requests", environ=environ, home=tmp_path) == [
        "pypi:requests"]
    # An extra index anywhere still counts: it can serve the higher version.
    (tmp_path / "pip.conf").write_text(f"[global]\nextra-index-url = {CORP_PY}/simple\n",
                                       encoding="utf-8")
    assert f"requests from {CORP_PY}" in _asked(
        _no_scan("pip install requests", environ=environ, home=tmp_path))


def test_a_config_path_that_is_no_regular_file_is_skipped(tmp_path):
    (tmp_path / ".npmrc").mkdir()  # a folder by that name
    assert _checked("npm i lodash", environ={}, home=tmp_path) == ["npm:lodash"]


def test_a_config_file_too_large_to_read_leaves_the_registry_unknown(tmp_path):
    """npm reads all of it; a registry past the part the hook reads was a silent pass."""
    (tmp_path / ".npmrc").write_text("; x\n" * 40_000 + f"registry={CORP}\n", encoding="utf-8")
    assert "lodash from a registry SkillTotal could not read (set in " in _asked(
        _no_scan("npm i lodash", environ={}, home=tmp_path))


def test_without_an_environment_nothing_outside_the_command_is_read(tmp_path):
    (tmp_path / ".npmrc").write_text(f"registry={CORP}\n", encoding="utf-8")
    assert _checked("npm i lodash", cwd=tmp_path) == ["npm:lodash"]


def test_in_ci_a_configured_registry_is_denied(tmp_path):
    out = _no_scan("npm i lodash", strict=True, strict_by="CI",
                   environ={"NPM_CONFIG_REGISTRY": CORP}, home=tmp_path)
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "deny"
    assert spec["permissionDecisionReason"].startswith(
        f"(CI rule) SkillTotal blocked this install; outside CI it would ask for approval. "
        f"lodash from {CORP} (set by NPM_CONFIG_REGISTRY)")


def test_the_ci_denial_says_how_to_allow_a_mirror(tmp_path):
    out = _no_scan("npm i lodash", strict=True, strict_by="CI",
                   environ={"NPM_CONFIG_REGISTRY": CORP}, home=tmp_path)
    assert f"set {ALLOW_UNCHECKED_ENV}=registry" in out["systemMessage"]


def test_a_ci_job_behind_a_mirror_can_allow_it_without_turning_strict_off(tmp_path):
    """A company mirror in .npmrc denied every named install in CI, and the only way out was
    SKILLTOTAL_STRICT=0. Allowing the `registry` kind lets it through, said in the console."""
    out = _no_scan("npm i lodash", strict=True, strict_by="CI",
                   allow_unchecked=frozenset({"registry"}),
                   environ={"NPM_CONFIG_REGISTRY": CORP}, home=tmp_path)
    spec = out["hookSpecificOutput"]
    assert spec.get("permissionDecision") != "deny"
    assert "lodash from" in out["systemMessage"]


def test_allowing_a_mirror_does_not_let_a_typosquat_through(tmp_path):
    """The `registry` kind covers only what comes from the configured registry: a name the public
    registry has and the scan flags is still judged."""
    out = hook_response(_bash("npm i lodash"), strict=True, strict_by="CI",
                        allow_unchecked=frozenset({"registry"}),
                        scan=lambda s, t: {**_report(), "verdict": {
                            "has_malicious_indicators": True}, "findings": [
                            {"id": "ST-X", "title": "x", "severity": "high",
                             "threat_class": "malicious_indicator", "evidence": []}]})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_installs_without_a_package_name_are_unchanged(tmp_path):
    out = _no_scan("npm ci", environ={"NPM_CONFIG_REGISTRY": CORP}, home=tmp_path)
    assert "permissionDecision" not in out["hookSpecificOutput"]


def test_the_cli_reads_the_agents_environment(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NPM_CONFIG_REGISTRY", CORP)
    monkeypatch.setattr(cli, "_hook_scan_cached", lambda s, t: pytest.fail(f"scanned {s}"))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(_bash("npm i lodash", tmp_path))))
    assert cli.main(["hook", "claude-code"]) == cli.EXIT_OK
    answer = json.loads(capsys.readouterr().out)
    assert f"lodash from {CORP} (set by NPM_CONFIG_REGISTRY)" in _asked(answer)


# --- .npmrc read as npm reads it (security review 2026-10-15, H2 and H4) ------------------------


def _project_npmrc(tmp_path, text):
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_text("{}", encoding="utf-8")
    (project / ".npmrc").write_text(text, encoding="utf-8")
    return project


@pytest.mark.parametrize("text", [
    f"registry=https://registry.npmjs.org/\nregistry={CORP}/\n",  # the last one wins
    f'"registry"={CORP}/\n',  # a quoted key
    f"'registry' = '{CORP}/'\n",
    f'registry = "{CORP}/" ; a comment\n',
    f"  registry  =  {CORP}/  # a comment\n",
    f"registry={CORP}/\r\n[section]\nregistry=https://registry.npmjs.org/\n",
])
def test_an_npmrc_is_read_the_way_npm_reads_it(tmp_path, text):
    project = _project_npmrc(tmp_path, text)
    out = _no_scan("npm i lodash", cwd=project, environ={}, home=tmp_path / "home")
    assert f"lodash from {CORP} (set in " in _asked(out)


@pytest.mark.parametrize("text", [
    f"[mirror]\nregistry={CORP}/\n",  # a key under a section is no npm setting
    f"registry\t:{CORP}/\n",  # no `=`: the whole line is one key npm does not know
    f"; registry={CORP}/\n# registry={CORP}/\n",
    f"registry={CORP}/\nregistry=https://registry.npmjs.org/\n",
])
def test_what_npm_does_not_take_for_the_registry_is_not_one(tmp_path, text):
    project = _project_npmrc(tmp_path, text)
    assert _checked("npm i lodash", cwd=project, environ={}, home=tmp_path / "home") == [
        "npm:lodash"]


@pytest.mark.parametrize("text", [
    "userconfig=./u.npmrc\n",
    "globalconfig=./g.npmrc\n",
    "prefix=./tools\n",
    "${KEY}=https://npm.corp.invalid/\n",
    f"registry[]={CORP}/\n",
])
def test_an_npmrc_that_sends_npm_elsewhere_leaves_the_registry_unknown(tmp_path, text):
    """A project's .npmrc can name another configuration file, which npm then reads; the hook
    does not follow a file the repository picks, so the registry is unknown: asked, denied in
    CI."""
    project = _project_npmrc(tmp_path, text)
    (project / "u.npmrc").write_text(f"registry={CORP}/\n", encoding="utf-8")
    (project / "g.npmrc").write_text(f"registry={CORP}/\n", encoding="utf-8")
    out = _no_scan("npm i lodash", cwd=project, environ={}, home=tmp_path / "home")
    assert "lodash from a registry SkillTotal could not read (" in _asked(out)
    strict = _no_scan("npm i lodash", cwd=project, environ={}, home=tmp_path / "home",
                      strict=True, strict_by="CI")
    assert strict["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_settings_above_the_unknown_file_still_decide(tmp_path):
    project = _project_npmrc(tmp_path, "userconfig=./u.npmrc\n")
    environ = {"NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/"}
    # The file the project names could still set the dist-tag.
    assert "lodash at an npm dist-tag SkillTotal could not read (" in _asked(
        _no_scan("npm i lodash", cwd=project, environ=environ, home=tmp_path))
    environ["npm_config_tag"] = "latest"
    assert _checked("npm i lodash", cwd=project, environ=environ, home=tmp_path) == [
        "npm:lodash"]


def test_the_user_npmrc_prefix_is_followed_to_the_global_npmrc(tmp_path):
    """`prefix=~/.npm-global` in the user's own .npmrc is common: npm then reads the global
    .npmrc under that prefix, and so does the hook."""
    home = tmp_path / "home"
    (home / ".npm-global" / "etc").mkdir(parents=True)
    (home / ".npmrc").write_text("prefix=~/.npm-global\n", encoding="utf-8")
    assert _checked("npm i lodash", environ={}, home=home) == ["npm:lodash"]
    (home / ".npm-global" / "etc" / "npmrc").write_text(f"registry={CORP}/\n", encoding="utf-8")
    out = _no_scan("npm i lodash", environ={}, home=home)
    assert f"lodash from {CORP} (set in " in _asked(out)


def test_a_workspace_member_reads_the_workspace_roots_npmrc(tmp_path):
    root = tmp_path / "mono"
    member = root / "pkg"
    member.mkdir(parents=True)
    (root / "package.json").write_text('{"workspaces": ["pkg"]}', encoding="utf-8")
    (root / ".npmrc").write_text(f"registry={CORP}/\n", encoding="utf-8")
    (member / "package.json").write_text("{}", encoding="utf-8")
    # npm ignores a member's own .npmrc; the root's is the project's.
    (member / ".npmrc").write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")
    out = _no_scan("npm i lodash", cwd=member, environ={}, home=tmp_path / "home")
    assert f"lodash from {CORP} (set in {(root / '.npmrc').as_posix()})" in _asked(out)


def test_a_pip_config_file_too_large_to_read_leaves_the_index_unknown(tmp_path):
    (tmp_path / "pip.conf").write_text("# x\n" * 20_000 + f"index-url={CORP_PY}\n",
                                       encoding="utf-8")
    environ = {"PIP_CONFIG_FILE": str(tmp_path / "pip.conf")}
    out = _no_scan("pip install requests", environ=environ, home=tmp_path)
    assert "requests from a registry SkillTotal could not read (set in " in _asked(out)


@pytest.mark.parametrize(("where", "text"), [
    ("project", "tag=next\n"),
    ("project", "tag = next ; prerelease\n"),
    ("project", "tag=latest\ntag='next'\n"),
    ("env", "next"),
])
def test_a_configured_dist_tag_is_the_release_checked(tmp_path, where, text):
    """npm installs a package named without a version from the `tag` it is configured with: a
    clean `latest` must not vouch for a different `next`."""
    project = _project_npmrc(tmp_path, text if where == "project" else "")
    environ = {"npm_config_tag": text} if where == "env" else {}
    assert _checked("npm i lodash && npx -y some-mcp && npm i x@1.2.3", cwd=project,
                    environ=environ, home=tmp_path / "home") == [
        "npm:lodash@next", "npm:some-mcp@next", "npm:x@1.2.3"]


@pytest.mark.parametrize("tag", ["latest", ""])
def test_the_latest_tag_changes_nothing(tmp_path, tag):
    project = _project_npmrc(tmp_path, f"tag={tag}\n" if tag else "")
    assert _checked("npm i lodash", cwd=project, environ={}, home=tmp_path / "home") == [
        "npm:lodash"]


def test_a_dist_tag_the_scan_cannot_ask_for_is_asked_about(tmp_path):
    project = _project_npmrc(tmp_path, "tag=>=1 <2\n")
    out = _no_scan("npm i lodash", cwd=project, environ={}, home=tmp_path / "home")
    assert "lodash at an npm dist-tag SkillTotal could not read (set in " in _asked(out)


# --- yarn, bun, pnpm and uv configuration files -------------------------------------------------


@pytest.mark.parametrize(("name", "text", "command"), [
    (".yarnrc.yml", f'npmRegistryServer: "{CORP}"\n', "yarn add lodash"),
    (".yarnrc.yml", f"npmScopes:\n  corp:\n    npmRegistryServer: {CORP}\n", "yarn dlx lodash"),
    (".yarnrc", f'registry "{CORP}/"\n', "yarn add lodash"),
    ("bunfig.toml", f'[install]\nregistry = "{CORP}/"\n', "bun add lodash"),
    ("bunfig.toml", f'[install]\nregistry = {{ url = "{CORP}/" }}\n', "bunx lodash"),
    ("bunfig.toml", f'[install.scopes]\ncorp = "{CORP}/"\n', "bun add lodash"),
    ("pnpm-workspace.yaml", f"packages:\n  - app\nregistry: {CORP}/\n", "pnpm add lodash"),
])
def test_a_node_tools_own_registry_file_is_read(tmp_path, name, text, command):
    (tmp_path / "app").mkdir()
    (tmp_path / name).write_text(text, encoding="utf-8")
    out = _no_scan(command, cwd=tmp_path / "app", environ={}, home=tmp_path / "home")
    assert "lodash from " in _asked(out)
    # npm itself does not read that file.
    assert _checked("npm i lodash", cwd=tmp_path / "app", environ={},
                    home=tmp_path / "home") == ["npm:lodash"]


@pytest.mark.parametrize(("name", "text"), [
    ("uv.toml", f'index-url = "{CORP_PY}/simple"\n'),
    ("uv.toml", f'[[index]]\nname = "corp"\nurl = "{CORP_PY}/simple"\n'),
    ("uv.toml", f'[pip]\nextra-index-url = ["{CORP_PY}/simple"]\n'),
    ("pyproject.toml", f'[project]\nname = "x"\n\n[tool.uv]\ndefault-index = "{CORP_PY}"\n'),
    ("pyproject.toml", f'[[tool.uv.index]]\nname = "corp"\nurl = "{CORP_PY}/simple"\n'),
])
def test_a_uv_index_in_a_project_file_is_read(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    out = _no_scan("uvx ruff", cwd=tmp_path, environ={}, home=tmp_path / "home")
    assert "ruff from " in _asked(out)
    assert _checked("pip install ruff", cwd=tmp_path, environ={}, home=tmp_path / "home") == [
        "pypi:ruff"]


@pytest.mark.parametrize(("name", "text", "command"), [
    (".yarnrc.yml", 'npmRegistryServer: "https://registry.yarnpkg.com"\nnodeLinker: pnp\n',
     "yarn add lodash"),
    ("bunfig.toml", "[install]\noptional = true\n", "bun add lodash"),
    ("pnpm-workspace.yaml", "packages:\n  - 'apps/*'\n", "pnpm add lodash"),
    ("pyproject.toml", '[project]\nname = "x"\n\n[tool.uv]\ndev-dependencies = []\n', "uvx ruff"),
    ("uv.toml", 'index-url = "https://pypi.org/simple"\n', "uvx ruff"),
])
def test_a_tool_file_without_another_registry_changes_nothing(tmp_path, name, text, command):
    (tmp_path / name).write_text(text, encoding="utf-8")
    assert _checked(command, cwd=tmp_path, environ={}, home=tmp_path / "home") != []
