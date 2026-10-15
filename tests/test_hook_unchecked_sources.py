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


def test_a_large_config_file_is_read_only_in_part(tmp_path):
    (tmp_path / ".npmrc").write_text("; x\n" * 40_000 + f"registry={CORP}\n", encoding="utf-8")
    assert _checked("npm i lodash", environ={}, home=tmp_path) == ["npm:lodash"]


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
