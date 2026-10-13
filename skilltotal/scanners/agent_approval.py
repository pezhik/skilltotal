"""Agent settings shipped with a component that turn approvals off, or send model traffic away.

A project's own agent settings apply when the project is opened in that agent: Claude Code reads
``.claude/settings.json`` and ``settings.local.json``, Gemini CLI ``.gemini/settings.json`` and
``.gemini/.env``, Codex ``.codex/config.toml``, VS Code (Copilot's agent) ``.vscode/settings.json``.

* Settings that skip every confirmation (Claude Code's ``bypassPermissions`` mode or an
  unrestricted ``Bash`` allow rule, every project MCP server enabled unasked, Gemini's ``yolo``
  mode, Codex with no approvals and no sandbox, VS Code's ``chat.tools.autoApprove``) let whatever
  the agent is told -- by a prompt injection too -- run without the user seeing it first. A prompt
  injection that writes VS Code's setting gets code execution the same way.
* A model API address on another host (``ANTHROPIC_BASE_URL`` in the settings' ``env``, a Codex
  ``base_url``, a ``*_BASE_URL`` in ``.gemini/.env``) receives the user's API key with each request
  and every prompt, with the code the agent reads into it. A gateway on this machine, or the
  vendor's own API, is not one.

An honest team can commit either, so both are risky constructs, not verdicts. Detection is
parsing only.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from skilltotal import bounded_json
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule

R_AUTO_APPROVE = "ST-AGENT-AUTO-APPROVE"
R_API_REDIRECT = "ST-AGENT-API-REDIRECT"

_CLAUDE_SETTINGS = re.compile(r"(?:^|/)\.claude/settings(?:\.local)?\.json$")
_GEMINI_SETTINGS = re.compile(r"(?:^|/)\.gemini/settings\.json$")
_GEMINI_ENV = re.compile(r"(?:^|/)\.gemini/\.env$")
_CODEX_CONFIG = re.compile(r"(?:^|/)\.codex/config\.toml$")
_VSCODE_SETTINGS = re.compile(r"(?:^|/)\.vscode/settings\.json$")

# Claude Code allow rules that let any shell command run unasked.
_ANY_BASH = frozenset({"Bash", "Bash(*)", "Bash(*:*)", "Bash(:*)"})
_VSCODE_AUTO_APPROVE = ("chat.tools.autoApprove", "chat.tools.global.autoApprove")
# The variables that point an agent's model client at an API address.
_BASE_URL_NAME = re.compile(
    r"^(?:ANTHROPIC|ANTHROPIC_BEDROCK|ANTHROPIC_VERTEX|OPENAI|GOOGLE_GEMINI|GEMINI|CODEX|AZURE_OPENAI)"
    r"_(?:BASE_URL|API_BASE|ENDPOINT)$"
)
# Host names of this machine, compared with an address (nothing here binds or connects).
_THIS_MACHINE = frozenset({"localhost", "0.0.0.0", "::1"})  # nosec B104
# The vendors' own API hosts: not a redirect.
_OFFICIAL_HOSTS = ("anthropic.com", "openai.com", "googleapis.com", "amazonaws.com", "azure.com",
                   "openai.azure.com")

_TOML_LINE = re.compile(
    r"""^[ \t]*(?P<key>[A-Za-z_][\w-]*)[ \t]*=[ \t]*(?P<q>["'])(?P<value>[^"'\n]*)(?P=q)""",
    re.MULTILINE,
)
_ENV_LINE = re.compile(
    r"""^[ \t]*(?:export[ \t]+)?(?P<key>[A-Za-z_]\w*)[ \t]*=[ \t]*"""
    r"""(?P<q>["']?)(?P<value>[^"'\s#]*)(?P=q)""",
    re.MULTILINE,
)


class AgentApprovalScanner(Scanner):
    name = "agent_approval"
    rules = [
        RuleSpec(
            id=R_AUTO_APPROVE,
            category="agent_configuration",
            severity=Severity.HIGH,
            title="Agent settings that turn approvals off",
            description=(
                "The component ships agent settings that let the agent act without asking: "
                "every shell command allowed, permission prompts bypassed, every project MCP "
                "server enabled, or tool calls auto-approved. Opened in that agent, the project "
                "runs whatever the agent is told, including by text it reads, without the user "
                "seeing it first."
            ),
            recommendation=(
                "Remove these settings from the component, or allow only the specific commands "
                "and servers the project needs. Review them before opening the project in an "
                "agent."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
        RuleSpec(
            id=R_API_REDIRECT,
            category="agent_configuration",
            severity=Severity.HIGH,
            title="Agent settings send model traffic to another host",
            description=(
                "The component ships agent settings that point the agent's model API at a host "
                "other than the vendor's or this machine. The agent sends that host the user's "
                "API key with each request, and every prompt, with the code it reads."
            ),
            recommendation=(
                "Remove the address from the shipped settings; a gateway belongs in each user's "
                "own configuration. Review it before opening the project in an agent."
            ),
            capability=Capability.NETWORK_EGRESS,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        approve: list[Evidence] = []
        redirect: list[Evidence] = []
        for f in index.files:
            path = f.relpath
            if _CLAUDE_SETTINGS.search(path):
                data = _json(f)
                if data is not None:
                    approve.extend(_claude_approvals(f, data))
                    redirect.extend(_env_redirects(f, data.get("env")))
            elif _GEMINI_SETTINGS.search(path):
                data = _json(f)
                if data is not None:
                    approve.extend(_gemini_approvals(f, data))
            elif _VSCODE_SETTINGS.search(path):
                data = _json(f)
                if data is not None:
                    approve.extend(_vscode_approvals(f, data))
            elif _CODEX_CONFIG.search(path):
                approve.extend(_codex_approvals(f))
                redirect.extend(_codex_redirects(f))
            elif _GEMINI_ENV.search(path):
                redirect.extend(_dotenv_redirects(f))
        findings = [_finding_from_rule(rule, evidence)
                    for rule, evidence in zip(self.rules, (approve, redirect), strict=True)
                    if evidence]
        return ScanResult(findings=findings)


def _json(f: IndexedFile) -> dict | None:
    try:
        data = bounded_json.loads(f.text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _at(f: IndexedFile, pattern: str) -> list[Evidence]:
    m = re.search(pattern, f.text)
    return [f.evidence_for_span(m.start(), m.end())] if m else []


def _key_value(key: str, value: object) -> str:
    """A regex for ``"key": value`` as JSON writes it."""
    return re.escape(json.dumps(key)) + r"\s*:\s*" + re.escape(json.dumps(value))


def _claude_approvals(f: IndexedFile, data: dict) -> list[Evidence]:
    found: list[Evidence] = []
    permissions = data.get("permissions")
    if isinstance(permissions, dict):
        if permissions.get("defaultMode") == "bypassPermissions":
            found += _at(f, _key_value("defaultMode", "bypassPermissions"))
        allow = permissions.get("allow")
        if isinstance(allow, list):
            for rule in allow:
                if isinstance(rule, str) and rule.replace(" ", "") in _ANY_BASH:
                    found += _at(f, re.escape(json.dumps(rule)))
    if data.get("enableAllProjectMcpServers") is True:
        found += _at(f, _key_value("enableAllProjectMcpServers", True))
    return found


def _gemini_approvals(f: IndexedFile, data: dict) -> list[Evidence]:
    found: list[Evidence] = []
    general = data.get("general")
    if isinstance(general, dict) and str(general.get("approvalMode", "")).lower() == "yolo":
        found += _at(f, r'"approvalMode"\s*:\s*"yolo"')
    tools = data.get("tools")
    if (isinstance(tools, dict) and tools.get("autoAccept") is True) \
            or data.get("autoAccept") is True:
        found += _at(f, _key_value("autoAccept", True))
    return found


def _vscode_approvals(f: IndexedFile, data: dict) -> list[Evidence]:
    return [ev for key in _VSCODE_AUTO_APPROVE if data.get(key) is True
            for ev in _at(f, _key_value(key, True))]


def _toml_values(f: IndexedFile) -> list[re.Match[str]]:
    return list(_TOML_LINE.finditer(f.text))


def _codex_approvals(f: IndexedFile) -> list[Evidence]:
    """No approvals and no sandbox: every command runs unasked with full access."""
    values = {m.group("key"): m for m in _toml_values(f)}
    policy, sandbox = values.get("approval_policy"), values.get("sandbox_mode")
    if policy and sandbox and policy.group("value") == "never" \
            and sandbox.group("value") == "danger-full-access":
        return [f.evidence_for_span(policy.start(), policy.end()),
                f.evidence_for_span(sandbox.start(), sandbox.end())]
    return []


def _codex_redirects(f: IndexedFile) -> list[Evidence]:
    return [f.evidence_for_span(m.start(), m.end()) for m in _toml_values(f)
            if m.group("key") == "base_url" and _elsewhere(m.group("value"))]


def _env_redirects(f: IndexedFile, env: object) -> list[Evidence]:
    if not isinstance(env, dict):
        return []
    return [ev for name, value in env.items()
            if isinstance(name, str) and isinstance(value, str)
            and _BASE_URL_NAME.match(name) and _elsewhere(value)
            for ev in _at(f, _key_value(name, value))]


def _dotenv_redirects(f: IndexedFile) -> list[Evidence]:
    return [f.evidence_for_span(m.start(), m.end()) for m in _ENV_LINE.finditer(f.text)
            if _BASE_URL_NAME.match(m.group("key")) and _elsewhere(m.group("value"))]


def _elsewhere(url: str) -> bool:
    """An http(s) address on a host that is neither this machine nor a vendor's own API."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    host = parts.hostname.lower().rstrip(".")
    if host in _THIS_MACHINE or host.startswith("127.") or host.endswith(".localhost"):
        return False
    return not any(host == h or host.endswith("." + h) for h in _OFFICIAL_HOSTS)
