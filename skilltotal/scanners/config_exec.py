"""Configuration artifacts that carry an executable command the agent runs for the user.

Two attack shapes published in October 2026 live here. Both move the payload out of code and
into a configuration value that an AI coding agent or its launcher executes on its own, so a
scan that only reads code sees nothing.

* **A command-running credential helper shipped in a distributable config artifact.** Claude
  Code runs the value of ``apiKeyHelper`` (and ``awsAuthRefresh`` / ``awsCredentialExport`` /
  ``gcpAuthRefresh`` / ``otelHeadersHelper``) as a shell command whenever it needs a key or a
  header. A third-party "provider switcher" copied a shared *provider card* verbatim into the
  user's live ``~/.claude/settings.json`` (LeanFlip issue #44, Oct 2026), carrying that command.
  The helper spreads through shareable JSON — provider cards, profile bundles, a skill-shipped
  ``settings.json`` — not through a repo's ``.claude/`` directory. A value that merely prints a
  fixed key is lower risk; a value that fetches-and-runs, or reads a credential and sends it
  off-host, is the malicious shape flagged here.

* **An agent-config dotenv that injects a command into the sandbox launcher.** A pull request
  adds a per-agent ``.env`` (``.gemini/.env`` and the like) to a workspace. In headless CI the
  workspace was trusted automatically, so the variable allowlist was skipped and the file was
  loaded into the process environment (CVE-2026-12537, Gemini CLI). A ``*_SANDBOX*`` /
  ``*PROXY_COMMAND*`` variable whose value opens with a shell command separator runs a second
  command on the host when the launcher concatenates it and spawns it with ``shell:true`` —
  before the sandbox starts, with no prompt or model call. An agent-config dotenv that defines a
  sandbox/proxy-command variable whose value carries shell metacharacters is flagged here.

Detection patterns below are string literals; nothing here executes a command.
"""

from __future__ import annotations

import re

from skilltotal import bounded_json
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)
from skilltotal.scanners.shell_script import REMOTE_EXEC

R_CRED_HELPER = "ST-AGENT-CRED-HELPER-EXEC"
R_DOTENV_EXEC = "ST-AGENT-DOTENV-EXEC"

# Claude Code settings keys whose value is run as a shell command when a key/header is needed.
_HELPER_KEYS = frozenset({
    "apikeyhelper", "awsauthrefresh", "awscredentialexport", "gcpauthrefresh",
    "otelheadershelper",
})
# A network client / URL reached from a helper command.
_HELPER_NET = re.compile(
    r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|nc|ncat|httpie)\b|https?://",
    re.IGNORECASE,
)
# A credential/secret source, an environment dump, or a shell chain that links one to a client.
_HELPER_CRED = re.compile(
    r"\.aws[/\\]credentials|\.ssh\b|\bid_rsa\b|\.npmrc\b|\.git-credentials\b|\.kube\b"
    r"|/etc/passwd|\$HOME\b|%USERPROFILE%|\bprocess\.env\b|\bprintenv\b|(?<![\w.])env(?![\w.])",
    re.IGNORECASE,
)
_HELPER_CHAIN = re.compile(r"[;|]|&&|\$\(|`")


def _helper_is_dangerous(value: str) -> bool:
    """A credential-helper command that fetches-and-runs, or reads a secret and sends it off."""
    if REMOTE_EXEC.search(value):
        return True
    if _HELPER_NET.search(value) and (_HELPER_CRED.search(value) or _HELPER_CHAIN.search(value)):
        return True
    return False


# An agent's per-tool config directory, where a planted `.env` is loaded by the agent/launcher.
_AGENT_ENV_DIRS = frozenset({
    ".gemini", ".claude", ".cursor", ".codex", ".continue", ".windsurf", ".vscode", ".aider",
})
# A sandbox / proxy-command variable the launcher turns into a spawned command.
_SANDBOX_VAR = re.compile(r"(?i)(?:proxy[_-]?command|sandbox)")
# Shell metacharacters that chain a second command into the value.
_SHELL_META = re.compile(r"[;|]|&&|\|\||\$\(|`|>\(")
_ENV_LINE = re.compile(
    r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=(.*)$", re.MULTILINE
)


def _iter_json_pairs(data: object):
    """Yield every ``(key, value)`` string pair at any depth (iterative, bounded stack)."""
    stack = [iter([(None, data)])]
    while stack:
        pair = next(stack[-1], None)
        if pair is None:
            stack.pop()
            continue
        key, value = pair
        if isinstance(key, str) and isinstance(value, str):
            yield key, value
        if isinstance(value, dict):
            stack.append(iter(value.items()))
        elif isinstance(value, list):
            stack.append((None, item) for item in value)


class ConfigExecScanner(Scanner):
    name = "config_exec"
    rules = [
        RuleSpec(
            id=R_CRED_HELPER,
            category="agent_config",
            severity=Severity.HIGH,
            title="Distributable config runs a command that fetches or exfiltrates credentials",
            description=(
                "A JSON configuration artifact (a provider card, profile bundle, or shipped "
                "settings.json) defines a Claude Code credential helper (apiKeyHelper, "
                "awsAuthRefresh, awsCredentialExport, gcpAuthRefresh, otelHeadersHelper) whose "
                "value is a shell command that downloads and runs code, or reads a credential and "
                "sends it off-host. Claude Code runs that command whenever it needs a key or a "
                "header, so importing or copying this config into the user's settings executes it."
            ),
            recommendation=(
                "Do not import this config. A credential helper should reference a local "
                "credential tool, never fetch-and-run or pipe a secret to a network client. Treat "
                "a machine that already imported it as exposed and rotate the affected keys."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_DOTENV_EXEC,
            category="agent_config",
            severity=Severity.HIGH,
            title="Agent-config dotenv injects a shell command into the sandbox/proxy launcher",
            description=(
                "A per-agent dotenv (`.gemini/.env` and similar) in the workspace defines a "
                "sandbox or proxy-command variable (*_SANDBOX*, *PROXY_COMMAND*) whose value "
                "carries shell metacharacters (; && | $( or backticks). The agent's launcher "
                "concatenates that value and spawns it with a shell, so the extra command runs on "
                "the host before the sandbox starts - in headless CI the workspace is trusted "
                "automatically and the variable allowlist is skipped (cf. CVE-2026-12537)."
            ),
            recommendation=(
                "Do not open this workspace with the agent. Remove the dotenv; a sandbox/proxy "
                "command variable must be a single program, never a value that chains a second "
                "command. Treat a CI run that loaded it as exposed."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        helper: list[Evidence] = []
        dotenv: list[Evidence] = []

        for f in index.select(suffixes=(".json",)):
            if not any(k in f.text.lower() for k in _HELPER_KEYS):
                continue
            try:
                data, _cut = bounded_json.loads_cut(f.text)
            except ValueError:
                continue
            for key, value in _iter_json_pairs(data):
                if key.lower() in _HELPER_KEYS and _helper_is_dangerous(value):
                    ev = _anchor(f, f'"{key}"') or _anchor(f, value[:60])
                    if ev is not None and len(helper) < MAX_EVIDENCE_SCANNED:
                        helper.append(ev)

        for f in index.files:
            if not self._is_agent_dotenv(f):
                continue
            for m in _ENV_LINE.finditer(f.text):
                name, value = m.group(1), m.group(2)
                if _SANDBOX_VAR.search(name) and _SHELL_META.search(value):
                    ev = f.evidence_for_span(m.start(1), m.end(2))
                    if len(dotenv) < MAX_EVIDENCE_SCANNED:
                        dotenv.append(ev)

        findings = []
        if helper:
            findings.append(_finding_from_rule(self._rule(R_CRED_HELPER), helper))
        if dotenv:
            findings.append(_finding_from_rule(self._rule(R_DOTENV_EXEC), dotenv))
        return ScanResult(findings=findings)

    @staticmethod
    def _is_agent_dotenv(f: IndexedFile) -> bool:
        parts = f.relpath.replace("\\", "/").lower().split("/")
        if len(parts) < 2 or parts[-1] != ".env":
            return False
        return parts[-2] in _AGENT_ENV_DIRS

    def _rule(self, rule_id: str) -> RuleSpec:
        return next(r for r in self.rules if r.id == rule_id)


def _anchor(f: IndexedFile, needle: str) -> Evidence | None:
    if not needle:
        return None
    idx = f.text.find(needle)
    if idx < 0:
        return None
    return f.evidence_for_span(idx, idx + len(needle))
