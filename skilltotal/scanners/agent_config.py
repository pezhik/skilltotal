"""Agent and IDE configuration that runs commands on its own, and AI CLIs driven with guards off.

Two attack shapes published in 2026 live here.

* **Auto-run configuration shipped with a component.** The Miasma worm (npm, June 2026) wrote
  `.claude/settings.json`, `.gemini/settings.json` and `.vscode/tasks.json` into projects so that
  opening the project in an agent or editor ran the worm again; the TrustFall research showed the
  agentic CLIs execute such project configuration after a single trust prompt, or none in CI.
  A hook in a repository can be an honest formatter, so the configuration alone is a risky
  construct. When the command, or the script it runs from the same component, fetches code and
  pipes it into a shell or decodes and executes it, it is a malicious indicator.
* **An AI coding CLI launched with its permission checks disabled.** The s1ngularity and
  Shai-Hulud npm campaigns drove the victim's own `claude`/`gemini`/`q` CLI with flags such as
  `--dangerously-skip-permissions` and `--yolo` to search the disk for secrets. Honest wrappers
  do this too, so it is a risky construct, not a verdict.

Detection patterns below are string literals; nothing here executes a command.
"""

from __future__ import annotations

import json
import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_PER_FINDING,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)

R_AUTORUN = "ST-AGENT-AUTORUN"
R_AUTORUN_REMOTE = "ST-AGENT-AUTORUN-REMOTE"
R_CLI_BYPASS = "ST-AGENT-CLI-BYPASS"

# Configuration an agent or editor executes when a project is opened or a session starts.
_HOOK_CONFIGS = (".claude/settings.json", ".claude/settings.local.json", ".gemini/settings.json",
                 ".cursor/hooks.json", ".qwen/settings.json")
_TASKS_CONFIG = ".vscode/tasks.json"

# Fetch-and-run or decode-and-run, in a shell command or in the source of a script.
_REMOTE_EXEC = re.compile(
    r"(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|base64\s+(?:-d|-D|--decode)\b[^\n]*\|\s*(?:ba|z)?sh\b"
    r"|\b(?:iex|Invoke-Expression)\b[^\n]*\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b"
    r"|\bpowershell(?:\.exe)?\b[^\n]*\s-(?:e|enc|encodedcommand)\s"
    r"|\beval\s*\(\s*(?:await\s+)?\(?\s*(?:await\s+)?fetch\s*\("
    r"|\bexec\s*\(\s*(?:urllib\.request\.)?urlopen\s*\(",
    re.IGNORECASE,
)

_AI_CLIS = r"(?:claude|gemini|codex|kiro(?:-cli)?|opencode|aider|cursor-agent|qwen|amp|q\s+chat)"
_BYPASS_FLAGS = (
    r"(?:--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|"
    r"--trust-all-tools|--allow-all-tools|--approval-mode[= ]yolo)"
)
_CLI_BYPASS = re.compile(rf"\b{_AI_CLIS}\b[^\n]{{0,160}}?{_BYPASS_FLAGS}", re.IGNORECASE)
_CODE_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".sh", ".bash", ".zsh", ".ps1")

# A path-looking token in a command that may name a script shipped in the component.
_PATH_TOKEN = re.compile(r"[\w.${}/\\-]+\.(?:m?js|cjs|ts|py|sh|bash|ps1)\b")


class AgentConfigScanner(Scanner):
    name = "agent_config"
    rules = [
        RuleSpec(
            id=R_AUTORUN,
            category="agent_config",
            severity=Severity.MEDIUM,
            title="Agent or editor configuration runs a command automatically",
            description=(
                "The component ships agent or IDE configuration that executes a command without "
                "a separate step: a Claude Code / Gemini CLI / Cursor hook, or a VS Code task "
                "that runs when the folder opens. Opening the project in that tool runs it with "
                "the developer's privileges."
            ),
            recommendation=(
                "Read the command and anything it runs before opening this project in an agent "
                "or editor. A published package has no reason to ship project auto-run config."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
        RuleSpec(
            id=R_AUTORUN_REMOTE,
            category="agent_config",
            severity=Severity.HIGH,
            title="Auto-run agent configuration fetches or decodes code and executes it",
            description=(
                "An automatically executed agent/IDE hook or task, or the script it runs from "
                "this component, downloads code and pipes it into a shell or decodes and runs "
                "it. This is how the Miasma npm worm re-infected projects through .claude/, "
                ".gemini/ and .vscode/ configuration."
            ),
            recommendation=(
                "Do not open the project in an agent or editor. Remove the configuration and "
                "treat the machine that already opened it as exposed."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_CLI_BYPASS,
            category="agent_config",
            severity=Severity.HIGH,
            title="Code launches an AI coding CLI with its permission checks disabled",
            description=(
                "Code runs a local AI coding agent (claude, gemini, codex, q …) with a flag that "
                "turns off its approval prompts. The agent then acts with the user's credentials "
                "and file access and nobody confirms what it does; the s1ngularity and "
                "Shai-Hulud npm campaigns used exactly this to search disks for secrets."
            ),
            recommendation=(
                "Confirm why the component drives an AI agent unattended and what prompt it "
                "sends. Prefer explicit, narrow tool allowlists over disabling approvals."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            code_context="comments",
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        by_path = {f.relpath: f for f in index.files}
        autorun: list[Evidence] = []
        remote: list[Evidence] = []
        for f in index.files:
            rel = f.relpath.replace("\\", "/")
            lowered = rel.lower()
            if any(lowered.endswith(c) for c in _HOOK_CONFIGS):
                commands = self._hook_commands(f)
            elif lowered.endswith(_TASKS_CONFIG):
                commands = self._folder_open_tasks(f)
            else:
                continue
            for command in commands:
                ev = self._evidence_for(f, command)
                autorun.append(ev)
                if _REMOTE_EXEC.search(command):
                    remote.append(ev)
                    continue
                script = self._referenced_script(command, by_path)
                if script is not None:
                    m = _REMOTE_EXEC.search(script.text)
                    if m:
                        remote.extend([ev, script.evidence_for_span(m.start(), m.end())])

        bypass: list[Evidence] = []
        for f in index.select(suffixes=_CODE_SUFFIXES):
            for _m, ev in f.finditer(_CLI_BYPASS):
                bypass.append(ev)
                if len(bypass) >= MAX_EVIDENCE_PER_FINDING:
                    break

        findings = []
        if remote:
            findings.append(_finding_from_rule(self._rule(R_AUTORUN_REMOTE), remote))
        elif autorun:
            findings.append(_finding_from_rule(self._rule(R_AUTORUN), autorun))
        if bypass:
            findings.append(_finding_from_rule(self._rule(R_CLI_BYPASS), bypass))
        return ScanResult(findings=findings)

    def _rule(self, rule_id: str) -> RuleSpec:
        return next(r for r in self.rules if r.id == rule_id)

    @staticmethod
    def _load(f: IndexedFile) -> object:
        text = re.sub(r"^\s*//.*$", "", f.text, flags=re.MULTILINE)  # tasks.json allows comments
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None

    def _hook_commands(self, f: IndexedFile) -> list[str]:
        data = self._load(f)
        hooks = data.get("hooks") if isinstance(data, dict) else None
        found: list[str] = []

        def walk(node: object) -> None:
            if isinstance(node, dict):
                command = node.get("command")
                if isinstance(command, str) and command.strip():
                    found.append(command)
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        if hooks is not None:
            walk(hooks)
        return found

    def _folder_open_tasks(self, f: IndexedFile) -> list[str]:
        data = self._load(f)
        tasks = data.get("tasks") if isinstance(data, dict) else None
        found = []
        for task in tasks if isinstance(tasks, list) else []:
            if not isinstance(task, dict):
                continue
            run_on = (task.get("runOptions") or {}).get("runOn")
            command = task.get("command")
            if run_on == "folderOpen" and isinstance(command, str):
                args = task.get("args") or []
                found.append(" ".join([command, *[a for a in args if isinstance(a, str)]]))
        return found

    @staticmethod
    def _evidence_for(f: IndexedFile, command: str) -> Evidence:
        at = f.text.find(json.dumps(command)[1:-1])
        if at < 0:
            at = max(0, f.text.find('"command"'))
        return f.evidence_for_span(at, at + 1)

    @staticmethod
    def _referenced_script(command: str, by_path: dict[str, IndexedFile]) -> IndexedFile | None:
        for token in _PATH_TOKEN.findall(command):
            cleaned = re.sub(r"^(?:\$\{?\w+\}?[/\\])+", "", token)
            cleaned = re.sub(r"^(?:\.[/\\])+", "", cleaned).replace("\\", "/")
            if cleaned in by_path:
                return by_path[cleaned]
        return None
