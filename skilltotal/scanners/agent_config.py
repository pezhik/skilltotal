"""Agent and IDE configuration that runs commands on its own, and AI CLIs driven with guards off.

Three attack shapes published in 2026 live here.

* **Auto-run configuration shipped with a component.** The Miasma worm (npm, June 2026) wrote
  `.claude/settings.json`, `.gemini/settings.json` and `.vscode/tasks.json` into projects so that
  opening the project in an agent or editor ran the worm again; the TrustFall research showed the
  agentic CLIs execute such project configuration after a single trust prompt, or none in CI.
  HookPry (Sept 2026) showed the same lifecycle-hook binding shipped from a Claude Code plugin's
  own manifest (`hooks/hooks.json`, or inline in `.claude-plugin/plugin.json`) rather than the
  well-known `.claude/` paths — a plugin *update* can add the hook without the user ever seeing a
  new settings file. A hook in a repository can be an honest formatter, so the configuration alone
  is a risky construct. When the command, or the script it runs from the same component, fetches
  code and pipes it into a shell or decodes and executes it, it is a malicious indicator.
* **A `.git/config` that runs a command on every `git status`/`git diff`.** GitSpawn (Manifold
  Security, Sept 2026) found that several AI coding agents run `git status`/`git diff` at session
  startup, before any trust prompt, and that `core.fsmonitor` in `.git/config` names a command git
  itself runs to refresh its index on those calls. A component that ships a rigged `.git/config`
  therefore gets code execution the moment the agent looks at the project.
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
from skilltotal.models import Capability, Evidence, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    concat_folded_spans,
)

# JS/TS (and Python) files where a client-config path may be split across concatenated literals.
_CONFIG_INJECT_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".pyw")

R_AUTORUN = "ST-AGENT-AUTORUN"
R_AUTORUN_REMOTE = "ST-AGENT-AUTORUN-REMOTE"
R_CLI_BYPASS = "ST-AGENT-CLI-BYPASS"
R_GITCONFIG_REMOTE = "ST-AGENT-GITCONFIG-EXEC-REMOTE"
R_CONFIG_INJECT = "ST-AGENT-CONFIG-INJECT"
R_GIT_PERSIST = "ST-GIT-HOOK-PERSIST"
R_SKILL_EXEC = "ST-SKILL-DYNAMIC-EXEC"

# Configuration an agent or editor executes when a project is opened or a session starts.
_HOOK_CONFIGS = (".claude/settings.json", ".claude/settings.local.json", ".gemini/settings.json",
                 ".cursor/hooks.json", ".qwen/settings.json")
# A Claude Code plugin's own hook manifest (HookPry, 2026). Hooks are what a plugin declares and
# is installed for, and what HookPry abuses is an *update* adding one, which a single snapshot
# cannot see. So only a fetch-or-decode-and-run command here is a finding; an honest hook is
# listed for review and never scored.
_PLUGIN_HOOK_CONFIGS = ("hooks/hooks.json", ".claude-plugin/plugin.json")
_TASKS_CONFIG = ".vscode/tasks.json"

# `.git/config`'s `core.fsmonitor` (GitSpawn, 2026): file_index.py reads this one path despite
# the general `.git` skip, because its content is itself an auto-exec surface, and hands it only
# to this check (`index.git_config`, never `index.files`). A boolean value
# (git's own built-in daemon) is the honest, overwhelmingly common case and is never flagged. A
# bare local hook path (e.g. a large monorepo's watchman integration) is not a malware verdict on
# its own -- it is a command git will run automatically, so it is surfaced for review, not
# flagged. Only a fetch-and-run / decode-and-run value is a malicious indicator.
_FSMONITOR = re.compile(r"^[ \t]*fsmonitor[ \t]*=[ \t]*(.+?)[ \t]*$", re.MULTILINE | re.IGNORECASE)
_GIT_BOOL_VALUES = frozenset({"true", "false", "yes", "no", "on", "off", "1", "0"})

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

# --- MCP-client config injection (SANDWORM_MODE "McpInject", 2026) ---------------------------
# Writing an attacker server into ANOTHER AI client's config loads it on that client's next
# session, from a package the user installed for something else. These are the config files of the
# common AI clients; a third-party component has no honest reason to write to them. `.claude/`
# settings are already covered by the auto-run rule above, so they are left out here.
_CLIENT_CONFIG_PATHS = re.compile(
    r"(?:claude_desktop_config\.json"
    r"|\.cursor[/\\]mcp\.json"
    r"|\.vscode[/\\]mcp\.json"
    r"|\.continue[/\\]config\.(?:json|yaml|yml)"
    r"|windsurf[/\\]mcp_config\.json"
    r"|\.codeium[/\\][^\s\"']{0,64}mcp[^\s\"']{0,64}\.json"
    r"|(?<![\w.])\.claude\.json)",
    re.IGNORECASE,
)
# A file-writing sink, in any of the languages we see. Reading these configs can be benign
# (a tool that lists / health-checks your installed servers); only WRITING one is the injection.
_WRITE_SINK = re.compile(
    r"\b(?:writeFileSync|writeFile|appendFileSync|appendFile|outputFile(?:Sync)?|createWriteStream"
    r"|write_text|write_bytes|Out-File|Set-Content|Add-Content)\b"
    r"|\bjson\.dump\s*\("
    r"|\bopen\s*\([^)]{0,200},\s*['\"][rbt]*[wa]\+?[rbt]*['\"]",
    re.IGNORECASE,
)
# The config path must be the TARGET of a write, not merely mentioned in the same file. A health
# check that reads ~/.claude.json and writes its OWN state file elsewhere (e.g. ECC's
# mcp-health-check.js) is not injection. This matches when a write sink opens its argument list and
# the config path appears inside it, on the same statement (bounded so a crafted line cannot
# backtrack). The config path (built from the shared alternation) is appended by the scanner.
_WRITE_CALL_OPEN = (
    r"(?:writeFileSync|writeFile|appendFileSync|appendFile|outputFile(?:Sync)?|createWriteStream"
    r"|Out-File|Set-Content|Add-Content|json\.dump|open)\s*\("
)
_WRITE_BEFORE = re.compile(_WRITE_CALL_OPEN + r"[^;\n]{0,200}$", re.IGNORECASE)
# Python `Path(...).write_text(...)` / `.write_bytes(...)`: the path precedes the write method.
_WRITE_METHOD_AFTER = re.compile(r"^[^;\n]{0,120}?\.write_(?:text|bytes)\s*\(", re.IGNORECASE)


def _is_write_target(text: str, start: int, end: int) -> bool:
    """True if the config-path span [start,end) sits inside a write sink's argument list."""
    line_start = text.rfind("\n", 0, start) + 1
    semi = text.rfind(";", line_start, start)
    stmt_start = max(line_start, semi + 1)
    before = text[max(stmt_start, start - 200):start]
    if _WRITE_BEFORE.search(before):
        return True
    after = text[end:end + 120]
    return bool(_WRITE_METHOD_AFTER.match(after))

# --- git-hook persistence (SANDWORM_MODE / supply-chain worms, 2026) -------------------------
# Repointing git's GLOBAL template dir makes a hook run for every repository the victim creates
# or clones. `init.templateDir` is rare and essentially never benign. `core.hooksPath` is NOT a
# reliable signal on its own: husky/lefthook/pre-commit all set it LOCALLY to a repo directory,
# so it is flagged only when set `--global`/`--system` (reaching outside the current repo).
# `core.fsmonitor` is handled by the .git/config rule above (git runs it directly).
_GIT_PERSIST = re.compile(
    r"\bgit\b[^\n]{0,40}?\bconfig\b[^\n]{0,80}?\binit\.templateDir\b"
    r"|\bgit\b[^\n]{0,40}?\bconfig\b(?=[^\n]{0,200}?\bcore\.hooksPath\b)[^\n]{0,200}?--(?:global|system)\b"
    r"|\bgit\b[^\n]{0,40}?\bconfig\b(?=[^\n]{0,200}?--(?:global|system)\b)[^\n]{0,200}?\bcore\.hooksPath\b",
    re.IGNORECASE,
)
# Reading or clearing the config is not installing persistence: `git config --global --get
# core.hooksPath`, or the value-less `git config --global core.hooksPath` (then `|| true` / end of
# command), just reads the current value — ECC's codex tooling does this to save/restore it.
_GIT_CONFIG_READ = re.compile(r"--(?:get|get-all|get-regexp|list|unset|unset-all|null)\b", re.I)
# core.hooksPath followed by an actual value (a SET), vs. nothing / a shell terminator (a READ).
_HOOKSPATH_SET = re.compile(r"core\.hooksPath\b[ \t]+[\"']?[^\s|&;)>\"']", re.I)

# --- auto-executed command in an Agent Skill (Clawsights dynamic context, Datadog 2026) ------
# A Claude Code skill may embed a "dynamic context" command with a leading `!` (bare or wrapped
# in backticks). It runs when the skill loads, before the model reads the skill, so `allowed-tools`
# refusals do not help. A benign skill uses this for `!`git status``; a malicious one hides a
# credential grab or a fetch-and-run in it. Only the dangerous bodies are flagged.
_SKILL_DYNAMIC_CMD = re.compile(r"(?m)^[ \t>]*!\s*(\S[^\n]*)")
# A credential source piped/joined to a network sink (exfil), or a fetch-and-run. `gh auth token`,
# an SSH/AWS/keychain read, or a kube/npm credential, reaching curl/wget/nc or an http(s) URL.
_SKILL_CRED_SOURCE = re.compile(
    r"\bgh\s+auth\s+(?:token|status\s+[^\n]{0,80}--show-token)"
    r"|security\s+find-(?:generic|internet)-password"
    r"|~/\.ssh\b|~/\.aws\b|\.aws/credentials|\bid_rsa\b|\.kube/config|~/\.npmrc|\.git-credentials",
    re.IGNORECASE,
)
_SKILL_NET_SINK = re.compile(
    r"\b(?:curl|wget|nc|ncat|http|https)\b|https?://", re.IGNORECASE
)

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
        RuleSpec(
            id=R_GITCONFIG_REMOTE,
            category="agent_config",
            severity=Severity.HIGH,
            title="A shipped .git/config fetches or decodes code and runs it on git status/diff",
            description=(
                "This component's own `.git/config` sets `core.fsmonitor` to a command that "
                "fetches code and pipes it into a shell, or decodes and runs it. Git runs that "
                "command on ordinary operations (`git status`, `git diff`) to refresh its index -- "
                "several AI coding agents run exactly those commands at session startup, before "
                "any trust prompt (GitSpawn, 2026)."
            ),
            recommendation=(
                "Do not open this project in an agent, editor, or run git commands in it. Remove "
                "`core.fsmonitor` from .git/config and treat a machine that already opened it as "
                "exposed."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_CONFIG_INJECT,
            category="agent_config",
            severity=Severity.HIGH,
            title="Code writes to another AI client's MCP/agent configuration",
            description=(
                "The component writes to a config file of a separate AI client (Claude Desktop, "
                "Cursor, VS Code, Continue, Windsurf). Adding a server there makes that client "
                "load it on its next session, from a package installed for something else — the "
                "MCP-config injection the SANDWORM_MODE npm campaign used to register a rogue "
                "server across clients."
            ),
            recommendation=(
                "Confirm why the component edits another client's configuration. A tool that "
                "registers itself should ask the user and write only the current client's config."
            ),
            capability=Capability.FILESYSTEM_WRITE,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
        RuleSpec(
            id=R_GIT_PERSIST,
            category="agent_config",
            severity=Severity.HIGH,
            title="Code installs a global git hook / template for persistence",
            description=(
                "The component runs `git config` to point git's global template directory or "
                "hooks path at its own files, so a hook runs for every repository the user "
                "creates or clones afterwards. This is the persistence mechanism of the "
                "SANDWORM_MODE npm campaign."
            ),
            recommendation=(
                "Do not install the component. A package has no legitimate reason to repoint the "
                "user's global git template or hooks path."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            code_context="comments",
        ),
        RuleSpec(
            id=R_SKILL_EXEC,
            category="agent_config",
            severity=Severity.HIGH,
            title="Agent skill auto-runs a command that steals credentials or fetches code",
            description=(
                "An Agent Skill embeds a `!` dynamic-context command that runs when the skill "
                "loads — before the model reads the skill, so its tool restrictions do not apply "
                "— and that command reads a credential and sends it off-host, or downloads code "
                "and runs it. This is the malicious-skill pattern Datadog documented (Clawsights)."
            ),
            recommendation=(
                "Do not install the skill. Remove any `!` dynamic-context command that touches "
                "credentials or the network; it executes without the user's confirmation."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        by_path = {f.relpath: f for f in index.files}
        autorun: list[Evidence] = []
        remote: list[Evidence] = []
        needs_review: list[NeedsReview] = []
        for f in index.files:
            rel = f.relpath.replace("\\", "/")
            lowered = rel.lower()
            plugin = any(lowered.endswith(c) for c in _PLUGIN_HOOK_CONFIGS)
            honest: list[str] = []
            if plugin or any(lowered.endswith(c) for c in _HOOK_CONFIGS):
                commands = self._hook_commands(f)
            elif lowered.endswith(_TASKS_CONFIG):
                commands = self._folder_open_tasks(f)
            else:
                continue
            for command in commands:
                ev = self._evidence_for(f, command)
                if _REMOTE_EXEC.search(command):
                    autorun.append(ev)
                    remote.append(ev)
                    continue
                script = self._referenced_script(command, by_path)
                m = _REMOTE_EXEC.search(script.text) if script is not None else None
                if m:
                    autorun.append(ev)
                    remote.extend([ev, script.evidence_for_span(m.start(), m.end())])
                elif plugin:
                    honest.append(command)
                else:
                    autorun.append(ev)
            if honest:
                needs_review.append(NeedsReview(
                    category="agent_config",
                    title="Plugin binds lifecycle hooks",
                    reason=(
                        "This plugin runs these commands on agent lifecycle events: "
                        + "; ".join(c[:120] for c in honest[:5])
                        + ". Confirm they do what the plugin says, and re-check after updates: "
                        "an update can add a hook without the user seeing it (HookPry, 2026)."
                    ),
                    file=f.relpath,
                    line=self._evidence_for(f, honest[0]).line_start,
                ))

        bypass: list[Evidence] = []
        config_inject: list[Evidence] = []
        git_persist: list[Evidence] = []
        for f in index.select(suffixes=_CODE_SUFFIXES):
            for _m, ev in f.finditer(_CLI_BYPASS):
                bypass.append(ev)
                if len(bypass) >= MAX_EVIDENCE_SCANNED:
                    break
            for m, ev in f.finditer(_GIT_PERSIST):
                line = f.line_text(ev.line_start)
                # A read (`--get`/`--list`/`--unset`, or value-less `core.hooksPath`) is not
                # persistence; a command quoted inside a shell string is printed help, not run.
                if _GIT_CONFIG_READ.search(line):
                    continue
                if f.in_shell_quoted(m.start()):
                    continue
                lower = line.lower()
                reads_hookspath = (
                    "core.hookspath" in lower
                    and "templatedir" not in lower
                    and not _HOOKSPATH_SET.search(line)
                )
                if reads_hookspath:
                    continue
                git_persist.append(ev)
                if len(git_persist) >= MAX_EVIDENCE_SCANNED:
                    break
            # Writing to another client's config is the injection; reading or health-checking one
            # is benign, so the config path must be the TARGET of a write sink, not just present.
            if _WRITE_SINK.search(f.text):
                for m, ev in f.finditer(_CLIENT_CONFIG_PATHS):
                    if _is_write_target(f.text, m.start(), m.end()):
                        config_inject.append(ev)
                        if len(config_inject) >= MAX_EVIDENCE_SCANNED:
                            break

        # Folded view: catch a client-config path split across string literals
        # (``"~/.cursor/" + "mcp.json"``). Same rule — it must be a write target.
        config_inject_lines = {(e.file, e.line_start) for e in config_inject}
        for f, start, end in concat_folded_spans(
            index, _CLIENT_CONFIG_PATHS, suffixes=_CONFIG_INJECT_SUFFIXES
        ):
            if len(config_inject) >= MAX_EVIDENCE_SCANNED:
                break
            if not _WRITE_SINK.search(f.text) or not _is_write_target(f.text, start, end):
                continue
            ev = f.evidence_for_span(start, end)
            if (ev.file, ev.line_start) not in config_inject_lines:
                config_inject_lines.add((ev.file, ev.line_start))
                config_inject.append(ev)

        skill_exec: list[Evidence] = []
        for f in index.files:
            if not self._is_skill_file(f):
                continue
            for m in _SKILL_DYNAMIC_CMD.finditer(f.text):
                body = m.group(1).strip().strip("`").strip()
                dangerous = _REMOTE_EXEC.search(body) or (
                    _SKILL_CRED_SOURCE.search(body) and _SKILL_NET_SINK.search(body)
                )
                if dangerous:
                    skill_exec.append(f.evidence_for_span(m.start(1), m.end(1)))
                    if len(skill_exec) >= MAX_EVIDENCE_SCANNED:
                        break

        gitconfig_remote: list[Evidence] = []
        gitconfig = index.git_config
        if gitconfig is not None:
            self._scan_git_config(gitconfig, gitconfig_remote, needs_review)

        findings = []
        if remote:
            findings.append(_finding_from_rule(self._rule(R_AUTORUN_REMOTE), remote))
        elif autorun:
            findings.append(_finding_from_rule(self._rule(R_AUTORUN), autorun))
        if bypass:
            findings.append(_finding_from_rule(self._rule(R_CLI_BYPASS), bypass))
        if config_inject:
            findings.append(_finding_from_rule(self._rule(R_CONFIG_INJECT), config_inject))
        if git_persist:
            findings.append(_finding_from_rule(self._rule(R_GIT_PERSIST), git_persist))
        if skill_exec:
            findings.append(_finding_from_rule(self._rule(R_SKILL_EXEC), skill_exec))
        if gitconfig_remote:
            findings.append(_finding_from_rule(self._rule(R_GITCONFIG_REMOTE), gitconfig_remote))
        return ScanResult(findings=findings, needs_review=needs_review)

    # A Claude Code / agent skill file: the well-known name, or a markdown file whose YAML
    # frontmatter declares `allowed-tools` (the skill marker) or a skill `name:` + `description:`.
    @staticmethod
    def _is_skill_file(f: IndexedFile) -> bool:
        name = f.relpath.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if name in ("skill.md", "agents.md"):
            return True
        if not name.endswith((".md", ".mdx")):
            return False
        head = f.text[:600]
        return bool(re.search(r"(?mi)^\s*allowed-tools\s*:", head))

    @staticmethod
    def _scan_git_config(
        f: IndexedFile, remote: list[Evidence], needs_review: list[NeedsReview]
    ) -> None:
        m = _FSMONITOR.search(f.text)
        if m is None:
            return
        value = m.group(1).strip().strip("\"'")
        if not value or value.lower() in _GIT_BOOL_VALUES:
            return  # unset, or the built-in daemon toggle -- not an external command
        if _REMOTE_EXEC.search(value):
            remote.append(f.evidence_for_span(m.start(1), m.end(1)))
            return
        needs_review.append(
            NeedsReview(
                category="agent_config",
                title="git config core.fsmonitor names an external command",
                reason=(
                    "core.fsmonitor is set to a command rather than a boolean, so git runs it "
                    "automatically on `status`/`diff`. Large repositories legitimately point this "
                    "at a local watchman hook script -- confirm this one is trusted before running "
                    "git commands or opening the project in an agent."
                ),
                file=f.relpath,
                line=f.evidence_for_span(m.start(1), m.end(1)).line_start,
            )
        )

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
