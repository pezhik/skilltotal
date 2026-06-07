"""MCP (Model Context Protocol) discovery and risk analysis.

Discovers MCP manifests / tool definitions and classifies declared tools by the dangerous
capability their name or description implies (filesystem, shell, network, browser,
credential). Also flags ``mcpServers`` entries that launch a binary via a ``command``.
Every emitted finding is anchored to the exact line of the offending key/name in the
manifest source.
"""

from __future__ import annotations

import json
import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity
from skilltotal.scanners.base import (
    MAX_EVIDENCE_PER_FINDING,
    RuleSpec,
    Scanner,
    ScanResult,
    alternation,
)

CATEGORY = "mcp"

MANIFEST_NAMES = {
    "mcp.json",
    ".mcp.json",
    "mcp.config.json",
    "server.json",
    "manifest.json",
}

# name/description keyword -> dangerous capability label
DANGEROUS_TOOL_PATTERNS: dict[str, re.Pattern[str]] = {
    "shell": re.compile(
        r"run_command|run_shell|shell_exec|exec_command|\bshell\b|terminal|\bbash\b|"
        r"\bexec\b|subprocess|system\b|spawn|execute_command",
        re.IGNORECASE,
    ),
    "filesystem": re.compile(
        r"read_file|write_file|delete_file|remove_file|list_dir|read_path|file_read|"
        r"file_write|filesystem|\bfs\b|edit_file",
        re.IGNORECASE,
    ),
    "network": re.compile(
        r"fetch_url|fetch\b|http_get|http_post|\burl\b|download|\bcurl\b|webhook|"
        r"send_request|post_to",
        re.IGNORECASE,
    ),
    "browser": re.compile(
        r"browser|navigate|puppeteer|playwright|screenshot|page_goto|open_page",
        re.IGNORECASE,
    ),
    "credential": re.compile(
        r"token|secret|credential|password|api[_-]?key|read_env|get_env|getenv|"
        r"keychain|vault",
        re.IGNORECASE,
    ),
}

# Tool-poisoning signatures (MCPTox-style): agent-directed instructions hidden in a tool's
# description/metadata, rather than documentation of what the tool does. These are distinct
# from the generic prompt-injection phrases in prompt_surface.py and are scoped to MCP tool
# surfaces, so matches are high-signal / low false-positive.
_POISONING = alternation(
    # Fake authority / hidden-block markers smuggled into a description.
    r"<\s*(?:important|system|secret|instructions?)\s*>",
    r"\[\s*(?:system|important|instructions?)\s*\]",
    r"(?:system|developer|admin(?:istrator)?)\s+(?:note|message|instruction)\s*:",
    # Imperatives aimed at the agent about *this* tool.
    r"before\s+(?:using|calling|invoking|running)\s+(?:this\s+)?tool",
    r"(?:always|first)\s+(?:call|use|invoke|run)\s+[^\n]{0,40}?\b(?:first|before)\b",
    r"ignore\s+(?:the\s+)?(?:tool['’]?s?\s+)?(?:actual\s+)?(?:description|purpose|instructions)",
    # Covert behaviour / exfiltration directed at the agent from within metadata.
    r"do\s+not\s+(?:tell|inform|mention|reveal|notify)[^\n]{0,30}user",
    r"(?:secretly|silently|without\s+(?:telling|informing)\s+the\s+user)",
    flags=re.IGNORECASE,
)

# Source-level signals that an MCP tool surface exists.
_CODE_SURFACE = re.compile(
    r"@(?:mcp|server|app)\.tool\b|FastMCP\s*\(|\bnew\s+Server\s*\(|\.registerTool\s*\(|"
    r"@tool\b",
)

CODE_SUFFIXES = (".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

# Extract the *name* of a tool defined in code, so it can be classified like a JSON tool.
# JS/TS: server.tool("execute_command", ...) / server.registerTool("name", ...)
_TS_TOOL_NAME = re.compile(r"\.(?:registerTool|tool)\s*\(\s*['\"]([\w.-]+)['\"]")
# Python decorator over a function: @mcp.tool() \n def run_command(...)
_PY_TOOL_DEF = re.compile(
    r"@(?:mcp|server|app|fastmcp)\.tool\s*(?:\([^)]*\))?\s*\r?\n\s*(?:async\s+)?def\s+(\w+)",
    re.MULTILINE,
)
# Python decorator with an explicit name: @mcp.tool(name="run_command")
_PY_TOOL_NAME_ARG = re.compile(
    r"@(?:mcp|server|app|fastmcp)\.tool\s*\([^)]*name\s*=\s*['\"](\w+)['\"]"
)


def _match_categories(text: str) -> list[str]:
    """Return the dangerous-capability categories a tool name/description matches."""
    return [label for label, pat in DANGEROUS_TOOL_PATTERNS.items() if pat.search(text)]


class McpScanner(Scanner):
    name = "mcp"
    rules = [
        RuleSpec(
            id="ST-MCP-DETECTED",
            category=CATEGORY,
            severity=Severity.LOW,
            title="MCP tool surface detected",
            description="An MCP manifest or tool-definition surface was detected.",
            recommendation="Review the declared MCP tools and their permissions.",
            capability=Capability.MCP_TOOLS_DETECTED,
        ),
        RuleSpec(
            id="ST-MCP-DANGEROUS-TOOL",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Dangerous MCP tool capability",
            description=(
                "One or more MCP tools expose dangerous capabilities "
                "(filesystem, shell, network, browser, or credential access)."
            ),
            recommendation=(
                "Confirm each powerful tool is required and constrained; broad MCP tools "
                "(shell/filesystem/network) grant an agent significant host access."
            ),
            capability=Capability.MCP_TOOLS_DETECTED,
        ),
        RuleSpec(
            id="ST-MCP-SERVER-EXEC",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="MCP server launches a host command",
            description=(
                "An mcpServers entry specifies a 'command', meaning installing/trusting "
                "this manifest will launch a binary on the host."
            ),
            recommendation=(
                "Verify the launched command and its source before trusting this MCP "
                "server configuration."
            ),
            capability=Capability.MCP_TOOLS_DETECTED,
        ),
        RuleSpec(
            id="ST-MCP-TOOL-POISONING",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="MCP tool description contains agent-directed instructions (tool poisoning)",
            description=(
                "An MCP tool's description/metadata embeds instructions aimed at the agent "
                "rather than documenting the tool (e.g. fake 'system note:' authority, "
                "'before using this tool ...', 'ignore the tool's description', or 'do not "
                "tell the user'). This is the tool-poisoning surface (cf. MCPTox): the agent "
                "may follow these hidden directives when the tool is listed, without the "
                "tool ever being executed."
            ),
            recommendation=(
                "Treat tool descriptions as untrusted input. Remove agent-directed "
                "imperatives from metadata and review whether the server attempts to steer "
                "or hide actions from the user."
            ),
            capability=Capability.PROMPT_SURFACE_RISK,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        detected: list[Evidence] = []
        dangerous: list[Evidence] = []
        server_exec: list[Evidence] = []
        poisoning: list[Evidence] = []
        needs_review: list[NeedsReview] = []
        dangerous_categories: set[str] = set()

        for f in index.select(suffixes=(".json",)):
            is_manifest_name = f.name.lower() in MANIFEST_NAMES
            try:
                data = json.loads(f.text)
            except (json.JSONDecodeError, ValueError):
                if is_manifest_name or "mcpServers" in f.text or '"tools"' in f.text:
                    needs_review.append(
                        NeedsReview(
                            category=CATEGORY,
                            title="Unparseable potential MCP manifest",
                            reason="File resembles an MCP manifest but is not valid JSON.",
                            file=f.relpath,
                        )
                    )
                continue

            self._analyze_json(
                f, data, is_manifest_name, detected, dangerous, server_exec,
                poisoning, dangerous_categories,
            )

        # Source-level tool definitions (Python / JS decorators & SDK calls).
        for _f, _m, ev in index.search(_CODE_SURFACE):
            detected.append(ev)
            if len(detected) >= MAX_EVIDENCE_PER_FINDING:
                break

        # Classify the names of tools defined in code (not just JSON manifests).
        self._classify_code_tools(index, dangerous, dangerous_categories)

        # Tool poisoning hidden in code-defined tool descriptions/docstrings. Scope to files
        # that actually expose an MCP tool surface to keep this high-signal / low false-positive.
        self._scan_code_poisoning(index, poisoning)

        findings: list[Finding] = []
        if dangerous:
            rule = self._rule("ST-MCP-DANGEROUS-TOOL")
            desc = rule.description
            if dangerous_categories:
                desc += " Categories: " + ", ".join(sorted(dangerous_categories)) + "."
            findings.append(
                Finding(
                    id=rule.id, severity=rule.severity, category=rule.category,
                    title=rule.title, description=desc,
                    evidence=dangerous[:MAX_EVIDENCE_PER_FINDING],
                    recommendation=rule.recommendation,
                )
            )
        if server_exec:
            findings.append(self._finding("ST-MCP-SERVER-EXEC", server_exec))
        if poisoning:
            findings.append(self._finding("ST-MCP-TOOL-POISONING", poisoning))
        if detected:
            findings.append(self._finding("ST-MCP-DETECTED", detected))

        return ScanResult(findings=findings, needs_review=needs_review)

    # -------------------------------------------------------------- internals
    def _analyze_json(
        self, f, data, is_manifest_name, detected, dangerous, server_exec,
        poisoning, dangerous_categories,
    ) -> None:
        if not isinstance(data, dict):
            return

        servers = data.get("mcpServers")
        if isinstance(servers, dict):
            ev = _evidence_for(f, '"mcpServers"')
            if ev:
                detected.append(ev)
            for srv in servers.values():
                if isinstance(srv, dict) and "command" in srv:
                    cev = _evidence_for(f, '"command"')
                    if cev:
                        server_exec.append(cev)

        tools = data.get("tools")
        tool_list = []
        if isinstance(tools, list):
            tool_list = tools
        elif isinstance(tools, dict):
            tool_list = list(tools.values())
        if tool_list or is_manifest_name:
            ev = _evidence_for(f, '"tools"') or _evidence_for(f, f.text[:1])
            if ev:
                detected.append(ev)

        for tool in tool_list:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name", ""))
            desc = str(tool.get("description", ""))
            cats = _match_categories(f"{name} {desc}")
            if cats:
                dangerous_categories.update(cats)
                anchor = _evidence_for(f, f'"{name}"') if name else None
                if anchor is None:
                    anchor = _evidence_for(f, '"name"')
                if anchor:
                    dangerous.append(anchor)
            pm = _POISONING.search(desc)
            if pm and len(poisoning) < MAX_EVIDENCE_PER_FINDING:
                # Anchor to the offending phrase in the raw source; fall back to the field key.
                anchor = _evidence_for(f, pm.group(0)) or _evidence_for(f, '"description"')
                if anchor:
                    poisoning.append(anchor)

    def _classify_code_tools(
        self,
        index: FileIndex,
        dangerous: list[Evidence],
        dangerous_categories: set[str],
    ) -> None:
        """Find tools defined in code and classify dangerous ones by their name."""
        seen: set[tuple[str, int]] = set()
        for f in index.select(suffixes=CODE_SUFFIXES):
            for pat in (_TS_TOOL_NAME, _PY_TOOL_DEF, _PY_TOOL_NAME_ARG):
                for m in pat.finditer(f.text):
                    cats = _match_categories(m.group(1))
                    if not cats:
                        continue
                    ev = f.evidence_for_span(m.start(), m.end())
                    key = (ev.file, ev.line_start)
                    if key in seen:
                        continue
                    seen.add(key)
                    dangerous_categories.update(cats)
                    if len(dangerous) < MAX_EVIDENCE_PER_FINDING:
                        dangerous.append(ev)

    def _scan_code_poisoning(self, index: FileIndex, poisoning: list[Evidence]) -> None:
        """Flag tool-poisoning phrases in code files that expose an MCP tool surface."""
        seen: set[tuple[str, int]] = set()
        for f in index.select(suffixes=CODE_SUFFIXES):
            if not _CODE_SURFACE.search(f.text):
                continue
            for m in _POISONING.finditer(f.text):
                ev = f.evidence_for_span(m.start(), m.end())
                key = (ev.file, ev.line_start)
                if key in seen:
                    continue
                seen.add(key)
                if len(poisoning) < MAX_EVIDENCE_PER_FINDING:
                    poisoning.append(ev)

    def _rule(self, rule_id: str) -> RuleSpec:
        return next(r for r in self.rules if r.id == rule_id)

    def _finding(self, rule_id: str, evidence: list[Evidence]) -> Finding:
        rule = self._rule(rule_id)
        return Finding(
            id=rule.id, severity=rule.severity, category=rule.category,
            title=rule.title, description=rule.description,
            evidence=evidence[:MAX_EVIDENCE_PER_FINDING],
            recommendation=rule.recommendation,
        )


def _evidence_for(f: IndexedFile, needle: str, start: int = 0) -> Evidence | None:
    """Anchor evidence to the first occurrence of ``needle`` in the file source."""
    if not needle:
        return None
    idx = f.text.find(needle, start)
    if idx < 0:
        return None
    return f.evidence_for_span(idx, idx + len(needle))
