"""Shipped agent or server configuration that injects code through an environment variable.

Claude Code applies the ``env`` block of a project's ``.claude/settings.json`` to every process it
starts, and an MCP or language server entry starts its server with the ``env`` it lists. Some
variables are not settings of the program at all: they make it load a file or run a command before
its own code.

* ``NODE_OPTIONS`` with ``--require`` / ``--import`` / ``--loader`` loads a module into every
  Node.js process; ``BASH_ENV`` is sourced by every non-interactive bash; ``PYTHONSTARTUP`` runs in
  every interactive Python.
* ``LD_PRELOAD`` and ``DYLD_INSERT_LIBRARIES`` map a native library into every process.
* ``GIT_SSH_COMMAND`` is the command git runs for each ssh remote, ``CLAUDE_CODE_SHELL_PREFIX`` the
  command Claude Code puts in front of each shell command.

An honest team can set these (a tracing preload, a wrapper), so the entry is a risky construct on
its own. What it loads is read by the other rules: ``skilltotal.autorun`` hands the value to them
as an auto-run command, and the engine treats a loaded file inside the component as an entry
point. ``NODE_OPTIONS`` without a preload flag (heap size), a preload of an installed package by
name (``--require dotenv/config``), an empty value, and search paths (``PYTHONPATH``,
``LD_LIBRARY_PATH``, ``PATH``) are not reported.

Parsing only (``skilltotal.autorun`` reads the files); nothing is run.
"""

from __future__ import annotations

from skilltotal.autorun import autorun_commands
from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)

R_ENV_INJECT = "ST-AGENT-ENV-INJECT"


class EnvInjectScanner(Scanner):
    name = "env_inject"
    rules = [
        RuleSpec(
            id=R_ENV_INJECT,
            category="agent_config",
            severity=Severity.HIGH,
            title="Agent or server configuration injects code through an environment variable",
            description=(
                "An `env` block in shipped agent settings or in an MCP or language server entry "
                "sets a variable that makes each process started with it load a file or run a "
                "command before its own code: `NODE_OPTIONS` with `--require` / `--import` / "
                "`--loader`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `PYTHONSTARTUP`, "
                "`GIT_SSH_COMMAND` or `CLAUDE_CODE_SHELL_PREFIX`. Opening the project in the "
                "agent, or starting the server, runs what the variable names with the "
                "developer's privileges, inside programs that look unrelated to it."
            ),
            recommendation=(
                "Read the file or command the variable names before opening the project or "
                "adding the server, and remove the entry unless you know why it is there. A "
                "file outside the component was not part of this scan."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence = []
        seen: set[tuple[str, int]] = set()
        for injection in autorun_commands(index).env_injections:
            ev = injection.evidence()
            if (ev.file, ev.line_start) in seen:
                continue
            seen.add((ev.file, ev.line_start))
            evidence.append(ev)
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
        if not evidence:
            return ScanResult()
        return ScanResult(findings=[_finding_from_rule(self.rules[0], evidence)])
