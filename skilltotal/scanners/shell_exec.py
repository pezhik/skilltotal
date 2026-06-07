"""Shell / command execution detection for Node.js.

Python shell execution is handled by the AST scanner (:mod:`skilltotal.scanners.python_ast`).
"""

from __future__ import annotations

import re

from skilltotal.models import Capability, Severity
from skilltotal.scanners.base import PatternScanner, RuleSpec, alternation

NODE_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

CATEGORY = "shell_execution"


class ShellExecScanner(PatternScanner):
    name = "shell_exec"
    rules = [
        RuleSpec(
            id="ST-SHELL-NODE",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Node.js shell/command execution",
            description=(
                "Node.js process execution was detected (child_process exec/spawn, or a "
                "process-spawning library such as zx / execa / cross-spawn / shelljs)."
            ),
            recommendation=(
                "Confirm the command and its arguments are fully controlled and not "
                "derived from untrusted input; prefer execFile with an argument array."
            ),
            capability=Capability.SHELL_EXECUTION,
            suffixes=NODE_SUFFIXES,
            pattern=alternation(
                r"child_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(",
                r"(?:require\(\s*['\"](?:node:)?child_process['\"]\s*\))",
                r"from\s+['\"](?:node:)?child_process['\"]",
                r"\b(?:exec|execSync|spawn|spawnSync)\s*\(",
                # process-spawning libraries (importing them is a shell signal)
                r"(?:require\(\s*['\"](?:execa|zx|shelljs|cross-spawn|spawn-rx|tinyexec|node-pty)['\"]\s*\))",
                r"from\s+['\"](?:execa|zx|shelljs|cross-spawn|spawn-rx|tinyexec|node-pty)['\"]",
                flags=re.MULTILINE,
            ),
        ),
    ]
