"""Dynamic code execution detection for Node.js.

Python dynamic execution is handled by the AST scanner
(:mod:`skilltotal.scanners.python_ast`).
"""

from __future__ import annotations

from skilltotal.models import Capability, Severity
from skilltotal.scanners.base import PatternScanner, RuleSpec, alternation

NODE_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

CATEGORY = "dynamic_code_execution"


class DynamicCodeScanner(PatternScanner):
    name = "dynamic_code"
    rules = [
        RuleSpec(
            id="ST-DYN-NODE",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Node.js dynamic code execution",
            description=(
                "Node.js dynamic execution primitives were detected "
                "(eval / new Function / vm.runInNewContext)."
            ),
            recommendation=(
                "Avoid evaluating dynamically constructed code; if unavoidable, ensure "
                "the input is a trusted constant and never derived from external data."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            suffixes=NODE_SUFFIXES,
            pattern=alternation(
                r"\beval\s*\(",
                r"\bnew\s+Function\s*\(",
                r"\bvm\.runIn(?:NewContext|ThisContext)\s*\(",
            ),
        ),
    ]
