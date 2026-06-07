"""Filesystem access detection for Node.js (read vs write are distinct rules).

Python filesystem access is handled by the AST scanner
(:mod:`skilltotal.scanners.python_ast`), which can also tell ``open(p, 'w')`` from a read.
"""

from __future__ import annotations

from skilltotal.models import Capability, Severity
from skilltotal.scanners.base import PatternScanner, RuleSpec, alternation

NODE_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

CATEGORY = "filesystem"

_READ_RECO = (
    "Confirm which files are read and that paths cannot be influenced by untrusted "
    "input to reach sensitive locations."
)
_WRITE_RECO = (
    "Confirm which files are written/deleted and that paths cannot be influenced by "
    "untrusted input."
)


class FilesystemScanner(PatternScanner):
    name = "filesystem"
    rules = [
        RuleSpec(
            id="ST-FS-NODE-READ",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            title="Node.js filesystem read",
            description="Node.js filesystem read APIs were detected (fs.readFile).",
            recommendation=_READ_RECO,
            capability=Capability.FILESYSTEM_READ,
            suffixes=NODE_SUFFIXES,
            pattern=alternation(
                r"\bfs\.readFile(?:Sync)?\s*\(",
                r"\bfs\.createReadStream\s*\(",
            ),
        ),
        RuleSpec(
            id="ST-FS-NODE-WRITE",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            title="Node.js filesystem write/delete",
            description=(
                "Node.js filesystem write/delete APIs were detected "
                "(fs.writeFile / fs.unlink / fs.rm)."
            ),
            recommendation=_WRITE_RECO,
            capability=Capability.FILESYSTEM_WRITE,
            suffixes=NODE_SUFFIXES,
            pattern=alternation(
                r"\bfs\.writeFile(?:Sync)?\s*\(",
                r"\bfs\.appendFile(?:Sync)?\s*\(",
                r"\bfs\.unlink(?:Sync)?\s*\(",
                r"\bfs\.rm(?:Sync)?\s*\(",
                r"\bfs\.createWriteStream\s*\(",
            ),
        ),
    ]
