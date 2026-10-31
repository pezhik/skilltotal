"""Filesystem access detection for Node.js (read vs write are distinct rules).

Python filesystem access is handled by the AST scanner
(:mod:`skilltotal.scanners.python_ast`), which can also tell ``open(p, 'w')`` from a read.
"""

from __future__ import annotations

from skilltotal.models import Capability, Severity
from skilltotal.scanners.base import PatternScanner, RuleSpec, alternation

NODE_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

CATEGORY = "filesystem"

# The Node.js calls that delete, and all that write or delete. ST-FS-NODE-WRITE matches these, and
# ST-MCP-ANNOTATION-MISMATCH reads the same set inside a tool handler.
NODE_FS_DELETE_CALLS = (
    r"\bfs\.unlink(?:Sync)?\s*\(",
    r"\bfs\.rm(?:Sync)?\s*\(",
    r"\bfs\.rmdir(?:Sync)?\s*\(",
)
NODE_FS_WRITE_CALLS = (
    r"\bfs\.writeFile(?:Sync)?\s*\(",
    r"\bfs\.appendFile(?:Sync)?\s*\(",
    *NODE_FS_DELETE_CALLS,
    r"\bfs\.createWriteStream\s*\(",
)

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
            # A JSDoc example (`* fs.createReadStream('speech.mp3')`) describes a call; it makes
            # none. Comment matches are demoted; code, strings included, stays in scope.
            code_context="comments",
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
            code_context="comments",
            suffixes=NODE_SUFFIXES,
            pattern=alternation(*NODE_FS_WRITE_CALLS),
        ),
    ]
