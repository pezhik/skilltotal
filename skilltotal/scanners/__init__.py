"""Scanner registry.

``SCANNERS`` is the ordered list of scanner instances the engine runs. ``all_rules()``
aggregates every declared :class:`RuleSpec` so the ``rules list`` command and the
capability engine share a single source of truth.
"""

from __future__ import annotations

from skilltotal.scanners.base import RuleSpec, Scanner
from skilltotal.scanners.dynamic_code import DynamicCodeScanner
from skilltotal.scanners.encrypted_archive import EncryptedArchiveScanner
from skilltotal.scanners.exposure import ExposureScanner
from skilltotal.scanners.filesystem import FilesystemScanner
from skilltotal.scanners.install_scripts import InstallScriptsScanner
from skilltotal.scanners.invisible_unicode import InvisibleUnicodeScanner
from skilltotal.scanners.mcp import McpScanner
from skilltotal.scanners.network import NetworkScanner
from skilltotal.scanners.obfuscation import ObfuscationScanner
from skilltotal.scanners.prompt_surface import PromptSurfaceScanner
from skilltotal.scanners.pth_exec import PthExecScanner
from skilltotal.scanners.python_ast import PythonAstScanner
from skilltotal.scanners.secrets import SecretsScanner
from skilltotal.scanners.sensitive_paths import SensitivePathScanner
from skilltotal.scanners.shell_evasion import ShellEvasionScanner
from skilltotal.scanners.shell_exec import ShellExecScanner
from skilltotal.scanners.shell_script import ShellScriptScanner

SCANNERS: list[Scanner] = [
    PythonAstScanner(),
    ShellExecScanner(),
    ShellScriptScanner(),
    ShellEvasionScanner(),
    FilesystemScanner(),
    SensitivePathScanner(),
    NetworkScanner(),
    InstallScriptsScanner(),
    DynamicCodeScanner(),
    ObfuscationScanner(),
    PthExecScanner(),
    McpScanner(),
    PromptSurfaceScanner(),
    InvisibleUnicodeScanner(),
    SecretsScanner(),
    ExposureScanner(),
    EncryptedArchiveScanner(),
]


def all_rules() -> list[RuleSpec]:
    rules: list[RuleSpec] = []
    for scanner in SCANNERS:
        rules.extend(scanner.rules)
    return rules


def rule_by_id() -> dict[str, RuleSpec]:
    return {r.id: r for r in all_rules()}


__all__ = ["SCANNERS", "all_rules", "rule_by_id", "Scanner", "RuleSpec"]
