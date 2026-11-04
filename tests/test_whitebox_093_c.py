"""White-box evasions of engine 0.92.0 closed in 0.93.0: obfuscated execution and post-exploitation.

Each evasion sample (a one-line indirection of a shape the engine already flags) must now be
flagged like its direct form, and the honest look-alike the broadened check could confuse must
stay clean. The samples live in the efficacy corpus; this file pins them by name, plus the shared
single-assignment folding in concat_normalize they rely on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal import engine
from skilltotal.collector import detect_component
from skilltotal.concat_normalize import assigned_once, bound_strings, fold_string_concats

CORPUS = Path(__file__).parent / "eval_corpus"


def _report(rel: str):
    root = CORPUS / rel
    return engine.analyze_directory(root, detect_component(root, source=str(root)))


def _flagged(report) -> bool:
    malicious = (report.verdict or {}).get("has_malicious_indicators")
    return bool(malicious) or report.risk_level.value in ("high", "critical")


def _ids(report) -> set[str]:
    return {f.id for f in report.findings}


@pytest.mark.parametrize(("rel", "rule"), [
    ("positive/AST01/decode-exec/python-zlib-exec", "ST-OBF-DECODE-EXEC"),
    ("positive/AST01/decode-exec/python-alias-sink", "ST-OBF-DECODE-EXEC"),
    ("positive/AST05/pickle-reduce-gadget/alias-chain-reduce", "ST-PICKLE-REDUCE"),
    ("positive/AST05/deserialize-exec/marshal-split-variable", "ST-OBF-DECODE-EXEC"),
    ("positive/AST01/decode-exec/node-global-eval-alias", "ST-OBF-DECODE-EXEC"),
    ("positive/AST01/decode-exec/node-fromcharcode", "ST-OBF-DECODE-EXEC"),
    ("positive/AST01/decode-exec/node-buffer-encoding-name", "ST-OBF-DECODE-EXEC"),
    ("positive/AST01/decode-exec/node-vm-script-inline", "ST-OBF-DECODE-EXEC"),
    ("positive/AST02/decode-spawn/execpath-name", "ST-OBF-DECODE-SPAWN"),
    ("positive/AST01/decode-exec/node-function-ctor-chain", "ST-OBF-DECODE-EXEC"),
    ("positive/AST03/cli-relay/split-files", "ST-AGENT-CLI-RELAY"),
    ("positive/AST04/mcp-config-inject/helper-returned-path", "ST-AGENT-CONFIG-PERSIST"),
    ("positive/AST01/clipboard-swap/node-shell-clip-tool", "ST-CLIPPER"),
])
def test_evasion_sample_is_flagged(rel: str, rule: str) -> None:
    report = _report(rel)
    assert _flagged(report), (rel, report.risk_level, _ids(report))
    assert rule in _ids(report)


@pytest.mark.parametrize("rel", [
    "negative/AST01/decode-exec/python-repl-exec-alias",
    "negative/AST01/decode-exec/node-ctor-charcode-helpers",
    "negative/AST05/deserialize-exec/zlib-config-cache",
    "negative/AST02/decode-spawn/execpath-name-runs-worker",
    "negative/AST03/cli-relay/split-files-local-config",
    "negative/AST01/clipboard-swap/node-shell-copy-own-address",
    "negative/AST04/mcp-config-inject/helper-path-health-check",
])
def test_look_alike_stays_clean(rel: str) -> None:
    report = _report(rel)
    assert not _flagged(report), (rel, report.risk_level, _ids(report))


@pytest.mark.parametrize(("rel", "rule", "fires"), [
    ("rules/ST-POSTEX-PERSIST/fires/ps-runkey-split-path", "ST-POSTEX-PERSIST", True),
    ("rules/ST-POSTEX-PERSIST/fires/python-launchagent-split", "ST-POSTEX-PERSIST", True),
    ("rules/ST-POSTEX-PERSIST/fires/shell-profile-d-aliases", "ST-POSTEX-PERSIST", True),
    ("rules/ST-POSTEX-PERSIST/silent/ps-runkey-read", "ST-POSTEX-PERSIST", False),
    ("rules/ST-POSTEX-PERSIST/silent/shell-profile-d-read", "ST-POSTEX-PERSIST", False),
    ("rules/ST-GIT-HOOK-PERSIST/fires/gitconfig-append-hookspath", "ST-GIT-HOOK-PERSIST", True),
    ("rules/ST-GIT-HOOK-PERSIST/silent/gitconfig-read-hookspath", "ST-GIT-HOOK-PERSIST", False),
    ("rules/ST-GIT-HOOK-PERSIST/silent/project-gitconfig-local-hooks", "ST-GIT-HOOK-PERSIST",
     False),
    ("rules/ST-AGENT-CLI-BYPASS/fires/mode-from-joined-name", "ST-AGENT-CLI-BYPASS", True),
    ("rules/ST-AGENT-CLI-BYPASS/silent/mode-name-default", "ST-AGENT-CLI-BYPASS", False),
])
def test_rule_sample(rel: str, rule: str, fires: bool) -> None:
    assert (rule in _ids(_report(rel))) is fires


# --- shared single-assignment folding ---------------------------------------------------------

def test_name_bound_once_folds_into_a_concatenation() -> None:
    text = 'const a = "~/.";\nconst p = a + "ssh/id_rsa";\n'
    assert '"~/.ssh/id_rsa"' in fold_string_concats(text, ".js")[0]


def test_name_assigned_twice_is_not_folded() -> None:
    text = 'let a = "~/.";\na = "x";\nconst p = a + "ssh/id_rsa";\n'
    assert fold_string_concats(text, ".js")[0] == text


def test_keyword_argument_is_not_a_binding() -> None:
    text = 'f(a="~/.")\np = a + "ssh/id_rsa"\n'
    assert fold_string_concats(text, ".py")[0] == text


def test_powershell_concat_with_bound_name_folds_and_anchors() -> None:
    text = '$hive = "HKCU:\\Software\\CurrentVersion"\n$key = $hive + "\\" + "Run"\n'
    folded, idx = fold_string_concats(text, ".ps1")
    assert '$key = "HKCU:\\Software\\CurrentVersion\\Run"' in folded
    line_two = folded.index("$key")
    assert idx[line_two] == text.index("$key")


def test_powershell_expanding_string_is_not_a_binding() -> None:
    text = '$a = "$env:APPDATA\\x"\n$b = $a + "\\" + "Run"\n'
    assert "a" not in bound_strings(text, ".ps1")


def test_bound_strings_reads_literal_lists_joined() -> None:
    assert bound_strings('const m = ["by", "pass"].join("");\n', ".js") == {"m": ("bypass", 10)}
    assert bound_strings('m = "".join(["by", "pass"])\n', ".py")["m"][0] == "bypass"


def test_assigned_once_counts_compound_assignments() -> None:
    names = assigned_once('let a = "x";\nlet b = "y";\nb += "z";\n', ".js")
    assert "a" in names and "b" not in names
