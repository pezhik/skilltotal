"""Unit tests for the offline efficacy harness (tests/manual_eval/efficacy.py).

These exercise discovery, the detection metric, and metric aggregation on a tiny synthetic
corpus built in a tmp dir — independent of the committed tests/eval_corpus/ content.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_EFFICACY = Path(__file__).resolve().parent / "manual_eval" / "efficacy.py"
_spec = importlib.util.spec_from_file_location("efficacy", _EFFICACY)
efficacy = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
# Register before exec so dataclasses can resolve field types via sys.modules during creation.
sys.modules["efficacy"] = efficacy
_spec.loader.exec_module(efficacy)


def _mk(root: Path, polarity: str, owasp: str, technique: str, variant: str, files: dict[str, str]):
    d = root / polarity / owasp / technique / variant
    d.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (d / name).write_text(content, encoding="utf-8", newline="")


def test_discover_parses_labels_from_path(tmp_path: Path):
    _mk(tmp_path, "positive", "AST01", "decode-exec", "py-b64", {"m.py": "x = 1\n"})
    _mk(tmp_path, "negative", "AST01", "decode-exec", "legit", {"m.js": "const x = 1;\n"})
    samples = {s.path.name: s for s in efficacy.discover(tmp_path)}
    assert set(samples) == {"py-b64", "legit"}
    pos = samples["py-b64"]
    assert pos.polarity == "positive" and pos.owasp == "AST01"
    assert pos.technique == "decode-exec" and pos.language == "python"
    assert samples["legit"].polarity == "negative" and samples["legit"].language == "node"


def test_recall_and_precision_on_known_shapes(tmp_path: Path):
    # Positive: base64-decode-and-exec -> ST-OBF-DECODE-EXEC-PY (malicious) -> detected.
    _mk(tmp_path, "positive", "AST01", "decode-exec", "py-b64-exec",
        {"m.py": "import base64\nexec(base64.b64decode(b'cHJpbnQoMSk='))\n"})
    # Negative: decodes a blob but never executes it -> must stay clean.
    _mk(tmp_path, "negative", "AST01", "decode-exec", "decode-only",
        {"safe.py": "import base64\nDATA = base64.b64decode(b'aGVsbG8=')\nprint(len(DATA))\n"})

    results, m = efficacy.run(tmp_path)
    assert m.positives == 1 and m.negatives == 1
    assert m.recall == 1.0, f"positive missed: {m.false_negatives}"
    assert not m.false_positives, f"benign flagged: {m.false_positives}"
    assert m.precision == 1.0
    assert m.recall_by_technique["decode-exec"] == 1.0
    assert "AST01" in m.coverage_matrix and m.coverage_matrix["AST01"].get("python") == 1


def test_metrics_record_a_missed_positive(tmp_path: Path):
    # A "positive" that the engine would NOT flag (a lone benign file) must show up as a miss,
    # proving the harness measures false negatives rather than silently passing.
    _mk(tmp_path, "positive", "AST01", "decode-exec", "not-actually-malicious",
        {"m.py": "def add(a, b):\n    return a + b\n"})
    m = efficacy.compute_metrics(efficacy.evaluate(efficacy.discover(tmp_path)))
    assert m.recall == 0.0
    assert m.false_negatives == ["positive/AST01/decode-exec/not-actually-malicious"]


def test_report_serialization_shape(tmp_path: Path):
    _mk(tmp_path, "positive", "AST01", "decode-exec", "py-b64-exec",
        {"m.py": "import base64\nexec(base64.b64decode(b'cHJpbnQoMSk='))\n"})
    _mk(tmp_path, "negative", "AST01", "decode-exec", "decode-only",
        {"safe.py": "import base64\nprint(len(base64.b64decode(b'aGk=')))\n"})
    m = efficacy.compute_metrics(efficacy.evaluate(efficacy.discover(tmp_path)))
    d = efficacy.to_dict(m)
    for key in ("engine_version", "ruleset_version", "recall", "precision", "fp_rate",
                "recall_by_class", "recall_by_technique", "coverage_matrix"):
        assert key in d, f"missing report key: {key}"
    md = efficacy.to_markdown(m)
    assert "detection-efficacy report" in md
    assert "Coverage matrix" in md


def _mk_rule(root: Path, rule_id: str, expect: str, variant: str, files: dict[str, str]):
    d = root / "rules" / rule_id / expect / variant
    d.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (d / name).write_text(content, encoding="utf-8", newline="")


_SERVER_EXEC = '{\n  "mcpServers": {\n    "s": {"command": "node", "args": ["server.js"]}\n  }\n}\n'
_REMOTE_ONLY = (
    '{\n  "mcpServers": {\n    "s": {"type": "http", "url": "https://x.invalid/mcp"}\n  }\n}\n'
)


def test_rule_samples_are_scored_per_rule_and_kept_out_of_recall(tmp_path: Path):
    _mk_rule(tmp_path, "ST-MCP-SERVER-EXEC", "fires", "local", {".mcp.json": _SERVER_EXEC})
    _mk_rule(tmp_path, "ST-MCP-SERVER-EXEC", "silent", "remote", {".mcp.json": _REMOTE_ONLY})
    samples = efficacy.discover_rule_samples(tmp_path)
    assert {(s.rule_id, s.expect, s.variant) for s in samples} == {
        ("ST-MCP-SERVER-EXEC", "fires", "local"), ("ST-MCP-SERVER-EXEC", "silent", "remote")}

    _, m = efficacy.run(tmp_path)
    assert m.positives == 0 and m.negatives == 0  # rule samples never enter recall/precision
    assert m.rule_misses == []
    row = m.rule_coverage["ST-MCP-SERVER-EXEC"]
    assert row["owasp"] == ["AST03"]
    assert (row["should_fire"], row["fired"]) == (1, 1)
    assert (row["should_stay_silent"], row["stayed_silent"]) == (1, 1)
    d = efficacy.to_dict(m)
    assert d["rule_coverage"]["ST-MCP-SERVER-EXEC"] == row and d["rule_misses"] == []
    assert "Rule coverage" in efficacy.to_markdown(m)


def test_rule_sample_that_misses_its_expectation_is_reported(tmp_path: Path):
    # A fires/ sample whose rule does not fire, and a silent/ sample whose rule does, are misses.
    _mk_rule(tmp_path, "ST-MCP-SERVER-EXEC", "fires", "remote", {".mcp.json": _REMOTE_ONLY})
    _mk_rule(tmp_path, "ST-MCP-SERVER-EXEC", "silent", "local", {".mcp.json": _SERVER_EXEC})
    _, m = efficacy.run(tmp_path)
    assert m.rule_misses == [
        "rules/ST-MCP-SERVER-EXEC/fires/remote", "rules/ST-MCP-SERVER-EXEC/silent/local"]
    md = efficacy.to_markdown(m)
    assert "missed their expectation" in md


def test_rule_coverage_counts_firings_on_labeled_samples(tmp_path: Path):
    _mk(tmp_path, "positive", "AST01", "decode-exec", "py-b64-exec",
        {"m.py": "import base64\nexec(base64.b64decode(b'cHJpbnQoMSk='))\n"})
    results, m = efficacy.run(tmp_path)
    mapped = [i for i in results[0].finding_ids if i in m.rule_coverage]
    assert mapped, "the decode-exec sample should fire at least one OWASP-mapped rule"
    assert all(m.rule_coverage[i]["malicious_samples"] == 1 for i in mapped)
    # every rule mapped to an OWASP class gets a row, fired or not
    assert m.rule_coverage["ST-MCP-DANGEROUS-TOOL"]["malicious_samples"] == 0
