"""Offline, deterministic tests for the corpus-report harness (local fixture sources only)."""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path

_CR = Path(__file__).parent / "manual_eval" / "corpus_report.py"
_spec = importlib.util.spec_from_file_location("corpus_report", _CR)
cr = importlib.util.module_from_spec(_spec)
# Register before exec so @dataclass (with `from __future__ annotations`) resolves field types.
sys.modules["corpus_report"] = cr
_spec.loader.exec_module(cr)

FIXTURES = Path(__file__).parent / "manual_eval" / "malicious"


def _manifest(tmp_path, rows):
    p = tmp_path / "m.csv"
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["source", "ecosystem", "type", "name"])
        w.writerows(rows)
    return p


def test_scan_row_maps_malicious_fixture_to_owasp():
    # decode-and-execute fixture -> at least one AST01 finding, offline.
    res = cr.scan_row(str(FIXTURES / "sh-base64-exec"), "skill", "sh-base64-exec")
    assert res.status == "ok"
    assert "AST01" in res.owasp


def test_aggregate_shape_and_counts(tmp_path):
    rows = [
        [str(FIXTURES / "npm-trapdoor-stealer"), "npm", "npm", "trapdoor"],
        [str(FIXTURES / "pypi-importtime-stealer"), "pypi", "pypi", "importtime"],
        # a deterministically unresolvable LOCAL path -> skipped (no network needed)
        [str(FIXTURES / "does-not-exist-xyz"), "npm", "npm", "ghost"],
    ]
    manifest = _manifest(tmp_path, rows)
    parsed = cr.load_manifest(manifest)
    results = [cr.scan_row(*r) for r in parsed]
    agg = cr.aggregate(results, manifest_sha="deadbeef")

    prov = agg["provenance"]
    assert prov["components_total"] == 3
    assert prov["scanned"] + prov["skipped"] + prov["errors"] == 3
    assert prov["scanned"] == 2  # both local fixtures resolve offline
    assert prov["skipped"] >= 1  # the missing path is skipped, never an error that aborts

    # risk distribution counts sum to scanned
    assert sum(b["count"] for b in agg["risk_distribution"].values()) == prov["scanned"]

    # OWASP block has all 10 categories; AST02 (supply chain) present on the npm install stealer
    assert set(agg["owasp"]) == {f"AST{n:02d}" for n in range(1, 11)}
    assert agg["owasp"]["AST02"]["count"] >= 1
    assert agg["owasp"]["AST01"]["count"] >= 1


def test_markdown_render_has_sections(tmp_path):
    rows = [[str(FIXTURES / "sh-base64-exec"), "skill", "skill", "b64"]]
    manifest = _manifest(tmp_path, rows)
    results = [cr.scan_row(*r) for r in cr.load_manifest(manifest)]
    md = cr.to_markdown(cr.aggregate(results, "abc123"))
    assert "# SkillTotal corpus report" in md
    assert "OWASP Agentic Skills Top 10" in md
    assert "AST01" in md
    assert "## Reproduce" in md


def test_cli_writes_json_and_md(tmp_path):
    rows = [[str(FIXTURES / "sh-base64-exec"), "skill", "skill", "b64"]]
    manifest = _manifest(tmp_path, rows)
    out = tmp_path / "corpus-report"
    rc = cr.main(["--manifest", str(manifest), "--out-prefix", str(out)])
    assert rc == 0
    data = json.loads((tmp_path / "corpus-report.json").read_text(encoding="utf-8"))
    assert data["provenance"]["scanned"] == 1
    assert (tmp_path / "corpus-report.md").read_text(encoding="utf-8").startswith(
        "# SkillTotal corpus report"
    )
