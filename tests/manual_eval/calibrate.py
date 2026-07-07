"""Dataset calibration harness: run the engine over a labeled CSV and score it.

Reads a CSV of labeled components (one per row), runs the *static* engine on each
(``engine.analyze`` — nothing is executed, per the engine invariant), and compares the
verdict against the row's expected class. Emits a JSON record + a markdown summary with
the metrics that matter: false-positive rate on benign rows, detection rate on
malicious/compromised rows, and the average ``needs_review`` count (the report-noise
metric).

CSV columns (header required): ``class,ecosystem,source,version,notes``
  - ``class``    one of: malicious | compromised-version | vulnerable-lab | benign-baseline
  - ``source``   an engine spec (``npm:x``, ``pypi:y``, a git URL), a local ``fixture:<name>``
                 (resolved to ``manual_eval/malicious/<name>`` and scanned offline), OR empty
                 -> row SKIPPED
  - ``version``  optional pin; folded into the spec (``npm:x@v`` / ``pypi:y==v``)
  - ``expected_result`` (optional): ``detect`` | ``allow`` — an explicit per-row gold label.
                 When present it drives the pass/fail judgement (``allow`` = must not be called
                 malicious; ``detect`` = must be flagged) instead of inferring from ``class``.
                 ``vulnerable-lab`` rows keep their softer rule (a risky construct is enough).
  - ``expected_findings`` / ``forbidden_findings`` (optional): a ``;``-separated list of rule ids
                 that MUST fire / MUST NOT fire on this component — a per-finding (TP/FP) golden
                 set. This catches regressions the verdict-level metrics miss: a false-positive
                 rule that fires but leaves the component "high, not malicious" passes the
                 benign-FP gate yet is a real FP. A row with either column set is counted in
                 ``finding_mismatches``; rows without them are unaffected (back-compat).

This is an *informational* tool (always exits 0). It never changes rules; calibration
decisions are made by a human. The real labeled dataset is maintained separately; this
module ships only the harness + a tiny synthetic sample for the unit test.

Usage:
    python tests/manual_eval/calibrate.py --dataset <file.csv> [--out <prefix>]
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from skilltotal import engine
from skilltotal.agent_skill import SKILL_MISMATCH_FINDING_ID
from skilltotal.collector import CollectionError, detect_component

# Expected-class -> what counts as a correct outcome.
BENIGN = "benign-baseline"
DETECT_CLASSES = {"malicious", "compromised-version"}
LAB_CLASSES = {"vulnerable-lab"}

# Local known-malicious fixtures, addressable as ``fixture:<name>`` in the dataset. These are
# always reachable (committed in-repo), unlike registry packages that get taken down — so they
# give the network corpus a deterministic detection floor when it runs (Tier 3). The dedicated
# offline gate is ``tests/test_offline_calibration.py``.
FIXTURE_ROOT = Path(__file__).parent / "malicious"
FIXTURE_PREFIX = "fixture:"


@dataclass
class RowResult:
    cls: str
    source: str
    status: str  # "ok" | "skipped" | "error"
    verdict_level: str | None = None
    has_malicious: bool | None = None
    risky_constructs: int | None = None
    capabilities: int | None = None
    needs_review: int | None = None
    risk_level: str | None = None
    skill_mismatch: bool | None = None  # ST-SKILL-CAP-MISMATCH fired (declared vs actual)
    passed: bool | None = None  # outcome vs expectation (None when skipped)
    # Per-finding golden set (optional): rule ids that MUST fire vs MUST NOT fire on this row.
    # ``findings_ok`` is None when the row declares no golden labels (most rows), so it never
    # counts against the finding-mismatch metric.
    finding_ids: list[str] | None = None  # all scored+capability finding ids on this component
    missing_findings: list[str] | None = None  # expected_findings that did NOT fire (recall gap)
    unexpected_findings: list[str] | None = None  # forbidden_findings that DID fire (a false pos)
    findings_ok: bool | None = None
    detail: str = ""


def _split_ids(raw: str) -> list[str]:
    """Parse a golden rule-id list from one CSV cell (``;`` or ``,`` separated)."""
    return [tok.strip() for tok in raw.replace(",", ";").split(";") if tok.strip()]


def _spec(source: str, version: str) -> str:
    """Fold an optional version pin into the engine spec."""
    source, version = source.strip(), version.strip()
    if not version:
        return source
    if source.lower().startswith("npm:"):
        return f"{source}@{version}"
    if source.lower().startswith("pypi:"):
        return f"{source}=={version}"
    return source  # git URLs / other: version handled by the ref in the URL, if any


def _judge(
    cls: str, has_mal: bool, risk_level: str, risky: int, caps: int, expected: str = ""
) -> bool:
    """Did the engine produce the expected kind of outcome for this row?

    ``expected`` is the optional per-row gold label (``detect`` | ``allow``). When given it is
    authoritative: ``allow`` rows pass iff not called malicious; ``detect`` rows pass iff
    flagged (with ``vulnerable-lab`` keeping its softer "a risky construct is enough" rule).
    When absent the outcome is inferred from ``class`` (back-compat).
    """
    elevated = risk_level in ("high", "critical")
    expected = expected.strip().lower()
    if expected == "allow":
        return not has_mal
    if expected == "detect":
        if cls in LAB_CLASSES:
            return has_mal or elevated or risky > 0
        return has_mal or elevated
    # No explicit gold label: fall back to class-based judging.
    if cls == BENIGN:
        # PASS = not called malware. Powerful (even critical) capabilities are fine here;
        # only a malicious-indicator on a trusted package is a real false positive.
        return not has_mal
    if cls in DETECT_CLASSES:
        return has_mal or elevated
    if cls in LAB_CLASSES:
        # Intentionally vulnerable: a risky construct or an elevated capability is enough;
        # we don't require a malicious verdict.
        return has_mal or elevated or risky > 0
    return True  # unknown class: informational only


def _analyze_spec(spec: str):
    """Run the static engine on a spec, resolving local ``fixture:<name>`` offline."""
    if spec.lower().startswith(FIXTURE_PREFIX):
        name = spec[len(FIXTURE_PREFIX) :].strip()
        root = FIXTURE_ROOT / name
        if not root.is_dir():
            raise CollectionError(f"unknown fixture: {name}")
        return engine.analyze_directory(root, detect_component(root, source=str(root)))
    return engine.analyze(spec)


def run_row(
    cls: str,
    source: str,
    version: str,
    expected: str = "",
    expect_findings: list[str] | None = None,
    forbid_findings: list[str] | None = None,
) -> RowResult:
    spec = _spec(source, version)
    if not spec:
        return RowResult(cls=cls, source="", status="skipped", detail="no source")
    try:
        report = _analyze_spec(spec)
    except CollectionError as exc:
        # Package pulled from the registry / repo unreachable: not a scanner failure.
        return RowResult(cls=cls, source=spec, status="skipped", detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - harness must never abort the whole run
        return RowResult(cls=cls, source=spec, status="error", detail=repr(exc))

    v = report.verdict or {}
    res = RowResult(
        cls=cls,
        source=spec,
        status="ok",
        verdict_level=v.get("level"),
        has_malicious=bool(v.get("has_malicious_indicators")),
        risky_constructs=int(v.get("risky_constructs", 0)),
        capabilities=int(v.get("capabilities", 0)),
        needs_review=len(report.needs_review),
        risk_level=report.risk_level.value,
    )
    res.skill_mismatch = any(f.id == SKILL_MISMATCH_FINDING_ID for f in report.findings)
    res.passed = _judge(
        cls, res.has_malicious, res.risk_level, res.risky_constructs, res.capabilities, expected
    )
    # Per-finding golden check: only when the row declares expected/forbidden rule ids. This is
    # the TP/FP floor the verdict-level metrics miss — e.g. a rule that fires but leaves the
    # component "high, not malicious" passes the benign-FP gate yet is still a false positive.
    expect_findings = expect_findings or []
    forbid_findings = forbid_findings or []
    if expect_findings or forbid_findings:
        ids = {f.id for f in report.findings}
        res.finding_ids = sorted(ids)
        res.missing_findings = [rid for rid in expect_findings if rid not in ids]
        res.unexpected_findings = [rid for rid in forbid_findings if rid in ids]
        res.findings_ok = not res.missing_findings and not res.unexpected_findings
    return res


def summarize(results: list[RowResult]) -> dict:
    ok = [r for r in results if r.status == "ok"]
    benign = [r for r in ok if r.cls == BENIGN]
    detect = [r for r in ok if r.cls in DETECT_CLASSES]
    labs = [r for r in ok if r.cls in LAB_CLASSES]
    benign_skill_mismatch = [r for r in benign if r.skill_mismatch]
    # A curated benign skill that trips the declared-vs-actual rule (ST-SKILL-CAP-MISMATCH) is a
    # regression / false positive for us — fold it into the gated benign-FP metric. Non-skill
    # benign packages never produce this finding, so existing rows are unaffected.
    benign_fp = [r for r in benign if r.has_malicious or r.skill_mismatch]
    noisy = [r.needs_review for r in ok if r.needs_review is not None]
    # Per-finding golden rows (those that declared expected/forbidden rule ids). A mismatch is a
    # TP/FP regression at rule granularity — a hard gate independent of the verdict-level metric.
    golden = [r for r in ok if r.findings_ok is not None]
    finding_mismatches = [r for r in golden if not r.findings_ok]
    # High-precision tripwire signal (Trust-Factory): a benign-baseline package that tripped a
    # FORBIDDEN rule (a synthesized exfil/typosquat combo) — an "elevated but not malicious" false
    # positive the benign_fp metric (malicious-only) misses. On a reputable corpus this is either a
    # real FP to fix or a real compromise to disclose; either way it needs triage, not a silent 0.
    combo_on_benign = [r for r in benign if r.unexpected_findings]
    return {
        "rows_total": len(results),
        "scanned": len(ok),
        "skipped": sum(1 for r in results if r.status == "skipped"),
        "errors": sum(1 for r in results if r.status == "error"),
        "benign_scanned": len(benign),
        "benign_false_positives": len(benign_fp),
        "benign_skill_mismatch": len(benign_skill_mismatch),
        "detect_scanned": len(detect),
        "detect_detected": sum(1 for r in detect if r.passed),
        "labs_scanned": len(labs),
        "labs_flagged": sum(1 for r in labs if r.passed),
        "golden_scanned": len(golden),
        "finding_mismatches": len(finding_mismatches),
        "combo_on_benign": len(combo_on_benign),
        "avg_needs_review": round(sum(noisy) / len(noisy), 2) if noisy else 0.0,
        "max_needs_review": max(noisy) if noisy else 0,
    }


def to_markdown(results: list[RowResult], summary: dict) -> str:
    lines = [
        "# SkillTotal calibration report",
        "",
        f"- rows: {summary['rows_total']} (scanned {summary['scanned']}, "
        f"skipped {summary['skipped']}, errors {summary['errors']})",
        f"- benign false positives: **{summary['benign_false_positives']}** / "
        f"{summary['benign_scanned']} scanned",
        f"- benign skill-mismatch (ST-SKILL-CAP-MISMATCH on benign skills): "
        f"{summary.get('benign_skill_mismatch', 0)}",
        f"- malicious/compromised detected: {summary['detect_detected']} / "
        f"{summary['detect_scanned']} scanned",
        f"- vulnerable-labs flagged: {summary['labs_flagged']} / {summary['labs_scanned']}",
        f"- per-finding golden mismatches: **{summary.get('finding_mismatches', 0)}** / "
        f"{summary.get('golden_scanned', 0)} golden rows",
        f"- combo-on-benign (tripwire): **{summary.get('combo_on_benign', 0)}** benign package(s) "
        f"tripped a forbidden exfil/typosquat combo",
        f"- needs_review noise: avg {summary['avg_needs_review']}, "
        f"max {summary['max_needs_review']}",
        "",
        "| class | source | status | verdict | has_mal | risk | nr | pass |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        pass_mark = "" if r.passed is None else ("PASS" if r.passed else "FAIL")
        lines.append(
            f"| {r.cls} | {r.source or '-'} | {r.status} | {r.verdict_level or '-'} | "
            f"{'' if r.has_malicious is None else r.has_malicious} | {r.risk_level or '-'} | "
            f"{'' if r.needs_review is None else r.needs_review} | {pass_mark} |"
        )
    mismatches = [r for r in results if r.findings_ok is False]
    if mismatches:
        lines += ["", "## Per-finding golden mismatches", ""]
        for r in mismatches:
            miss = ", ".join(r.missing_findings or []) or "-"
            extra = ", ".join(r.unexpected_findings or []) or "-"
            lines.append(f"- `{r.source}` — missing (recall): {miss}; unexpected (FP): {extra}")
    return "\n".join(lines) + "\n"


def load_rows(path: Path) -> list[tuple[str, str, str, str, list[str], list[str]]]:
    rows: list[tuple[str, str, str, str, list[str], list[str]]] = []
    # utf-8-sig strips a leading BOM if present: a CSV written by PowerShell's
    # `Set-Content -Encoding utf8` (PS 5.1) carries a BOM that would otherwise make DictReader
    # read the first header as "﻿class", silently dropping every row's class.
    with path.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            rows.append(
                (
                    (row.get("class") or "").strip(),
                    (row.get("source") or "").strip(),
                    (row.get("version") or "").strip(),
                    (row.get("expected_result") or "").strip(),
                    _split_ids(row.get("expected_findings") or ""),
                    _split_ids(row.get("forbidden_findings") or ""),
                )
            )
    return rows


def calibrate(dataset: Path) -> tuple[list[RowResult], dict]:
    results = [run_row(c, s, v, exp, ef, ff) for c, s, v, exp, ef, ff in load_rows(dataset)]
    return results, summarize(results)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run engine calibration over a labeled CSV.")
    ap.add_argument("--dataset", required=True, type=Path)
    ap.add_argument("--out", type=Path, help="output prefix; writes <prefix>.json and .md")
    args = ap.parse_args()

    results, summary = calibrate(args.dataset)
    payload = {"summary": summary, "results": [asdict(r) for r in results]}

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.with_suffix(".json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
        args.out.with_suffix(".md").write_text(
            to_markdown(results, summary), encoding="utf-8"
        )
    print(to_markdown(results, summary))


if __name__ == "__main__":
    main()
