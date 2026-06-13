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

This is an *informational* tool (always exits 0). It never changes rules; calibration
decisions are made by a human. The real labeled dataset lives in the private ops repo;
this module ships only the harness + a tiny synthetic sample for the unit test.

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
    passed: bool | None = None  # outcome vs expectation (None when skipped)
    detail: str = ""


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


def run_row(cls: str, source: str, version: str, expected: str = "") -> RowResult:
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
    res.passed = _judge(
        cls, res.has_malicious, res.risk_level, res.risky_constructs, res.capabilities, expected
    )
    return res


def summarize(results: list[RowResult]) -> dict:
    ok = [r for r in results if r.status == "ok"]
    benign = [r for r in ok if r.cls == BENIGN]
    detect = [r for r in ok if r.cls in DETECT_CLASSES]
    labs = [r for r in ok if r.cls in LAB_CLASSES]
    benign_fp = [r for r in benign if r.has_malicious]
    noisy = [r.needs_review for r in ok if r.needs_review is not None]
    return {
        "rows_total": len(results),
        "scanned": len(ok),
        "skipped": sum(1 for r in results if r.status == "skipped"),
        "errors": sum(1 for r in results if r.status == "error"),
        "benign_scanned": len(benign),
        "benign_false_positives": len(benign_fp),
        "detect_scanned": len(detect),
        "detect_detected": sum(1 for r in detect if r.passed),
        "labs_scanned": len(labs),
        "labs_flagged": sum(1 for r in labs if r.passed),
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
        f"- malicious/compromised detected: {summary['detect_detected']} / "
        f"{summary['detect_scanned']} scanned",
        f"- vulnerable-labs flagged: {summary['labs_flagged']} / {summary['labs_scanned']}",
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
    return "\n".join(lines) + "\n"


def load_rows(path: Path) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            rows.append(
                (
                    (row.get("class") or "").strip(),
                    (row.get("source") or "").strip(),
                    (row.get("version") or "").strip(),
                    (row.get("expected_result") or "").strip(),
                )
            )
    return rows


def calibrate(dataset: Path) -> tuple[list[RowResult], dict]:
    results = [run_row(c, s, v, exp) for c, s, v, exp in load_rows(dataset)]
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
