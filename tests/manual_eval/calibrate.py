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
    python tests/manual_eval/calibrate.py --dataset <file.csv> [--out <prefix>] [--jobs N]
                                          [--progress <file>]

``--jobs N`` scans N rows at once, each in a process of its own (default 1). Rows are
independent and almost all of the time is the scan itself, not the download, so a 750-row run
goes from hours to well under one on an 8-core machine. Results come back in row order, so the
report is the same as with one process; the ``[i/N]`` progress lines then count rows as they
finish, not as they start.

``--cache-dir DIR`` replays a row instead of fetching and scanning it when the same engine code
has already scanned the same bytes: the key is a hash of every file under ``skilltotal/`` (plus
this harness, the Python version and the platform) and the component's exact identity, which is
resolved without a download (an npm version and its integrity, a PyPI version and its file
digests, a git commit from ``git ls-remote``). The engine is deterministic, so a hit is the same
report the scan would produce; any change to the engine or a new published version misses by
construction. A row whose identity cannot be resolved (a local path, a fixture, a registry
lookup that fails) is scanned as before. The pass/fail judgement and the golden-finding check
are recomputed from the cached facts, so relabelling a row never needs a rescan.

``--previous FILE`` (a report JSON from an earlier run) orders the rows longest-first under
``--jobs``, from the per-row ``seconds`` that report recorded, so the run does not end with one
large package scanning while the other workers idle. The report itself stays in row order.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
import urllib.request
import warnings
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from skilltotal import engine
from skilltotal.agent_skill import SKILL_MISMATCH_FINDING_ID
from skilltotal.collector import (
    CollectionError,
    classify_source,
    detect_component,
    find_program,
    noninteractive_git_env,
    npm_package_spec,
    parse_git_url,
    pypi_package_spec,
    run_bounded,
)

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
    # Wall time of the row (download + scan), and its two parts; None when skipped or replayed.
    seconds: float | None = None
    fetch_seconds: float | None = None
    scan_seconds: float | None = None
    cached: bool = False  # replayed from --cache-dir, see the module docstring


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


def _analyze_spec(spec: str) -> tuple[engine.Report, float]:
    """Run the static engine on a spec, resolving local ``fixture:<name>`` offline.

    Returns the report and the seconds the download took: ``engine.analyze`` reports "Reading
    files" the moment the source is on disk, so the first progress call marks the end of the
    fetch without the harness re-implementing how the engine collects a source."""
    if spec.lower().startswith(FIXTURE_PREFIX):
        name = spec[len(FIXTURE_PREFIX) :].strip()
        root = FIXTURE_ROOT / name
        if not root.is_dir():
            raise CollectionError(f"unknown fixture: {name}")
        return engine.analyze_directory(root, detect_component(root, source=str(root))), 0.0
    started = time.monotonic()
    fetched: list[float] = []

    def mark(_message: str) -> None:
        if not fetched:
            fetched.append(time.monotonic() - started)

    report = engine.analyze(spec, progress=mark)
    return report, (fetched[0] if fetched else 0.0)


# What a scan says about a component, independent of the row's label: everything the
# judgement and the golden check need. A cache entry stores exactly this.
_FACT_FIELDS = (
    "verdict_level", "has_malicious", "risky_constructs", "capabilities", "needs_review",
    "risk_level", "skill_mismatch", "finding_ids",
)


def _facts(report: engine.Report) -> dict:
    v = report.verdict or {}
    return {
        "verdict_level": v.get("level"),
        "has_malicious": bool(v.get("has_malicious_indicators")),
        "risky_constructs": int(v.get("risky_constructs", 0)),
        "capabilities": int(v.get("capabilities", 0)),
        "needs_review": len(report.needs_review),
        "risk_level": report.risk_level.value,
        "skill_mismatch": any(f.id == SKILL_MISMATCH_FINDING_ID for f in report.findings),
        "finding_ids": sorted({f.id for f in report.findings}),
    }


def _well_formed_facts(facts: object) -> bool:
    if not isinstance(facts, dict) or any(k not in facts for k in _FACT_FIELDS):
        return False
    return (
        isinstance(facts["has_malicious"], bool)
        and isinstance(facts["skill_mismatch"], bool)
        and all(isinstance(facts[k], int) for k in ("risky_constructs", "capabilities",
                                                     "needs_review"))
        and isinstance(facts["risk_level"], str)
        and isinstance(facts["finding_ids"], list)
        and all(isinstance(i, str) for i in facts["finding_ids"])
    )


def _result(
    cls: str,
    spec: str,
    facts: dict,
    expected: str,
    expect_findings: list[str],
    forbid_findings: list[str],
) -> RowResult:
    """Judge a row's facts against its labels."""
    res = RowResult(
        cls=cls,
        source=spec,
        status="ok",
        verdict_level=facts["verdict_level"],
        has_malicious=facts["has_malicious"],
        risky_constructs=facts["risky_constructs"],
        capabilities=facts["capabilities"],
        needs_review=facts["needs_review"],
        risk_level=facts["risk_level"],
        skill_mismatch=facts["skill_mismatch"],
    )
    res.passed = _judge(
        cls, res.has_malicious, res.risk_level, res.risky_constructs, res.capabilities, expected
    )
    # Per-finding golden check: only when the row declares expected/forbidden rule ids. This is
    # the TP/FP floor the verdict-level metrics miss — e.g. a rule that fires but leaves the
    # component "high, not malicious" passes the benign-FP gate yet is still a false positive.
    if expect_findings or forbid_findings:
        ids = set(facts["finding_ids"])
        res.finding_ids = sorted(ids)
        res.missing_findings = [rid for rid in expect_findings if rid not in ids]
        res.unexpected_findings = [rid for rid in forbid_findings if rid in ids]
        res.findings_ok = not res.missing_findings and not res.unexpected_findings
    return res


def run_row(
    cls: str,
    source: str,
    version: str,
    expected: str = "",
    expect_findings: list[str] | None = None,
    forbid_findings: list[str] | None = None,
    cache_dir: Path | None = None,
    engine_key: str | None = None,
) -> RowResult:
    spec = _spec(source, version)
    if not spec:
        return RowResult(cls=cls, source="", status="skipped", detail="no source")
    expect_findings = expect_findings or []
    forbid_findings = forbid_findings or []

    entry: Path | None = None
    if cache_dir is not None and engine_key:
        identity = component_identity(spec)
        if identity:
            digest = hashlib.sha256(identity.encode()).hexdigest()
            entry = cache_dir / engine_key / f"{digest}.json"
            facts = _load_cached(entry, identity)
            if facts is not None:
                res = _result(cls, spec, facts, expected, expect_findings, forbid_findings)
                res.cached = True
                return res

    started = time.monotonic()
    try:
        report, fetch_seconds = _analyze_spec(spec)
    except CollectionError as exc:
        # Package pulled from the registry / repo unreachable: not a scanner failure.
        return RowResult(cls=cls, source=spec, status="skipped", detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - harness must never abort the whole run
        return RowResult(cls=cls, source=spec, status="error", detail=repr(exc))
    seconds = time.monotonic() - started

    facts = _facts(report)
    res = _result(cls, spec, facts, expected, expect_findings, forbid_findings)
    res.seconds = round(seconds, 3)
    res.fetch_seconds = round(fetch_seconds, 3)
    res.scan_seconds = round(seconds - fetch_seconds, 3)
    if entry is not None:
        _store_cached(entry, identity, spec, facts, res)
    return res


# --- result cache -------------------------------------------------------------------------

_PACKAGE_ROOT = Path(engine.__file__).resolve().parent
_EXACT_VERSION = re.compile(r"^\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.+-]*)?$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_LOOKUP_TIMEOUT = 60  # seconds for one registry metadata request or git ls-remote


def engine_key(package_root: Path = _PACKAGE_ROOT, harness: Path = Path(__file__)) -> str:
    """A digest of everything that decides a report: the engine package, this harness, the
    Python version (``ast`` differs between releases) and the platform (path rules differ)."""
    h = hashlib.sha256()
    files = sorted(
        p for p in package_root.rglob("*") if p.is_file() and "__pycache__" not in p.parts
    )
    for path in files:
        h.update(path.relative_to(package_root).as_posix().encode())
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    h.update(harness.read_bytes())
    h.update(f"\0{sys.version_info[0]}.{sys.version_info[1]}\0{sys.platform}".encode())
    return h.hexdigest()[:24]


def component_identity(spec: str) -> str | None:
    """The exact bytes ``spec`` names today, resolved without downloading them; None when that
    is not possible (a local path, a fixture, a lookup failure), in which case the row is
    simply scanned."""
    try:
        kind = classify_source(spec)
        if kind == "npm":
            return _npm_identity(spec)
        if kind == "pypi":
            return _pypi_identity(spec)
        if kind == "git":
            return _git_identity(spec)
    except Exception:  # noqa: BLE001 - a lookup failure only costs the cache hit
        return None
    return None


def _registry_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "skilltotal-calibration"})
    with urllib.request.urlopen(req, timeout=_LOOKUP_TIMEOUT) as resp:  # nosec B310 - https
        return json.loads(resp.read().decode("utf-8"))


def _npm_identity(spec: str) -> str | None:
    name, pin = npm_package_spec(spec)
    if not name:
        return None
    if pin and _EXACT_VERSION.match(pin):
        return f"npm:{name}@{pin}"  # a published version never changes
    meta = _registry_json(f"https://registry.npmjs.org/{name}/{pin or 'latest'}")
    version = meta.get("version")
    integrity = (meta.get("dist") or {}).get("integrity") or ""
    return f"npm:{name}@{version}#{integrity}" if version else None


def _pypi_identity(spec: str) -> str | None:
    name, pin = pypi_package_spec(spec)
    if not name:
        return None
    if pin and _EXACT_VERSION.match(pin):
        return f"pypi:{name}=={pin}"
    meta = _registry_json(f"https://pypi.org/pypi/{name}/json")
    version = (meta.get("info") or {}).get("version")
    digests = sorted((u.get("digests") or {}).get("sha256", "") for u in meta.get("urls") or [])
    if not version:
        return None
    files = hashlib.sha256("\n".join(digests).encode()).hexdigest()[:16]
    return f"pypi:{name}=={version}#{files}"


def _git_identity(spec: str) -> str | None:
    clone_url, ref, subpath, _note = parse_git_url(spec)
    if ref and _SHA1.match(ref):
        sha = ref
    else:
        git = find_program("git")
        if not git:
            return None
        # The engine's own non-interactive environment and bounded run: with only
        # GIT_TERMINAL_PROMPT=0, a deleted repository waited for a Git Credential Manager login,
        # and on Windows subprocess.run's timeout then waited for the pipe for four hours
        # (tripwire, 2026-10-27).
        done = run_bounded(
            [git, "ls-remote", "--exit-code", clone_url, ref or "HEAD"],
            env=noninteractive_git_env(), timeout=_LOOKUP_TIMEOUT,
        )
        first = done.stdout.split("\n", 1)[0].split("\t", 1)[0].strip()
        if done.returncode != 0 or not _SHA1.match(first):
            return None
        sha = first
    return f"git:{clone_url}@{sha}" + (f"/{subpath}" if subpath else "")


def _load_cached(entry: Path, identity: str) -> dict | None:
    try:
        data = json.loads(entry.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("identity") != identity:
        return None
    facts = data.get("facts")
    return facts if _well_formed_facts(facts) else None


def _store_cached(entry: Path, identity: str, spec: str, facts: dict, res: RowResult) -> None:
    payload = {
        "identity": identity,
        "spec": spec,
        "facts": facts,
        "seconds": res.seconds,
        "fetch_seconds": res.fetch_seconds,
        "scan_seconds": res.scan_seconds,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        entry.parent.mkdir(parents=True, exist_ok=True)
        tmp = entry.with_name(entry.name + f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(payload, indent=1), encoding="utf-8")
        os.replace(tmp, entry)
    except OSError:
        pass  # a cache that cannot be written only costs the next run its hit


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
    # High-precision tripwire signal: a benign-baseline package that tripped a
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
        # The mean is pulled by a few large packages (one linter alone moved it by 2.5 before
        # 0.57.0), so the median and p90 say what a typical report looks like.
        "median_needs_review": _percentile(noisy, 50),
        "p90_needs_review": _percentile(noisy, 90),
        "max_needs_review": max(noisy) if noisy else 0,
        "cached": sum(1 for r in ok if r.cached),
        "scan_seconds": round(sum(r.seconds or 0.0 for r in results), 1),
    }


def _percentile(values: list[int], pct: int) -> float:
    """Nearest-rank percentile; 0.0 for no values."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, -(-pct * len(ordered) // 100))
    return float(ordered[rank - 1])


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
        f"- replayed from the result cache: {summary.get('cached', 0)} / {summary['scanned']}; "
        f"row time summed {summary.get('scan_seconds', 0.0)} s",
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


def previous_seconds(reports: list[Path]) -> dict[str, float]:
    """``source -> seconds`` from earlier runs' JSON reports, the first report given winning for
    a source several of them timed (pass the newest first). A replayed row carries no time, so
    a run after a fully cached one still finds its timings in the report before that."""
    out: dict[str, float] = {}
    for report in reports:
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
            rows = data["results"] if isinstance(data, dict) else []
        except (OSError, ValueError, KeyError, TypeError):
            continue
        for r in rows:
            if not isinstance(r, dict) or not r.get("source"):
                continue
            if isinstance(r.get("seconds"), (int, float)) and str(r["source"]) not in out:
                out[str(r["source"])] = float(r["seconds"])
    return out


def longest_first(specs: list[str], seconds: dict[str, float]) -> list[int]:
    """Row indices ordered for ``--jobs``: rows this run has no timing for go first (a new row
    may be the largest), then the rest from slowest to fastest; ties keep row order."""
    unknown = [i for i, s in enumerate(specs) if s not in seconds]
    known = sorted((i for i, s in enumerate(specs) if s in seconds),
                   key=lambda i: (-seconds[specs[i]], i))
    return unknown + known


def calibrate(
    dataset: Path,
    progress: TextIO | None = None,
    jobs: int = 1,
    cache_dir: Path | None = None,
    previous: list[Path] | None = None,
) -> tuple[list[RowResult], dict]:
    """Run every row. With ``progress``, write ``[i/N] <source>`` there as each row starts
    (one process) or finishes (``jobs`` > 1, see the module docstring)."""
    rows = load_rows(dataset)
    key = engine_key() if cache_dir is not None else None
    if jobs <= 1:
        results = []
        for i, (c, s, v, exp, ef, ff) in enumerate(rows, 1):
            if progress is not None:
                print(f"[{i}/{len(rows)}] {s}", file=progress, flush=True)
            results.append(run_row(c, s, v, exp, ef, ff, cache_dir, key))
        return results, summarize(results)

    order = list(range(len(rows)))
    if previous:
        order = longest_first([_spec(r[1], r[2]) for r in rows], previous_seconds(previous))
    out: list[RowResult | None] = [None] * len(rows)
    with ProcessPoolExecutor(max_workers=jobs, initializer=_quiet_worker) as pool:
        pending = {pool.submit(run_row, *rows[i], cache_dir, key): i for i in order}
        for done, fut in enumerate(as_completed(pending), 1):
            i = pending[fut]
            try:
                out[i] = fut.result()
            except Exception as exc:  # noqa: BLE001 - a dead worker is one row's error, not the run's
                out[i] = RowResult(
                    cls=rows[i][0], source=rows[i][1], status="error", detail=repr(exc)
                )
            if progress is not None:
                print(f"[{done}/{len(rows)}] {rows[i][1]}", file=progress, flush=True)
    results = [r for r in out if r is not None]
    return results, summarize(results)


def _quiet_worker() -> None:
    # Each worker compiles third-party Python too (see main).
    warnings.filterwarnings("ignore", category=SyntaxWarning)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run engine calibration over a labeled CSV.")
    ap.add_argument("--dataset", required=True, type=Path)
    ap.add_argument("--out", type=Path, help="output prefix; writes <prefix>.json and .md")
    ap.add_argument(
        "--jobs", type=int, default=1, help="rows scanned at once, each in its own process"
    )
    ap.add_argument(
        "--progress", type=Path, help="write the [i/N] progress lines here instead of stderr"
    )
    ap.add_argument(
        "--cache-dir", type=Path,
        help="replay rows the same engine code already scanned at the same version/commit",
    )
    ap.add_argument(
        "--previous", type=Path, action="append",
        help="an earlier run's JSON report (repeatable, newest first); with --jobs, scan its "
             "slowest rows first",
    )
    args = ap.parse_args()

    # Compiling the scanned third-party Python emits SyntaxWarnings (invalid escapes in a
    # linter's test files, ...). They say nothing about the calibration and filled the progress
    # file the release script tails: 118 lines in the first half hour of the 0.62.0 run.
    warnings.filterwarnings("ignore", category=SyntaxWarning)
    # Progress goes to stderr, flushed per row: stdout carries the markdown report, and a piped
    # stdout is block-buffered, so progress printed there would arrive in chunks.
    opts = {"jobs": max(1, args.jobs), "cache_dir": args.cache_dir, "previous": args.previous}
    if args.progress:
        with args.progress.open("w", encoding="utf-8") as progress:
            results, summary = calibrate(args.dataset, progress=progress, **opts)
    else:
        results, summary = calibrate(args.dataset, progress=sys.stderr, **opts)
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
