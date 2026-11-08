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

A row the whole-report cache misses is still fetched and indexed, but under ``--cache-dir`` each
scanner whose code is unchanged replays its result on the same files (``skilltotal.scan_cache``,
stored in ``DIR/by-scanner``): a release that changes two scanners rescans those two, so a large
package is not scanned whole again for a rule that never reads most of it. One row in
``SCAN_CACHE_AUDIT`` (chosen by its files) is scanned in full anyway and compared with the replay;
a difference is counted in ``scanner_cache_mismatches``, that scanner's stored results are
deleted, and every row that replayed anything is scanned again in full, so the report is right
either way.

``--previous FILE`` (a report JSON from an earlier run) orders the rows longest-first under
``--jobs``, from the per-row ``seconds`` that report recorded, so the run does not end with one
large package scanning while the other workers idle. The report itself stays in row order.

Each row records what was scanned, so a row that replayed nothing can be explained from two
reports: ``identity`` (the exact version or commit, under ``--cache-dir``), ``component_version``,
``index_digest`` (the digest of the scanned files the scanner cache keys on) and
``scanner_audited`` (the 1-in-N audit scanned it in full; which rows it picks changes with the
engine, see ``skilltotal.scan_cache``).

``--snapshot-dir DIR`` scans a stored copy of each registry or git row instead of fetching it, so
two runs compare the engine and nothing else. A copy is stored the first time a row is fetched:
``DIR/snapshots/<key>/`` holds ``tree.zip`` (the fetched files; of ``.git`` only its folder and
``config``, the one file in it the engine reads) and ``meta.json`` (the identity, version or
commit, fetch time, and the component and source notes the live fetch reported, so the report is
the same as a live fetch's). The key is a digest of the source and its identity;
``DIR/sources/<digest of the source>.json`` names the copy a source uses now. A copy that is
missing or damaged is fetched again and stored. ``--refresh-snapshots`` looks up each row's
identity first: unchanged, the stored copy is scanned without a download; changed, the new
release or commit is fetched and stored, and the row's ``snapshot_previous`` names the identity
it replaced. A component whose tree holds a link or a file that cannot be read is not stored (the
row is scanned live). The summary's ``snapshot_store`` gives the store's size.

``--order changed-first`` (needs ``--previous``) runs first the rows on which a previous report
found a rule of a scanner whose code changed (no folder for its current code in
``DIR/by-scanner``), then the rest, each group from small to large by the previous timings, so a
regression shows within minutes and the largest rows come last. ``--fail-fast`` stops the run at
the first row whose outcome check fails (``passed`` false). A row that replayed anything is
first scanned again in full, so a stored result cannot stop a run. Rows not yet started are
reported with status ``not_run``, and the summary says ``stopped_early``. Both are for a gate
over a corpus where any failed row blocks: a calibration set with detection rows that are
allowed to fail must not use ``--fail-fast``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.request
import uuid
import warnings
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from skilltotal import engine
from skilltotal.agent_skill import SKILL_MISMATCH_FINDING_ID
from skilltotal.collector import (
    CollectionError,
    SourceContext,
    classify_source,
    collect,
    detect_component,
    find_program,
    noninteractive_git_env,
    npm_package_spec,
    parse_git_url,
    pypi_package_spec,
    run_bounded,
)
from skilltotal.file_index import is_link
from skilltotal.models import Component, NeedsReview
from skilltotal.scan_cache import ScanCache, code_digest

# Under --cache-dir, one row in this many is scanned in full as well and compared with the replay.
SCAN_CACHE_AUDIT = 20
SCANNER_CACHE = "by-scanner"

# Expected-class -> what counts as a correct outcome.
BENIGN = "benign-baseline"
DETECT_CLASSES = {"malicious", "compromised-version"}
LAB_CLASSES = {"vulnerable-lab"}
# The status of a row --fail-fast never started.
NOT_RUN = "not_run"

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
    # Scanners replayed from DIR/by-scanner on a scanned row, and those whose audited replay
    # differed from a fresh scan (see the module docstring).
    scanner_replays: int | None = None
    scanner_cache_mismatches: list[str] | None = None
    # What was scanned, so a row that replayed nothing can be explained across runs (see the
    # module docstring). None where the run could not know it.
    identity: str | None = None
    component_version: str | None = None
    index_digest: str | None = None
    scanner_audited: bool | None = None
    # Under --snapshot-dir: "read" (scanned from the stored copy) or "stored" (fetched and stored
    # now); the identity a refresh replaced; when the scanned copy was fetched.
    snapshot: str | None = None
    snapshot_previous: str | None = None
    snapshot_fetched_at: str | None = None


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


def _analyze_spec(spec: str, scan_cache: ScanCache | None = None) -> tuple[engine.Report, float]:
    """Run the static engine on a spec, resolving local ``fixture:<name>`` offline.

    Returns the report and the seconds the download took: ``engine.analyze`` reports "Reading
    files" the moment the source is on disk, so the first progress call marks the end of the
    fetch without the harness re-implementing how the engine collects a source."""
    if spec.lower().startswith(FIXTURE_PREFIX):
        name = spec[len(FIXTURE_PREFIX) :].strip()
        root = FIXTURE_ROOT / name
        if not root.is_dir():
            raise CollectionError(f"unknown fixture: {name}")
        report = engine.analyze_directory(root, detect_component(root, source=str(root)),
                                          scan_cache=scan_cache)
        return report, 0.0
    started = time.monotonic()
    fetched: list[float] = []

    def mark(_message: str) -> None:
        if not fetched:
            fetched.append(time.monotonic() - started)

    report = engine.analyze(spec, progress=mark, scan_cache=scan_cache)
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


def _analyze_context(ctx: SourceContext, scan_cache: ScanCache | None) -> engine.Report:
    """The report ``engine.analyze`` gives for a source, for one collected here (a live fetch
    that is also stored, or a stored copy). tests/test_calibrate_snapshots.py holds the two
    reports equal."""
    report = engine.analyze_directory(ctx.root, ctx.component, scan_cache=scan_cache)
    if ctx.note:
        report.needs_review.append(
            NeedsReview(category="source", title="Scan target normalized", reason=ctx.note))
    report.needs_review.extend(engine.source_notes(ctx))
    return report


Labels = tuple[str, list[str], list[str]]  # expected_result, expected and forbidden rule ids


def run_row(
    cls: str,
    source: str,
    version: str,
    expected: str = "",
    expect_findings: list[str] | None = None,
    forbid_findings: list[str] | None = None,
    cache_dir: Path | None = None,
    engine_key: str | None = None,
    replay: bool = True,
    snapshot_dir: Path | None = None,
    refresh: bool = False,
) -> RowResult:
    """Scan one row. ``replay=False`` scans it in full even under ``cache_dir`` and stores the
    fresh report over whatever entry was there. ``snapshot_dir`` and ``refresh``: see the module
    docstring."""
    spec = _spec(source, version)
    if not spec:
        return RowResult(cls=cls, source="", status="skipped", detail="no source")
    labels: Labels = (expected, expect_findings or [], forbid_findings or [])
    if snapshot_dir is not None and _snapshot_kind(spec):
        return _snapshot_row(cls, spec, labels, cache_dir, engine_key, replay,
                             SnapshotStore(snapshot_dir), refresh)

    entry: Path | None = None
    identity: str | None = None
    if cache_dir is not None and engine_key:
        identity = component_identity(spec)
        if identity:
            entry = _cache_entry(cache_dir, engine_key, identity)
            hit = _load_cached(entry, identity) if replay else None
            if hit is not None:
                return _replayed(cls, spec, hit, identity, labels)

    scan_cache = _scan_cache(cache_dir, engine_key, replay)
    started = time.monotonic()
    try:
        report, fetch_seconds = _analyze_spec(spec, scan_cache)
    except CollectionError as exc:
        # Package pulled from the registry / repo unreachable: not a scanner failure.
        return RowResult(cls=cls, source=spec, status="skipped", detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - harness must never abort the whole run
        return RowResult(cls=cls, source=spec, status="error", detail=repr(exc))
    res, facts = _scanned(cls, spec, report, started, fetch_seconds, scan_cache, labels)
    res.identity = identity
    if entry is not None:
        _store_cached(entry, identity, spec, facts, res)
    return res


def _scan_cache(cache_dir: Path | None, key: str | None, replay: bool) -> ScanCache | None:
    if cache_dir is None or not replay:
        return None
    # Salted with the engine digest: each engine audits a different one row in N (the unsalted
    # audit picked the same rows on every run, see skilltotal.scan_cache).
    return ScanCache(cache_dir / SCANNER_CACHE, audit_every=SCAN_CACHE_AUDIT, audit_salt=key or "")


def _scanned(
    cls: str, spec: str, report: engine.Report, started: float, fetch_seconds: float,
    scan_cache: ScanCache | None, labels: Labels,
) -> tuple[RowResult, dict]:
    """A scanned row's result (and the facts a cache entry stores)."""
    seconds = time.monotonic() - started
    facts = _facts(report)
    res = _result(cls, spec, facts, *labels)
    res.seconds = round(seconds, 3)
    res.fetch_seconds = round(fetch_seconds, 3)
    res.scan_seconds = round(seconds - fetch_seconds, 3)
    res.component_version = report.component.version or None
    if scan_cache is not None:
        res.scanner_replays = scan_cache.replayed
        res.scanner_cache_mismatches = sorted(set(scan_cache.mismatches)) or None
        res.index_digest = scan_cache.last_digest
        res.scanner_audited = scan_cache.audited > 0
    return res, facts


def _replayed(cls: str, spec: str, hit: dict, identity: str, labels: Labels) -> RowResult:
    res = _result(cls, spec, hit["facts"], *labels)
    res.cached = True
    res.identity = identity
    for name in ("index_digest", "component_version"):
        if isinstance(hit.get(name), str):
            setattr(res, name, hit[name])
    return res


# --- snapshots ----------------------------------------------------------------------------

SNAPSHOT_FORMAT = 1
_TREE = "tree.zip"
_META = "meta.json"
# What a SourceContext says about the fetch beyond its files; engine.analyze turns each into a
# report note, so a stored copy keeps them.
_CONTEXT_FIELDS = ("note", "skipped_entries", "distribution_note", "mirror_note", "unpacked_note")
_KEY = re.compile(r"^[0-9a-f]{24}$")
_GIT_IDENTITY = re.compile(r"^git:(?P<url>.+)@(?P<sha>[0-9a-f]{40})(?P<sub>/.*)?$")
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)  # every entry: the same tree gives the same archive bytes


class SnapshotUnusable(Exception):
    """A fetched tree that cannot be stored, or a stored copy that cannot be read back, exactly."""


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:24]


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _snapshot_kind(spec: str) -> bool:
    """Whether a row has a stored copy: a registry package or a git repository (a local path or
    a fixture is on disk already)."""
    if spec.lower().startswith(FIXTURE_PREFIX):
        return False
    try:
        return classify_source(spec) in ("npm", "pypi", "git")
    except Exception:  # noqa: BLE001 - an unclassifiable spec is scanned as before
        return False


@dataclass
class Snapshot:
    key: str
    meta: dict
    folder: Path

    @property
    def identity(self) -> str:
        return str(self.meta["identity"])

    @property
    def cache_identity(self) -> str:
        """The whole-row cache key of a row scanned from this copy: its exact archive bytes."""
        return f"snapshot:{self.key}#{self.meta['tree_sha256']}"


class SnapshotStore:
    """Stored copies of fetched components (see the module docstring)."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def _pointer(self, spec: str) -> Path:
        return self.root / "sources" / f"{_digest(spec)}.json"

    def _folder(self, key: str) -> Path:
        return self.root / "snapshots" / key

    def current(self, spec: str) -> Snapshot | None:
        """The copy ``spec`` uses now, or None when there is none or it is not intact."""
        try:
            pointer = json.loads(self._pointer(spec).read_text(encoding="utf-8"))
            key = pointer["snapshot"]
            if pointer.get("spec") != spec or not isinstance(key, str) or not _KEY.match(key):
                return None
            folder = self._folder(key)
            meta = json.loads((folder / _META).read_text(encoding="utf-8"))
            if (not isinstance(meta, dict) or meta.get("format") != SNAPSHOT_FORMAT
                    or meta.get("spec") != spec or meta.get("identity") != pointer.get("identity")
                    or not isinstance(meta.get("component"), dict)
                    or not isinstance(meta.get("context"), dict)
                    or _file_sha256(folder / _TREE) != meta.get("tree_sha256")):
                return None
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return None
        return Snapshot(key, meta, folder)

    def save(self, spec: str, identity: str, ctx: SourceContext) -> Snapshot:
        """Store the tree ``ctx`` fetched as ``spec``'s copy of ``identity``."""
        commit = _check_fetched(identity, ctx)
        key = _digest(f"{spec}\0{identity}")
        tmp = self.root / "snapshots" / f".tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        tmp.mkdir(parents=True)
        try:
            files, size = _write_tree(Path(ctx.root), tmp / _TREE)
            meta = {
                "format": SNAPSHOT_FORMAT,
                "spec": spec,
                "identity": identity,
                "version": ctx.component.version,
                "commit": commit,
                "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "root_name": Path(ctx.root).name,
                "component": ctx.component.to_dict(),
                "context": {name: getattr(ctx, name) for name in _CONTEXT_FIELDS},
                "files": files,
                "bytes": size,
                "tree_sha256": _file_sha256(tmp / _TREE),
            }
            (tmp / _META).write_text(json.dumps(meta, indent=1), encoding="utf-8")
            final = self._folder(key)
            if final.exists():
                shutil.rmtree(final)
            os.replace(tmp, final)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        pointer = self._pointer(spec)
        pointer.parent.mkdir(parents=True, exist_ok=True)
        part = pointer.with_name(f"{pointer.name}.{os.getpid()}.tmp")
        part.write_text(json.dumps({"format": SNAPSHOT_FORMAT, "spec": spec, "snapshot": key,
                                    "identity": identity, "updated": meta["fetched_at"]}),
                        encoding="utf-8")
        os.replace(part, pointer)
        return Snapshot(key, meta, final)

    def open(self, snap: Snapshot, dest: Path) -> SourceContext:
        """Unpack ``snap`` under the empty folder ``dest``: the context a live fetch gave."""
        name = str(snap.meta.get("root_name") or "")
        if not name or name in (".", "..") or any(c in name for c in "/\\:"):
            raise SnapshotUnusable(f"bad root folder name {name!r}")
        root = dest / name
        root.mkdir()
        with zipfile.ZipFile(snap.folder / _TREE) as zf:
            for info in zf.infolist():
                target = root.joinpath(*_member_parts(info.filename))
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, target.open("xb") as out:
                    shutil.copyfileobj(src, out)
        context = snap.meta["context"]
        return SourceContext(
            root=root, component=Component(**snap.meta["component"]),
            note=context.get("note"), skipped_entries=int(context.get("skipped_entries") or 0),
            distribution_note=context.get("distribution_note"),
            mirror_note=context.get("mirror_note"), unpacked_note=context.get("unpacked_note"),
        )

    def _referenced(self) -> set[str]:
        keys: set[str] = set()
        for pointer in (self.root / "sources").glob("*.json"):
            try:
                keys.add(str(json.loads(pointer.read_text(encoding="utf-8"))["snapshot"]))
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return keys

    def _snapshot_folders(self) -> list[Path]:
        base = self.root / "snapshots"
        return sorted(d for d in base.iterdir() if d.is_dir()) if base.is_dir() else []

    def prune(self) -> int:
        """Drop copies no source names any more (a refresh replaced them) and leftover partial
        ones; returns how many. Only for a run that holds the store alone."""
        referenced = self._referenced()
        gone = [d for d in self._snapshot_folders() if d.name not in referenced]
        for folder in gone:
            shutil.rmtree(folder, ignore_errors=True)
        return len(gone)

    def size_report(self) -> dict:
        folders = self._snapshot_folders()
        referenced = self._referenced()
        size = 0
        for folder in folders:
            size += sum(f.stat().st_size for f in folder.iterdir() if f.is_file())
        return {
            "snapshots": len(folders),
            "sources": len(list((self.root / "sources").glob("*.json"))),
            "bytes": size,
            "unreferenced": sum(1 for d in folders if d.name not in referenced),
        }


def _member_parts(name: str) -> list[str]:
    """The path parts of an archive member, refusing any that could leave the folder."""
    parts = [p for p in name.rstrip("/").split("/")]
    if not name or "\\" in name or name.startswith("/") or any(
            p in ("", ".", "..") or ":" in p for p in parts):
        raise SnapshotUnusable(f"bad archive member {name!r}")
    return parts


def _tree_entries(root: Path) -> list[tuple[str, bool]]:
    """``(relative path, is a folder)`` for everything a stored copy keeps under ``root``: every
    file and folder, and of a ``.git`` folder only the folder itself and, at the top, its
    ``config`` (the one file in it the index reads). A link or anything that is neither a file
    nor a folder cannot be stored faithfully, so the copy is refused."""
    out: list[tuple[str, bool]] = []
    pending: list[tuple[str, ...]] = [()]
    while pending:
        parts = pending.pop()
        try:
            with os.scandir(root.joinpath(*parts)) as listing:
                entries = list(listing)
        except OSError as exc:
            raise SnapshotUnusable(f"cannot list {'/'.join(parts) or '.'}") from exc
        for entry in entries:
            rel = (*parts, entry.name)
            relpath = "/".join(rel)
            path = Path(entry.path)
            if is_link(path):
                raise SnapshotUnusable(f"a link: {relpath}")
            if entry.is_dir(follow_symlinks=False):
                out.append((relpath, True))
                if entry.name == ".git":
                    config = path / "config"
                    if not parts and is_link(config):
                        raise SnapshotUnusable("a link: .git/config")
                    if not parts and config.is_file():
                        out.append((".git/config", False))
                    continue
                pending.append(rel)
            elif entry.is_file(follow_symlinks=False):
                out.append((relpath, False))
            else:
                raise SnapshotUnusable(f"neither a file nor a folder: {relpath}")
    return sorted(out)


def _write_tree(root: Path, archive: Path) -> tuple[int, int]:
    """Write the tree under ``root`` to ``archive``; returns (files, bytes before compression)."""
    files = size = 0
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for relpath, is_dir in _tree_entries(root):
            if is_dir:
                zf.writestr(zipfile.ZipInfo(relpath + "/", date_time=_ZIP_TIME), b"")
                continue
            info = zipfile.ZipInfo(relpath, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            source = root.joinpath(*relpath.split("/"))
            try:
                with source.open("rb") as src, zf.open(info, "w", force_zip64=True) as out:
                    shutil.copyfileobj(src, out)
            except OSError as exc:
                raise SnapshotUnusable(f"cannot read {relpath}") from exc
            files += 1
            size += info.file_size
    return files, size


def _check_fetched(identity: str, ctx: SourceContext) -> str | None:
    """Refuse a fetch that is not the release or commit ``identity`` names (one published between
    the lookup and the download); returns the commit of a git checkout."""
    kind = identity.split(":", 1)[0]
    if kind in ("npm", "pypi"):
        body = identity.split("#", 1)[0]
        version = body.rsplit("@", 1)[-1] if kind == "npm" else body.split("==", 1)[-1]
        fetched = ctx.component.version
        if version != fetched and version not in (ctx.component.download_url or ""):
            raise SnapshotUnusable(f"fetched {fetched or 'an unknown version'}, the registry "
                                   f"named {version}")
        return None
    match = _GIT_IDENTITY.match(identity)
    if not match:
        raise SnapshotUnusable(f"unknown identity {identity!r}")
    base = Path(ctx.root)
    for _ in [p for p in (match.group("sub") or "").split("/") if p]:
        base = base.parent
    commit = _head_commit(base / ".git")
    if commit != match.group("sha"):
        raise SnapshotUnusable(f"checked out {commit or 'an unknown commit'}, ls-remote named "
                               f"{match.group('sha')}")
    return commit


def _head_commit(git_dir: Path) -> str | None:
    """The commit a checkout's HEAD names, read from its files (no git run)."""
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if _SHA1.match(head):
        return head
    ref = head[5:].strip() if head.startswith("ref: ") else ""
    if not ref.startswith("refs/") or ".." in ref.split("/"):
        return None
    try:
        value = git_dir.joinpath(*ref.split("/")).read_text(encoding="utf-8").strip()
        if _SHA1.match(value):
            return value
    except OSError:
        pass
    try:
        for line in (git_dir / "packed-refs").read_text(encoding="utf-8").splitlines():
            sha, _, name = line.partition(" ")
            if name.strip() == ref and _SHA1.match(sha):
                return sha
    except OSError:
        pass
    return None


def _snapshot_row(
    cls: str, spec: str, labels: Labels, cache_dir: Path | None, key: str | None,
    replay: bool, store: SnapshotStore, refresh: bool,
) -> RowResult:
    """One registry or git row under --snapshot-dir: its stored copy, or a fetch that is stored."""
    snap = store.current(spec)
    previous = snap.identity if snap is not None else None
    identity: str | None = None
    note = ""
    if refresh or snap is None:
        identity = component_identity(spec)
        if snap is not None and identity is None:
            note = "the identity lookup failed; scanned the stored copy"
        elif snap is not None and identity != snap.identity:
            snap = None
    if snap is not None:
        res = _scan_snapshot(cls, spec, labels, cache_dir, key, replay, store, snap)
    else:
        res = _fetch_and_store(cls, spec, labels, cache_dir, key, replay, store, identity)
        if res.snapshot == "stored" and previous is not None and previous != res.identity:
            res.snapshot_previous = previous
    res.detail = "; ".join(d for d in (res.detail, note) if d)
    return res


def _scan_snapshot(
    cls: str, spec: str, labels: Labels, cache_dir: Path | None, key: str | None,
    replay: bool, store: SnapshotStore, snap: Snapshot,
) -> RowResult:
    entry: Path | None = None
    if cache_dir is not None and key:
        entry = _cache_entry(cache_dir, key, snap.cache_identity)
        hit = _load_cached(entry, snap.cache_identity) if replay else None
        if hit is not None:
            res = _replayed(cls, spec, hit, snap.identity, labels)
            res.snapshot, res.snapshot_fetched_at = "read", snap.meta.get("fetched_at")
            return res
    scan_cache = _scan_cache(cache_dir, key, replay)
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="skilltotal-snapshot-",
                                         ignore_cleanup_errors=True) as tmp:
            try:
                ctx = store.open(snap, Path(tmp))
            except (SnapshotUnusable, OSError, zipfile.BadZipFile, ValueError) as exc:
                unusable = f"the stored copy could not be unpacked ({exc}); fetched live"
            else:
                unusable = ""
                fetch_seconds = time.monotonic() - started
                report = _analyze_context(ctx, scan_cache)
    except Exception as exc:  # noqa: BLE001 - harness must never abort the whole run
        return RowResult(cls=cls, source=spec, status="error", detail=repr(exc))
    if unusable:
        # Scanned as fetched now, and not stored again: the same copy would fail the same way.
        res = _fetch_and_store(cls, spec, labels, cache_dir, key, replay, store, None)
        res.detail = "; ".join(d for d in (res.detail, unusable) if d)
        return res
    res, facts = _scanned(cls, spec, report, started, fetch_seconds, scan_cache, labels)
    res.identity = snap.identity
    res.snapshot, res.snapshot_fetched_at = "read", snap.meta.get("fetched_at")
    if entry is not None:
        _store_cached(entry, snap.cache_identity, spec, facts, res)
    return res


def _fetch_and_store(
    cls: str, spec: str, labels: Labels, cache_dir: Path | None, key: str | None,
    replay: bool, store: SnapshotStore, identity: str | None,
) -> RowResult:
    """Fetch ``spec`` as engine.analyze would, store the copy when ``identity`` names it, scan."""
    scan_cache = _scan_cache(cache_dir, key, replay)
    started = time.monotonic()
    snap: Snapshot | None = None
    why = "" if identity else "not stored: its identity could not be looked up"
    try:
        with collect(spec) as ctx:
            if identity:
                try:
                    snap = store.save(spec, identity, ctx)
                except Exception as exc:  # noqa: BLE001 - storing a copy never fails the row
                    why = f"not stored: {exc}"
            fetch_seconds = time.monotonic() - started
            report = _analyze_context(ctx, scan_cache)
    except CollectionError as exc:
        return RowResult(cls=cls, source=spec, status="skipped", detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - harness must never abort the whole run
        return RowResult(cls=cls, source=spec, status="error", detail=repr(exc))
    res, facts = _scanned(cls, spec, report, started, fetch_seconds, scan_cache, labels)
    res.identity = identity
    res.detail = why
    if snap is not None:
        res.snapshot, res.snapshot_fetched_at = "stored", snap.meta["fetched_at"]
        if cache_dir is not None and key:
            _store_cached(_cache_entry(cache_dir, key, snap.cache_identity), snap.cache_identity,
                          spec, facts, res)
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


def _cache_entry(cache_dir: Path, key: str, identity: str) -> Path:
    return cache_dir / key / f"{hashlib.sha256(identity.encode()).hexdigest()}.json"


def _load_cached(entry: Path, identity: str) -> dict | None:
    """The stored entry for ``identity`` (its ``facts`` checked), or None."""
    try:
        data = json.loads(entry.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("identity") != identity:
        return None
    return data if _well_formed_facts(data.get("facts")) else None


def _store_cached(entry: Path, identity: str, spec: str, facts: dict, res: RowResult) -> None:
    payload = {
        "identity": identity,
        "spec": spec,
        "facts": facts,
        "seconds": res.seconds,
        "fetch_seconds": res.fetch_seconds,
        "scan_seconds": res.scan_seconds,
        "index_digest": res.index_digest,
        "component_version": res.component_version,
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
        "scanner_replays": sum(r.scanner_replays or 0 for r in ok),
        "scanner_cache_mismatches": sum(1 for r in ok if r.scanner_cache_mismatches),
        "scanner_audited": sum(1 for r in ok if r.scanner_audited),
        "scan_seconds": round(sum(r.seconds or 0.0 for r in results), 1),
        "snapshots_read": sum(1 for r in ok if r.snapshot == "read"),
        "snapshots_stored": sum(1 for r in ok if r.snapshot == "stored"),
        "snapshots_changed": sum(1 for r in ok if r.snapshot_previous),
        "not_run": sum(1 for r in results if r.status == NOT_RUN),
        # Set by calibrate() under --fail-fast: the run stopped at the failure on this source.
        "stopped_early": False,
        "stopped_on": None,
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
    ]
    if summary.get("stopped_early"):
        lines += [
            f"**Stopped early** (--fail-fast) at the failure on `{summary.get('stopped_on')}`: "
            f"{summary.get('not_run', 0)} row(s) not run. This is a partial report.",
            "",
        ]
    lines += [
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
        f"- scanner results replayed: {summary.get('scanner_replays', 0)}; audited replays that "
        f"differed from a fresh scan: **{summary.get('scanner_cache_mismatches', 0)}** row(s)",
    ]
    if "snapshot_store" in summary:
        store = summary["snapshot_store"]
        lines.append(
            f"- snapshots: {summary.get('snapshots_read', 0)} read, "
            f"{summary.get('snapshots_stored', 0)} stored ({summary.get('snapshots_changed', 0)} "
            f"replaced a changed upstream); store {store['snapshots']} copies, "
            f"{store['bytes'] / 1e6:.1f} MB, {store['unreferenced']} unreferenced")
    lines += [
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


def previous_findings(reports: list[Path]) -> dict[str, list[str]]:
    """``source -> finding ids`` from earlier runs' JSON reports (the first report given wins).
    A report records the ids of a row that declares golden labels, as the tripwire corpus does."""
    out: dict[str, list[str]] = {}
    for report in reports:
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
            rows = data["results"] if isinstance(data, dict) else []
        except (OSError, ValueError, KeyError, TypeError):
            continue
        for r in rows:
            if not isinstance(r, dict) or not r.get("source") or str(r["source"]) in out:
                continue
            ids = r.get("finding_ids")
            if isinstance(ids, list) and all(isinstance(i, str) for i in ids):
                out[str(r["source"])] = list(ids)
    return out


def changed_scanner_rules(cache_dir: Path | None) -> set[str]:
    """The rule ids of every scanner whose current code has no folder in ``cache_dir``'s scanner
    cache (all of them without a cache): the rules this engine may judge differently."""
    from skilltotal.scanners import SCANNERS

    base = cache_dir / SCANNER_CACHE if cache_dir is not None else None
    return {
        rule.id
        for scanner in SCANNERS
        if base is None or not (base / scanner.name / code_digest(scanner)).is_dir()
        for rule in getattr(scanner, "rules", [])
    }


def changed_first(
    specs: list[str], seconds: dict[str, float], findings: dict[str, list[str]],
    changed_rules: set[str],
) -> list[int]:
    """Row indices for ``--order changed-first``: rows a previous report found a changed rule on,
    then the rest; within each, rows with no timing first (new rows), then small to large."""
    def by_size(indices: list[int]) -> list[int]:
        unknown = [i for i in indices if specs[i] not in seconds]
        known = sorted((i for i in indices if specs[i] in seconds),
                       key=lambda i: (seconds[specs[i]], i))
        return unknown + known

    first = [i for i, s in enumerate(specs) if changed_rules & set(findings.get(s, ()))]
    taken = set(first)
    return by_size(first) + by_size([i for i in range(len(specs)) if i not in taken])


def calibrate(
    dataset: Path,
    progress: TextIO | None = None,
    jobs: int = 1,
    cache_dir: Path | None = None,
    previous: list[Path] | None = None,
    snapshot_dir: Path | None = None,
    refresh_snapshots: bool = False,
    order_by: str | None = None,
    fail_fast: bool = False,
) -> tuple[list[RowResult], dict]:
    """Run every row. With ``progress``, write ``[i/N] <source>`` there as each row starts
    (one process) or finishes (``jobs`` > 1, see the module docstring)."""
    rows = load_rows(dataset)
    key = engine_key() if cache_dir is not None else None
    if cache_dir is not None:
        # The ops job drops cache folders untouched for 60 days; replays alone write nothing.
        try:
            (cache_dir / SCANNER_CACHE).mkdir(parents=True, exist_ok=True)
            os.utime(cache_dir / SCANNER_CACHE)
        except OSError:
            pass
    specs = [_spec(r[1], r[2]) for r in rows]
    order = list(range(len(rows)))
    if order_by == "changed-first":
        order = changed_first(specs, previous_seconds(previous or []),
                              previous_findings(previous or []), changed_scanner_rules(cache_dir))
    elif previous and jobs > 1:
        order = longest_first(specs, previous_seconds(previous))
    where = {"snapshot_dir": snapshot_dir, "refresh": refresh_snapshots}
    ran, stopped_on = _run_rows(rows, order, jobs, progress, cache_dir, key, replay=True,
                                fail_fast=fail_fast, **where)
    # The report stays in row order; under --fail-fast the rows never started are named.
    results = [
        ran[i] if i in ran else RowResult(
            cls=rows[i][0], source=specs[i], status=NOT_RUN,
            detail=f"not scanned: --fail-fast stopped the run at the failure on {stopped_on}")
        for i in range(len(rows))
    ]
    # An audited replay that differed from a fresh scan means some stored result of that scanner
    # is wrong: its entries go, and every row that replayed anything is scanned again in full.
    bad = sorted({name for r in results for name in (r.scanner_cache_mismatches or [])})
    if bad and cache_dir is not None:
        for name in bad:
            shutil.rmtree(cache_dir / SCANNER_CACHE / name, ignore_errors=True)
        again = [i for i in order if results[i].scanner_replays]
        if progress is not None:
            print(f"scanner cache differed for {', '.join(bad)}: rescanning {len(again)} row(s)",
                  file=progress, flush=True)
        rescanned, _ = _run_rows(rows, again, jobs, progress, cache_dir, key, replay=False,
                                 **where)
        for i, fresh in rescanned.items():
            fresh.scanner_cache_mismatches = results[i].scanner_cache_mismatches
            results[i] = fresh
    summary = summarize(results)
    summary["stopped_early"] = stopped_on is not None
    summary["stopped_on"] = stopped_on
    if snapshot_dir is not None:
        store = SnapshotStore(snapshot_dir)
        # Copies a refresh replaced, and partial ones a killed run left: only a refresh, which
        # runs on the store alone, removes them.
        summary["snapshots_pruned"] = store.prune() if refresh_snapshots else 0
        summary["snapshot_store"] = store.size_report()
    return results, summary


def _failed(res: RowResult) -> bool:
    return res.status == "ok" and res.passed is False


def _run_rows(
    rows: list, order: list[int], jobs: int, progress: TextIO | None,
    cache_dir: Path | None, key: str | None, *, replay: bool, fail_fast: bool = False,
    snapshot_dir: Path | None = None, refresh: bool = False,
) -> tuple[dict[int, RowResult], str | None]:
    """``run_row`` for the rows at ``order``, by row index. One process writes
    ``[i/N] <source>`` as each row starts; ``jobs`` > 1 as each one finishes. With
    ``fail_fast``, no new row starts after the first confirmed failure (rows already running
    finish); the second value is that row's source, None when the run did not stop."""
    out: dict[int, RowResult] = {}
    extra = (cache_dir, key, replay, snapshot_dir, refresh)

    def confirmed(i: int) -> bool:
        # A failure that rests on a stored result is scanned again in full before it may stop
        # the run (a stored copy of the component is still what is scanned: no new download).
        res = out[i]
        if res.cached or res.scanner_replays:
            out[i] = run_row(*rows[i], cache_dir, key, False, snapshot_dir, False)
        return _failed(out[i])

    if jobs <= 1:
        for n, i in enumerate(order, 1):
            if progress is not None:
                print(f"[{n}/{len(order)}] {rows[i][1]}", file=progress, flush=True)
            out[i] = run_row(*rows[i], *extra)
            if fail_fast and _failed(out[i]) and confirmed(i):
                return out, out[i].source
        return out, None
    stopped_on: str | None = None
    with ProcessPoolExecutor(max_workers=jobs, initializer=_quiet_worker) as pool:
        pending = {pool.submit(run_row, *rows[i], *extra): i for i in order}
        done = 0
        for fut in as_completed(pending):
            if fut.cancelled():
                continue
            i = pending[fut]
            done += 1
            try:
                out[i] = fut.result()
            except Exception as exc:  # noqa: BLE001 - a dead worker is one row's error, not the run's
                out[i] = RowResult(
                    cls=rows[i][0], source=rows[i][1], status="error", detail=repr(exc)
                )
            if progress is not None:
                print(f"[{done}/{len(order)}] {rows[i][1]}", file=progress, flush=True)
            if fail_fast and stopped_on is None and _failed(out[i]) and confirmed(i):
                stopped_on = out[i].source
                for other in pending:
                    other.cancel()
                if progress is not None:
                    print(f"--fail-fast: stopped at the failure on {stopped_on}",
                          file=progress, flush=True)
    return out, stopped_on


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
    ap.add_argument(
        "--snapshot-dir", type=Path,
        help="scan a stored copy of each registry/git row instead of fetching it; a row with "
             "none is fetched and stored",
    )
    ap.add_argument(
        "--refresh-snapshots", action="store_true",
        help="with --snapshot-dir: fetch and store what changed upstream, scan the rest stored",
    )
    ap.add_argument(
        "--order", choices=["changed-first"], dest="order_by",
        help="changed-first: rows with a finding of a scanner whose code changed first, then "
             "the rest, small to large (timings and findings from --previous)",
    )
    ap.add_argument(
        "--fail-fast", action="store_true",
        help="stop at the first row whose outcome check fails; the report is partial and says so",
    )
    args = ap.parse_args()
    if args.refresh_snapshots and args.snapshot_dir is None:
        ap.error("--refresh-snapshots needs --snapshot-dir")

    # Compiling the scanned third-party Python emits SyntaxWarnings (invalid escapes in a
    # linter's test files, ...). They say nothing about the calibration and filled the progress
    # file the release script tails: 118 lines in the first half hour of the 0.62.0 run.
    warnings.filterwarnings("ignore", category=SyntaxWarning)
    # Progress goes to stderr, flushed per row: stdout carries the markdown report, and a piped
    # stdout is block-buffered, so progress printed there would arrive in chunks.
    opts = {"jobs": max(1, args.jobs), "cache_dir": args.cache_dir, "previous": args.previous,
            "snapshot_dir": args.snapshot_dir, "refresh_snapshots": args.refresh_snapshots,
            "order_by": args.order_by, "fail_fast": args.fail_fast}
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
