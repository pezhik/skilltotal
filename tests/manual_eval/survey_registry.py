"""Survey the whole public MCP registry: scan every unique component, once, reproducibly.

This is the data-collection half of a published study, so the method has to be defensible:

* **Deduplicated population.** The registry lists a *server per published version*, so 73k entries
  collapse to ~17.5k distinct sources. Aggregating over the raw list would count one package a
  thousand times and inflate every percentage.
* **Two independent bounds, both disclosed.** ``--clone-mb`` bounds fetch size and ``--timeout``
  bounds wall-clock per component. A size cap alone is not enough: a repo can sit under the cap and
  still take minutes to analyze. Whatever the bounds exclude is recorded as a skip with its reason,
  never silently dropped — "scanned N of M, skipped K because ..." is part of the result.
* **Resumable.** Output is JSONL appended as each component finishes, and a restart skips sources
  already present. A multi-hour run must not be all-or-nothing.
* **Isolated per component.** Each scan runs in its own subprocess, so a hang or a crash costs one
  row instead of the run, and ``--timeout`` can actually be enforced by killing it.

Evidence snippets are deliberately NOT recorded: the study reports aggregates (which rules fire,
which capabilities appear), never a verdict about a named project.

Usage:
    python tests/manual_eval/survey_registry.py --out survey.jsonl --workers 8
    python tests/manual_eval/survey_registry.py --out survey.jsonl --limit 50   # smoke slice
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess  # nosec B404 - we spawn ourselves, with a fixed argv
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_HERE))

import discover_mcp as dm  # noqa: E402

import skilltotal  # noqa: E402


def unique_sources(items: list[dict]) -> list[tuple[str, str]]:
    """(source, ecosystem) for each DISTINCT registry source, in first-seen order."""
    seen: dict[str, str] = {}
    for cand in (dm.normalize_entry(it) for it in items):
        if cand is not None and dm.hygiene_ok(cand):
            seen.setdefault(cand.source, cand.ecosystem)
    return list(seen.items())


def load_registry(cache: Path | None, max_pages: int) -> list[dict]:
    """Registry items from a local cache when present, else fetched and cached."""
    if cache and cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    items = dm.fetch_registry(max_pages=max_pages)
    if cache:
        cache.write_text(json.dumps(items), encoding="utf-8")
    return items


def scan_one(source: str) -> dict:
    """Analyze one component in-process and project it down to aggregate-only fields."""
    from skilltotal import engine

    report = engine.analyze(source).to_dict()
    meta = report.get("metadata") or {}
    findings = report.get("findings") or []
    return {
        "risk_score": report.get("risk_score"),
        "risk_level": report.get("risk_level"),
        "malicious": bool((report.get("verdict") or {}).get("has_malicious_indicators")),
        # Rule ids + severities only — never the evidence, which would name and quote a project.
        "rules": sorted({f["id"] for f in findings}),
        "severities": sorted({f["severity"] for f in findings}),
        "owasp": sorted({o for f in findings for o in (f.get("owasp") or [])}),
        "capabilities": sorted((report.get("capabilities") or {}).keys()),
        # traits entries are keyed "trait" (traits.build_trait_profile), not "id".
        "traits": sorted(t["trait"] for t in (report.get("traits") or []) if t.get("trait")),
        "findings_count": len(findings),
        "needs_review_count": len(report.get("needs_review") or []),
        "component_type": (report.get("component") or {}).get("type"),
        "ruleset_version": meta.get("ruleset_version"),
    }


def _run_worker(source: str, ecosystem: str, timeout: int, clone_mb: int) -> dict:
    """Run one scan in a killable child process; a timeout or crash becomes a recorded skip."""
    env = dict(os.environ)
    env["SKILLTOTAL_MAX_CLONE_MB"] = str(clone_mb)
    env["PYTHONIOENCODING"] = "utf-8"
    started = time.perf_counter()
    row: dict = {"source": source, "ecosystem": ecosystem}
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, no shell
            [sys.executable, str(Path(__file__).resolve()), "--one", source],
            capture_output=True, text=True, timeout=timeout, env=env, encoding="utf-8",
        )
    except subprocess.TimeoutExpired:
        row.update(status="skipped", reason="timeout")
        row["elapsed"] = round(time.perf_counter() - started, 2)
        return row
    row["elapsed"] = round(time.perf_counter() - started, 2)
    if proc.returncode != 0:
        reason = (proc.stderr or "").strip().splitlines()[-1:] or ["unknown"]
        row.update(status="skipped", reason=reason[0][:200])
        return row
    try:
        row.update(status="ok", **json.loads(proc.stdout))
    except ValueError:
        row.update(status="skipped", reason="unparseable worker output")
    return row


def already_done(out: Path) -> set[str]:
    """Sources already recorded, so a restart resumes instead of rescanning."""
    if not out.exists():
        return set()
    done: set[str] = set()
    with out.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                done.add(json.loads(line)["source"])
            except (ValueError, KeyError):
                continue  # a torn last line from a killed run
    return done


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scan every unique component in the MCP registry.")
    ap.add_argument("--one", help="internal: scan a single source and print JSON")
    ap.add_argument("--out", default=str(_REPO_ROOT / "survey.jsonl"))
    ap.add_argument("--registry-cache", default="")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=60, help="wall-clock seconds per component")
    ap.add_argument("--clone-mb", type=int, default=50)
    ap.add_argument("--max-pages", type=int, default=1000)
    ap.add_argument("--limit", type=int, default=0, help="scan only the first N (smoke run)")
    ap.add_argument(
        "--ecosystem",
        default="",
        help="comma-separated subset to scan (npm,pypi,git); empty means all. Lets a change that "
        "only affects one fetch path be re-measured without repeating the whole population.",
    )
    args = ap.parse_args(argv)

    if args.one:  # worker mode
        json.dump(scan_one(args.one), sys.stdout)
        return 0

    cache = Path(args.registry_cache) if args.registry_cache else None
    items = load_registry(cache, args.max_pages)
    population = unique_sources(items)
    out = Path(args.out)
    done = already_done(out)
    todo = [(s, e) for s, e in population if s not in done]
    wanted = {x.strip() for x in args.ecosystem.split(",") if x.strip()}
    if wanted:
        todo = [(s, e) for s, e in todo if e in wanted]
    if args.limit:
        todo = todo[: args.limit]

    print(
        f"registry entries={len(items)} unique={len(population)} "
        f"already done={len(done)} to scan={len(todo)} "
        f"engine={skilltotal.__version__} ruleset={skilltotal.RULESET_VERSION} "
        f"workers={args.workers} timeout={args.timeout}s clone_cap={args.clone_mb}MB",
        flush=True,
    )

    started = time.perf_counter()
    counts = {"ok": 0, "skipped": 0}
    with out.open("a", encoding="utf-8") as fh, ThreadPoolExecutor(args.workers) as pool:
        futures = [
            pool.submit(_run_worker, src, eco, args.timeout, args.clone_mb) for src, eco in todo
        ]
        for i, future in enumerate(futures, 1):
            row = future.result()
            counts[row["status"]] = counts.get(row["status"], 0) + 1
            fh.write(json.dumps(row) + "\n")
            if i % 100 == 0 or i == len(futures):
                rate = i / max(0.001, time.perf_counter() - started)
                eta = (len(futures) - i) / max(0.001, rate) / 3600
                fh.flush()
                print(
                    f"[{i}/{len(futures)}] ok={counts['ok']} skipped={counts['skipped']} "
                    f"{rate:.1f}/s eta={eta:.1f}h",
                    flush=True,
                )
    print(f"done in {(time.perf_counter() - started) / 3600:.2f}h -> {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
