"""Auto-grow the corpus report manifest from the official MCP registry.

Deterministic, stdlib-only (urllib/json/csv), no LLM, no execution beyond the engine's normal
static analyze. Appends only registry components that pass dedup + resolvability + hygiene gates,
capped per run and bounded by an overall manifest ceiling. Internally resilient: any fetch or
per-candidate failure is logged and skipped; the run never aborts (exit 0) so the weekly report
refresh proceeds on whatever manifest exists.

The full run is network-bound and scheduled (like corpus_report.py); CI tests the pure
normalize/dedup/cap/hygiene/append/resolve-gate logic offline.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.error import URLError

from skilltotal import engine
from skilltotal.collector import CollectionError

REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0/servers"
MANIFEST_DEFAULT = "tests/manual_eval/report_manifest.csv"

# Positive allowlist: accept only clean, expected source shapes — an npm/pypi coordinate or a
# github URL. The official MCP registry yields exactly these; anything else (local paths, odd
# characters, whitespace) is rejected before it can reach the public manifest. An allowlist avoids
# enumerating any private/denylisted token in this public file; the authoritative public-hygiene
# grep runs in the ops publish step (over the committed manifest, before push).
_SAFE_SOURCE = re.compile(
    r"^(?:npm:[A-Za-z0-9._@/-]+|pypi:[A-Za-z0-9._-]+|https://github\.com/[A-Za-z0-9._/-]+)$"
)
_SLUG_STRIP = re.compile(r"[^a-z0-9._-]")


@dataclass(frozen=True)
class Candidate:
    source: str
    ecosystem: str
    type: str
    name: str


def _slug(name: str) -> str:
    """Stable manifest name from a reverse-DNS registry name: last path segment, lowercased."""
    tail = name.rsplit("/", 1)[-1].lower()
    return _SLUG_STRIP.sub("", tail)


def normalize_entry(item: dict) -> Candidate | None:
    """Map a registry list item ({"server": {...}, ...}) to a manifest Candidate, or None to skip.

    Prefers an npm/pypi package coordinate (per-server unique, cheap to resolve); falls back to a
    github repository URL. Returns None when neither is present/usable.
    """
    server = item.get("server") or {}
    name = (server.get("name") or "").strip()
    if not name:
        return None
    slug = _slug(name)
    if not slug:
        return None
    for pkg in server.get("packages") or []:
        rtype = (pkg.get("registryType") or "").strip().lower()
        ident = (pkg.get("identifier") or "").strip()
        if rtype == "npm" and ident:
            return Candidate(f"npm:{ident}", "npm", "mcp", slug)
        if rtype == "pypi" and ident:
            return Candidate(f"pypi:{ident}", "pypi", "mcp", slug)
    repo = server.get("repository") or {}
    url = (repo.get("url") or "").strip()
    if url and (repo.get("source") or "").strip().lower() == "github":
        return Candidate(url, "git", "mcp", slug)
    return None


def hygiene_ok(cand: Candidate) -> bool:
    """True only for a clean, expected source shape (npm/pypi coordinate or github URL).

    A positive allowlist: local paths, whitespace, and unexpected characters are rejected before a
    candidate can reach the public manifest.
    """
    return bool(_SAFE_SOURCE.match(cand.source))


def dedup(cands: list[Candidate], existing_sources: set[str]) -> list[Candidate]:
    """Drop candidates whose source is already known (in the manifest or earlier in this run)."""
    seen = set(existing_sources)
    out: list[Candidate] = []
    for c in cands:
        if c.source in seen:
            continue
        seen.add(c.source)
        out.append(c)
    return out


def resolvable(source: str, analyze=engine.analyze) -> bool:
    """True if the engine can resolve and statically scan `source` without error."""
    try:
        analyze(source)
        return True
    except CollectionError:
        return False
    except Exception:  # noqa: BLE001 - a bad component must never abort the run
        return False


def select_new(
    cands: list[Candidate],
    existing_sources: set[str],
    *,
    current_count: int,
    max_new: int,
    max_tries: int,
    manifest_cap: int,
    analyze=engine.analyze,
) -> list[Candidate]:
    """Deterministically pick up to max_new hygienic, deduped, resolvable candidates.

    Stops at max_new, the manifest ceiling, or after max_tries resolve attempts (resolves are
    network-bound clones/installs, so the attempt budget bounds the run's wall-clock).
    """
    if current_count >= manifest_cap:
        return []
    pool = [c for c in dedup(cands, existing_sources) if hygiene_ok(c)]
    pool.sort(key=lambda c: c.name)
    chosen: list[Candidate] = []
    tries = 0
    for c in pool:
        reached_cap = current_count + len(chosen) >= manifest_cap
        if len(chosen) >= max_new or reached_cap or tries >= max_tries:
            break
        tries += 1
        if resolvable(c.source, analyze):
            chosen.append(c)
    return chosen


def load_existing_sources(path: Path) -> set[str]:
    """Set of non-empty source strings already in the manifest (utf-8-sig: tolerate a BOM)."""
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return {
            (r.get("source") or "").strip()
            for r in csv.DictReader(fh)
            if (r.get("source") or "").strip()
        }


def count_rows(path: Path) -> int:
    """Number of data rows (non-empty source) currently in the manifest."""
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return sum(1 for r in csv.DictReader(fh) if (r.get("source") or "").strip())


def append_rows(path: Path, rows: list[Candidate]) -> None:
    """Append rows to the manifest CSV (append-only: header and existing rows untouched)."""
    if not rows:
        return
    with open(path, "a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        for c in rows:
            w.writerow([c.source, c.ecosystem, c.type, c.name])


def fetch_registry(
    base_url: str = REGISTRY_URL, *, max_pages: int = 20, timeout: float = 15.0
) -> list[dict]:
    """Page through the registry, returning raw list items. Stdlib urllib; bounded by max_pages."""
    items: list[dict] = []
    cursor: str | None = None
    for _ in range(max_pages):
        url = base_url + (f"?limit=100&cursor={cursor}" if cursor else "?limit=100")
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - constant https URL
            data = json.loads(resp.read().decode("utf-8"))
        items.extend(data.get("servers") or [])
        cursor = (data.get("metadata") or {}).get("nextCursor")
        if not cursor:
            break
    return items


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Grow the corpus manifest from the official MCP registry."
    )
    ap.add_argument("--manifest", default=MANIFEST_DEFAULT)
    ap.add_argument("--max-new", type=int, default=5)
    ap.add_argument("--max-tries", type=int, default=50)
    ap.add_argument("--manifest-cap", type=int, default=200)
    ap.add_argument("--max-pages", type=int, default=20)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    manifest = Path(args.manifest)
    try:
        existing = load_existing_sources(manifest)
        current = count_rows(manifest)
    except OSError as exc:
        print(f"cannot read manifest {manifest}: {exc!r}; added 0", flush=True)
        return 0

    try:
        items = fetch_registry(max_pages=args.max_pages)
    except (URLError, OSError, ValueError) as exc:
        print(f"registry fetch failed ({exc!r}); added 0", flush=True)
        return 0

    cands = [c for c in (normalize_entry(it) for it in items) if c is not None]
    chosen = select_new(
        cands,
        existing,
        current_count=current,
        max_new=args.max_new,
        max_tries=args.max_tries,
        manifest_cap=args.manifest_cap,
    )
    print(
        f"registry items={len(items)} candidates={len(cands)} chosen={len(chosen)} "
        f"manifest_rows={current} cap={args.manifest_cap}",
        flush=True,
    )
    for c in chosen:
        print(f"  + {c.source} ({c.ecosystem}/{c.type}) {c.name}", flush=True)
    if args.dry_run:
        print("[dry-run] no manifest write", flush=True)
        return 0
    append_rows(manifest, chosen)
    print(f"appended {len(chosen)} row(s) to {manifest}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
