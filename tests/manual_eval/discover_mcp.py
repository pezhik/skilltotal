"""Read the official MCP registry: page it, and normalize an entry into a scannable source.

Deterministic, stdlib-only (urllib/json), no LLM, nothing executed. This is the population layer
under `survey_registry.py`, which scans every component the registry lists; it decides only what a
registry entry points at and whether that shape is safe to put in a public artifact.

The fetch is network-bound; CI tests the pure normalize/hygiene logic offline.
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass

REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0/servers"

# Positive allowlist: accept only clean, expected source shapes — an npm/pypi coordinate or a
# github URL. The official MCP registry yields exactly these; anything else (local paths, odd
# characters, whitespace) is rejected before it can reach a published artifact. An allowlist avoids
# enumerating any private/denylisted token in this public file; the authoritative public-hygiene
# check runs before a release is published.
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
    """Stable short name from a reverse-DNS registry name: last path segment, lowercased."""
    tail = name.rsplit("/", 1)[-1].lower()
    return _SLUG_STRIP.sub("", tail)


def normalize_entry(item: dict) -> Candidate | None:
    """Map a registry list item ({"server": {...}, ...}) to a Candidate, or None to skip.

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
    candidate reaches a scan or a published artifact.

    ``..`` is rejected explicitly. The allowlist's character classes permit ``.`` and ``/`` (both
    legal in scoped npm names), so a traversal-shaped identifier such as ``npm:../../etc/passwd``
    satisfied the pattern. It was never exploitable — ``collector.npm_package_spec`` refuses
    traversal, so the scan itself rejects such a source — but this allowlist claims to stop it, and
    neither npm, PyPI nor GitHub permits ``..`` in a name, so nothing legitimate is lost by
    enforcing that here too.
    """
    return ".." not in cand.source and bool(_SAFE_SOURCE.match(cand.source))


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
