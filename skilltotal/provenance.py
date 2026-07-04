"""Opt-in provenance signals from registry metadata (npm / PyPI).

The engine's core invariant is component-only analysis: everything is derived from the
files inside the component. Registry metadata — publish dates, deprecation flags,
repository links — is *context about* the component, not component content: useful for an
install decision, but never evidence of behavior. Provenance therefore:

1. is opt-in (``skilltotal scan --provenance``), never part of a default scan;
2. runs at the CLI layer, so the engine itself stays component-only;
3. emits only :class:`~skilltotal.models.NeedsReview` entries, which never affect the
   score or the verdict.

Only registry sources (``npm:`` / ``pypi:``) have provenance; other sources yield nothing.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from skilltotal.collector import npm_package_spec, pypi_package_spec
from skilltotal.models import NeedsReview

RECENT_DAYS = 30
STALE_YEARS = 3

_CATEGORY = "provenance"
_HTTP_TIMEOUT = 20
_MAX_METADATA_BYTES = 20 * 1024 * 1024


class ProvenanceError(Exception):
    """Registry metadata could not be fetched (offline, unknown package, ...)."""


def collect_provenance(source: str, *, now: datetime | None = None) -> list[NeedsReview]:
    """Provenance signals for an ``npm:``/``pypi:`` source; [] for other source kinds."""
    now = now or datetime.now(timezone.utc)
    normalized = source.strip().lower()
    if normalized.startswith("npm:"):
        name, version = npm_package_spec(source)
        if not name:
            raise ProvenanceError(f"invalid npm package name in: {source}")
        meta = _fetch(f"https://registry.npmjs.org/{quote(name, safe='@')}")
        return signals_from_npm(meta, version, now=now)
    if normalized.startswith("pypi:"):
        name, version = pypi_package_spec(source)
        if not name:
            raise ProvenanceError(f"invalid PyPI package name in: {source}")
        meta = _fetch(f"https://pypi.org/pypi/{quote(name)}/json")
        return signals_from_pypi(meta, version, now=now)
    return []


def signals_from_npm(
    meta: dict, version: str | None, *, now: datetime
) -> list[NeedsReview]:
    signals: list[NeedsReview] = []
    dist_tags = meta.get("dist-tags") or {}
    latest = dist_tags.get("latest")
    version = version or latest
    versions = meta.get("versions") or {}
    manifest = versions.get(version) or {}
    times = meta.get("time") or {}

    deprecated = manifest.get("deprecated")
    if deprecated:
        signals.append(_signal(
            "Deprecated on npm",
            f"version {version} is marked deprecated: {deprecated}",
        ))

    published = _parse_time(times.get(version))
    if published and now - published < timedelta(days=RECENT_DAYS):
        signals.append(_signal(
            "Recently published",
            f"version {version} was published {(now - published).days} day(s) ago "
            f"(younger than {RECENT_DAYS} days); new releases have had little community "
            "scrutiny",
        ))

    latest_published = _parse_time(times.get(latest)) if latest else None
    if latest_published and now - latest_published > timedelta(days=365 * STALE_YEARS):
        signals.append(_signal(
            "No recent releases",
            f"the latest release ({latest}) is from "
            f"{latest_published.date().isoformat()}, more than {STALE_YEARS} years ago",
        ))

    if manifest and not manifest.get("repository"):
        signals.append(_signal(
            "No repository link",
            f"version {version} declares no repository in its manifest, so the published "
            "artifact cannot be compared against a source tree",
        ))
    return signals


def signals_from_pypi(
    meta: dict, version: str | None, *, now: datetime
) -> list[NeedsReview]:
    signals: list[NeedsReview] = []
    info = meta.get("info") or {}
    latest = info.get("version")
    version = version or latest
    releases = meta.get("releases") or {}
    files = releases.get(version) or []

    if info.get("yanked") or any(f.get("yanked") for f in files):
        reason = info.get("yanked_reason") or next(
            (f.get("yanked_reason") for f in files if f.get("yanked_reason")), ""
        )
        signals.append(_signal(
            "Yanked on PyPI",
            f"version {version} was yanked" + (f": {reason}" if reason else ""),
        ))

    published = _earliest_upload(files)
    if published and now - published < timedelta(days=RECENT_DAYS):
        signals.append(_signal(
            "Recently published",
            f"version {version} was published {(now - published).days} day(s) ago "
            f"(younger than {RECENT_DAYS} days); new releases have had little community "
            "scrutiny",
        ))

    latest_published = _earliest_upload(releases.get(latest) or []) if latest else None
    if latest_published and now - latest_published > timedelta(days=365 * STALE_YEARS):
        signals.append(_signal(
            "No recent releases",
            f"the latest release ({latest}) is from "
            f"{latest_published.date().isoformat()}, more than {STALE_YEARS} years ago",
        ))

    urls = info.get("project_urls") or {}
    linked = any(
        v for k, v in urls.items()
        if k.lower() in ("source", "repository", "homepage", "github", "code")
    ) or info.get("home_page")
    if info and not linked:
        signals.append(_signal(
            "No repository link",
            f"version {version} declares no source/repository URL, so the published "
            "artifact cannot be compared against a source tree",
        ))
    return signals


def _signal(title: str, reason: str) -> NeedsReview:
    return NeedsReview(category=_CATEGORY, title=title, reason=reason)


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _earliest_upload(files: list[dict]) -> datetime | None:
    stamps = [
        t for f in files if (t := _parse_time(f.get("upload_time_iso_8601"))) is not None
    ]
    return min(stamps) if stamps else None


def _fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "skilltotal-scanner"})
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # nosec B310 - https
            data = json.loads(resp.read(_MAX_METADATA_BYTES))
    except (OSError, ValueError) as exc:
        raise ProvenanceError(f"cannot fetch registry metadata from {url}: {exc}") from exc
    if not isinstance(data, dict):
        raise ProvenanceError(f"unexpected registry metadata shape from {url}")
    return data
