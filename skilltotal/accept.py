"""Reviewed false positives that `guard` and `inventory` accept (the ``--accept FILE``).

A scheduled ``guard --installed`` blocks every day on a finding a team has reviewed and found
harmless, and the only way out used to be turning the check off. An accept file records each such
review: one entry per component *at one exact version*, naming the fingerprints of the findings it
accepts (the baseline's: rule id, file and snippet, hashed) and why. Matching is narrow on purpose:
an update, or a new finding in the same version, is judged afresh, so a trojanized update of an
accepted component still blocks.

A component is named by :func:`skilltotal.drift.component_key` (``host|kind|name``) when it is
installed, and by :func:`source_key` for ``guard <source>``.

Pure library: the CLI reads and writes the file and prints the warnings.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from typing import Any

from skilltotal import bounded_json

ACCEPT_FORMAT = "skilltotal-accept"
ACCEPT_VERSION = 1
_FINGERPRINT = re.compile(r"[0-9a-f]{16}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_KEYS = {"component", "version", "findings", "rules", "reason", "accepted_by", "expires"}
_RISK_CLASSES = ("malicious_indicator", "risky_construct")


class AcceptError(ValueError):
    """The file is not an accept file this version can use."""


@dataclass(frozen=True)
class Acceptance:
    """One entry of an accept file."""

    number: int  # its position in the file, from 1, for messages
    component: str
    version: str
    findings: frozenset[str]
    reason: str
    rules: tuple[str, ...] = ()
    accepted_by: str = ""
    expires: date | None = None

    def label(self) -> str:
        return f"{self.component}@{self.version}" if self.version else self.component


@dataclass
class Applied:
    """What the accept file took out of one component's scan."""

    rules: list[str]
    count: int                    # evidence occurrences removed
    reason: str
    expires: str                  # the earliest expiry of the entries used, "" for none
    accepted_by: str
    malicious: list[str]          # accepted rules that are malicious indicators
    risk_fingerprints: set[str]   # accepted fingerprints of risk findings (for --state)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"rules": self.rules, "count": self.count, "reason": self.reason}
        if self.expires:
            out["expires"] = self.expires
        if self.accepted_by:
            out["accepted_by"] = self.accepted_by
        return out


def _entry(number: int, raw: object) -> Acceptance:
    where = f"entry {number}"
    if not isinstance(raw, dict):
        raise AcceptError(f"{where} is not an object")
    unknown = sorted(str(k) for k in raw if k not in _KEYS)
    if unknown:
        # A misspelt "expires" would make an acceptance permanent: refuse it.
        raise AcceptError(f"{where}: unknown key(s) {', '.join(unknown)}")
    component, version = raw.get("component"), raw.get("version")
    if not isinstance(component, str) or not component.strip():
        raise AcceptError(f"{where}: \"component\" must be a non-empty string")
    if not isinstance(version, str):
        raise AcceptError(f"{where}: \"version\" must be a string (\"\" for a component that "
                          "has no version)")
    findings = raw.get("findings")
    if not isinstance(findings, list) or not findings:
        raise AcceptError(f"{where}: \"findings\" must be a non-empty list of fingerprints")
    for fp in findings:
        if not isinstance(fp, str) or not _FINGERPRINT.fullmatch(fp):
            raise AcceptError(f"{where}: {json.dumps(fp)[:40]} is not a finding fingerprint "
                              "(16 lowercase hex characters)")
    rules = raw.get("rules", [])
    if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
        raise AcceptError(f"{where}: \"rules\" must be a list of rule ids")
    reason = raw.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise AcceptError(f"{where} ({component}): \"reason\" is empty; write why its findings "
                          "are safe")
    accepted_by = raw.get("accepted_by", "")
    if not isinstance(accepted_by, str):
        raise AcceptError(f"{where}: \"accepted_by\" must be a string")
    expires = raw.get("expires")
    day: date | None = None
    if expires is not None:
        if not isinstance(expires, str) or not _DATE.fullmatch(expires):
            raise AcceptError(f"{where}: \"expires\" must be a date written YYYY-MM-DD")
        try:
            day = date.fromisoformat(expires)
        except ValueError:
            raise AcceptError(f"{where}: \"expires\" {expires} is not a date") from None
    return Acceptance(number, component.strip(), version.strip(), frozenset(findings),
                      reason.strip(), tuple(rules), accepted_by.strip(), day)


def _document(text: str) -> list[Any]:
    """The ``accepted`` list of an accept file's text, its entries not yet checked."""
    try:
        data = bounded_json.loads(text)
    except ValueError as exc:
        raise AcceptError(f"not JSON ({exc})") from None
    if not isinstance(data, dict) or data.get("format") != ACCEPT_FORMAT:
        raise AcceptError(f"not a SkillTotal accept file (no \"format\": \"{ACCEPT_FORMAT}\")")
    if data.get("version") != ACCEPT_VERSION:
        raise AcceptError(f"accept file version {data.get('version')!r} is not {ACCEPT_VERSION}")
    accepted = data.get("accepted")
    if not isinstance(accepted, list):
        raise AcceptError("its \"accepted\" is not a list of entries")
    return accepted


def load_accept(text: str) -> list[Acceptance]:
    """The entries of an accept file's text; raises AcceptError for anything else, an entry
    without a reason included (that is the review step ``--write-accept`` leaves to a person)."""
    return [_entry(n, raw) for n, raw in enumerate(_document(text), start=1)]


class AcceptList:
    """The entries of one accept file, as they apply on ``today``."""

    def __init__(self, entries: list[Acceptance], today: date) -> None:
        self.expired = [e for e in entries if e.expires is not None and e.expires < today]
        self.active = [e for e in entries if e not in self.expired]
        self._used: set[int] = set()

    def candidates(self, key: str, version: str | None) -> set[str]:
        """The fingerprints the entries for ``key`` accept: at ``version``, or at any version
        when it is not known before the scan."""
        out: set[str] = set()
        for e in self.active:
            if e.component == key and (version is None or e.version == version):
                out |= e.findings
        return out

    def matching(self, key: str, version: str) -> list[Acceptance]:
        """The entries for ``key`` at exactly ``version``; they count as used."""
        found = [e for e in self.active if e.component == key and e.version == version]
        self._used.update(e.number for e in found)
        return found

    def stale(self, key: str | None = None) -> list[Acceptance]:
        """Entries that matched no scanned component at their version (only those for ``key``
        when given)."""
        return [e for e in self.active if e.number not in self._used
                and (key is None or e.component == key)]


def applied(entries: list[Acceptance], hits: dict[str, str],
            classes: dict[str, str]) -> Applied | None:
    """What ``entries`` took out of a scan: ``hits`` maps each removed fingerprint to its rule
    id, ``classes`` a rule id to its threat class. None when nothing was removed."""
    if not hits:
        return None
    rules = sorted(set(hits.values()))
    expiries = sorted(e.expires.isoformat() for e in entries if e.expires is not None)
    return Applied(
        rules=rules,
        count=len(hits),
        reason="; ".join(dict.fromkeys(e.reason for e in entries)),
        expires=expiries[0] if expiries else "",
        accepted_by=", ".join(dict.fromkeys(e.accepted_by for e in entries if e.accepted_by)),
        malicious=[r for r in rules if classes.get(r) == "malicious_indicator"],
        risk_fingerprints={fp for fp, rule in hits.items() if classes.get(rule) in _RISK_CLASSES},
    )


def source_key(source: str) -> str:
    """The component key of a ``guard <source>``: ``npm:<name>`` or ``pypi:<name>`` (normalized,
    without the version), else the source as written."""
    from skilltotal.collector import npm_package_spec, pypi_package_spec

    text = source.strip()
    if text.lower().startswith("npm:"):
        name, _ = npm_package_spec(text)
        if name:
            return f"npm:{name.lower()}"
    if text.lower().startswith("pypi:"):
        name, _ = pypi_package_spec(text)
        if name:
            return "pypi:" + re.sub(r"[-_.]+", "-", name).lower()
    return text


def risk_findings(report: dict[str, Any]) -> tuple[list[str], list[str]]:
    """(fingerprints, rule ids) of a serialized report's risk findings, sorted; the fingerprints
    are the ones ``--state`` records."""
    from skilltotal.drift import record

    rules = {str(f.get("id", "")) for f in report.get("findings") or []
             if isinstance(f, dict) and f.get("threat_class") in _RISK_CLASSES
             and f.get("evidence")}
    return record(report, "")["risk"], sorted(rules)


def draft_entry(component: str, version: str, findings: list[str],
                rules: list[str]) -> dict[str, Any]:
    """An entry for ``--write-accept``: its reason is left empty for a person to fill in."""
    return {"component": component, "version": version, "findings": findings, "rules": rules,
            "reason": ""}


def dump_with(existing: str | None, drafts: list[dict[str, Any]]) -> tuple[str, int]:
    """The text of an accept file holding the entries of ``existing`` (an accept file's text, or
    None) and the ``drafts`` it does not already cover, and how many drafts were added. Raises
    AcceptError when ``existing`` is not an accept file, so another file is never overwritten."""
    entries: list[Any] = _document(existing) if existing is not None else []
    added = 0
    for draft in drafts:
        covered = any(
            isinstance(e, dict) and e.get("component") == draft["component"]
            and e.get("version") == draft["version"] and isinstance(e.get("findings"), list)
            and set(draft["findings"]) <= set(e["findings"])
            for e in entries)
        if not covered:
            entries.append(draft)
            added += 1
    text = json.dumps({"format": ACCEPT_FORMAT, "version": ACCEPT_VERSION, "accepted": entries},
                      indent=2, ensure_ascii=False) + "\n"
    return text, added
