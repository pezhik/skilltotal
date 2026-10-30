"""Update drift: risk an installed component gained when its version changed.

A trojanized update arrives the way every other update does (an editor's marketplace, a
launcher that runs the latest package), so no install command is there to check. What a
scheduled ``inventory --state FILE`` or ``guard --installed --state FILE`` can see is the change:
the state file keeps, per installed component, the version last seen and the fingerprints of its
risk findings (malicious indicators and risky constructs; capabilities are not risk). A component
whose version changed and that now has risk findings it did not have before has *drifted*.

The fingerprints are the baseline's (:func:`skilltotal.baseline.evidence_fingerprint`: rule id,
file and snippet, hashed), so the state file holds component names, versions and those hashes, and
nothing from the files themselves (secrets are exposures, never fingerprinted here). The first run
with a new state file only records.

Pure library: the CLI reads and writes the file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from skilltotal import bounded_json
from skilltotal.baseline import evidence_fingerprint

STATE_FORMAT = "skilltotal-inventory-state"
STATE_VERSION = 1
_RISK_CLASSES = ("malicious_indicator", "risky_construct")
_BLOCKING_SEVERITIES = ("high", "critical")


class StateError(ValueError):
    """The file is not a state file this version can read."""


@dataclass
class Drift:
    old_version: str
    new_version: str
    rule_ids: list[str]  # rules with risk evidence the previous version did not have
    blocking: bool       # among them a malicious indicator or a high/critical risky construct

    def to_dict(self) -> dict[str, Any]:
        return {"from": self.old_version, "to": self.new_version, "rules": self.rule_ids,
                "blocks": self.blocking}


def component_key(host: str, kind: str, name: str, version: str) -> str:
    """One component across its versions: host, kind and name, without the ``@version`` an
    editor extension's name ends with."""
    if version and name.endswith(f"@{version}"):
        name = name[: -len(version) - 1]
    return f"{host}|{kind}|{name}"


def component_version(report: dict[str, Any], fallback: str = "") -> str:
    """The version a component was installed at: its manifest's (``fallback``, read during
    discovery), else the one the scan derived."""
    return fallback or str((report.get("component") or {}).get("version") or "")


def _risk(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Fingerprint -> the risk findings it belongs to."""
    out: dict[str, list[dict[str, Any]]] = {}
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict) or finding.get("threat_class") not in _RISK_CLASSES:
            continue
        for ev in finding.get("evidence") or []:
            if isinstance(ev, dict):
                fp = evidence_fingerprint(str(finding.get("id", "")), str(ev.get("file", "")),
                                          str(ev.get("snippet", "")))
                out.setdefault(fp, []).append(finding)
    return out


def record(report: dict[str, Any], version: str) -> dict[str, Any]:
    """The state entry for one scanned component."""
    return {"version": version, "risk": sorted(_risk(report))}


def detect(previous: dict[str, Any] | None, report: dict[str, Any],
           version: str) -> Drift | None:
    """The drift of a component since ``previous`` (its state entry), or None: never on a first
    sight, nor when the version is unknown or unchanged."""
    if not previous or not version or previous.get("version") == version:
        return None
    old_version = str(previous.get("version") or "")
    if not old_version:
        return None
    known = set(previous.get("risk") or [])
    gained = [finding for fp, findings in _risk(report).items() if fp not in known
              for finding in findings]
    if not gained:
        return None
    rule_ids = list(dict.fromkeys(str(f.get("id", "")) for f in gained))
    blocking = any(f.get("threat_class") == "malicious_indicator"
                   or str(f.get("severity", "")) in _BLOCKING_SEVERITIES for f in gained)
    return Drift(old_version, version, rule_ids, blocking)


def load_state(text: str) -> dict[str, dict[str, Any]]:
    """The components of a state file's text; raises StateError for anything else, so a file
    that is not one is never overwritten."""
    try:
        data = bounded_json.loads(text)
    except ValueError as exc:
        raise StateError(f"not JSON ({exc})") from None
    if not isinstance(data, dict) or data.get("format") != STATE_FORMAT:
        raise StateError(f"not a SkillTotal state file (no \"format\": \"{STATE_FORMAT}\")")
    if data.get("version") != STATE_VERSION:
        raise StateError(f"state file version {data.get('version')!r} is not {STATE_VERSION}")
    components = data.get("components")
    if not isinstance(components, dict) or not all(
            isinstance(entry, dict) and isinstance(entry.get("risk", []), list)
            for entry in components.values()):
        raise StateError("its \"components\" are not a mapping of component entries")
    return components


def dump_state(components: dict[str, dict[str, Any]]) -> str:
    return json.dumps({"format": STATE_FORMAT, "version": STATE_VERSION,
                       "components": dict(sorted(components.items()))}, indent=2,
                      ensure_ascii=False) + "\n"
