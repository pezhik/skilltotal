"""AI-BOM export: the installed-component inventory as a CycloneDX 1.6 document.

An SBOM answers "what is deployed?" for classic software; this is the same answer for an
agent stack — every MCP server and skill the machine's agent hosts reference, with
SkillTotal's scan verdict attached as component properties. The output is standard
CycloneDX JSON, so it feeds any SBOM tooling (dependency-track, compliance pipelines)
without a custom format.

Pure library: builds a dict from inventory items (the shape produced by the CLI's
inventory command); serialization and I/O stay in the CLI.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from skilltotal import __version__
from skilltotal.collector import npm_package_spec, pypi_package_spec

_PROPERTY_KEYS = (
    ("host", "skilltotal:host"),
    ("kind", "skilltotal:kind"),
    ("source", "skilltotal:source"),
    ("config", "skilltotal:config"),
    ("risk_level", "skilltotal:risk_level"),
    ("risk_score", "skilltotal:risk_score"),
    ("verdict", "skilltotal:verdict"),
    ("has_malicious_indicators", "skilltotal:has_malicious_indicators"),
    ("error", "skilltotal:scan_error"),
)


def build_aibom(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a CycloneDX 1.6 BOM dict from inventory items."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {"type": "application", "name": "skilltotal", "version": __version__}
                ]
            },
        },
        "components": [_component(item) for item in items],
    }


def _component(item: dict[str, Any]) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "application",
        "name": str(item.get("name", "")),
    }
    purl = purl_from_source(item.get("source"))
    if purl:
        component["purl"] = purl
        version = purl.rsplit("@", 1)[1] if "@" in purl.split("/", 1)[1] else None
        if version:
            component["version"] = version
    properties = []
    for key, prop_name in _PROPERTY_KEYS:
        value = item.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        properties.append({"name": prop_name, "value": str(value)})
    if properties:
        component["properties"] = properties
    return component


def purl_from_source(source: str | None) -> str | None:
    """Derive a package URL from an ``npm:``/``pypi:`` source spec; None otherwise."""
    if not source:
        return None
    normalized = source.strip().lower()
    if normalized.startswith("npm:"):
        name, version = npm_package_spec(source)
        if not name:
            return None
        # purl encodes the npm scope marker: pkg:npm/%40scope/name@version
        name = name.replace("@", "%40", 1) if name.startswith("@") else name
        return f"pkg:npm/{name}@{version}" if version else f"pkg:npm/{name}"
    if normalized.startswith("pypi:"):
        name, version = pypi_package_spec(source)
        if not name:
            return None
        return f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}"
    return None
