"""SARIF 2.1.0 rendering for GitHub Code Scanning / IDE integration.

Each evidence occurrence becomes one SARIF result so it maps to a specific line; the tool
driver advertises the full rule registry. Severity maps to SARIF ``level`` plus a numeric
``security-severity`` property understood by GitHub.

A location's ``uri`` is the evidence path relative to the scanned folder, percent-encoded as a
URI reference (a space, ``#``, ``%`` or a newline in a file name must not change what it points
at). ``uri_prefix`` puts the scanned folder in front of it, so a scan of ``app/`` uploaded from the
repository root points Code Scanning at ``app/x.py``, which exists, not at ``x.py``.
"""

from __future__ import annotations

import json
from urllib.parse import quote

from skilltotal import __version__
from skilltotal.models import Report, Severity, ThreatClass
from skilltotal.owasp import OWASP_TAXONOMY, owasp_for
from skilltotal.rules import get_rules

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://www.skilltotal.ai"

# Stable guid for the OWASP taxonomy ToolComponent so rule relationships can reference it
# (SARIF links relationships to a taxonomy by guid). Fixed literal — deterministic output.
_OWASP_GUID = "3a8c1e94-7b2d-4f6a-9c1e-0d5b2a7f4e10"
_OWASP_NAME = "OWASP Agentic Skills Top 10"
_OWASP_URI = "https://owasp.org/www-project-agentic-skills-top-10/"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

# GitHub security-severity is a 0.0-10.0 numeric scale.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "4.0",
    Severity.LOW: "2.0",
}


def _level(severity: Severity, threat_class: ThreatClass) -> str:
    """A capability (what a component can do, such as run a shell) is not a risk: it never moves
    the score or the gate, so it is a note, never an alert that a clean gate contradicts."""
    return "note" if threat_class == ThreatClass.CAPABILITY else _LEVEL[severity]


def render_sarif(report: Report, *, uri_prefix: str = "", category: str = "") -> str:
    """``uri_prefix``: the scanned folder relative to the repository root, put in front of every
    location. ``category``: the run's ``automationDetails.id`` category, which keeps the alerts of
    two scans uploaded from one job apart."""
    return json.dumps(_sarif_doc(report, uri_prefix, category), indent=2, ensure_ascii=False)


def artifact_uri(path: str, prefix: str = "") -> str:
    """``prefix/path`` as a relative URI reference: each segment percent-encoded (RFC 3986), with
    ``:`` encoded too, so a file named ``a:b.js`` cannot read as a URI scheme."""
    prefix = prefix.replace("\\", "/").strip("/")
    while prefix.startswith("./"):
        prefix = prefix[2:]
    if prefix == ".":
        prefix = ""
    joined = f"{prefix}/{path}" if prefix else path
    return quote(joined, safe="/!$&'()*+,;=@")


def _sarif_doc(report: Report, uri_prefix: str = "", category: str = "") -> dict:
    run: dict = {}
    if category:
        # GitHub reads the category as everything before the last '/'.
        run["automationDetails"] = {"id": category if category.endswith("/") else f"{category}/"}
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                **run,
                "tool": {
                    "driver": {
                        "name": "SkillTotal",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": _rule_descriptors(),
                    }
                },
                "taxonomies": _taxonomies(),
                "results": _results(report, uri_prefix),
                "properties": {
                    "risk_score": report.risk_score,
                    "risk_level": report.risk_level.value,
                    "component": report.component.to_dict(),
                },
            }
        ],
    }


def _taxonomies() -> list[dict]:
    """The OWASP Agentic Skills Top 10 as a SARIF taxonomy (all 10 categories as taxa)."""
    return [
        {
            "name": _OWASP_NAME,
            "guid": _OWASP_GUID,
            "version": "1.0",
            "organization": "OWASP",
            "informationUri": _OWASP_URI,
            "shortDescription": {"text": "OWASP Agentic Skills Top 10 (2026)"},
            "isComprehensive": True,
            "taxa": [
                {
                    "id": cat.id,
                    "name": cat.title,
                    "helpUri": cat.url,
                    "shortDescription": {"text": cat.title},
                }
                for cat in OWASP_TAXONOMY
            ],
        }
    ]


def _owasp_relationships(rule_id: str) -> list[dict]:
    """SARIF relationships linking a rule to its OWASP Agentic Skills Top 10 taxa."""
    return [
        {
            "target": {
                "id": cat_id,
                "toolComponent": {"name": _OWASP_NAME, "guid": _OWASP_GUID},
            },
            "kinds": ["relevant"],
        }
        for cat_id in owasp_for(rule_id)
    ]


def _rule_descriptors() -> list[dict]:
    descriptors = []
    for rule in get_rules():
        owasp_ids = owasp_for(rule.id)
        descriptor = {
            "id": rule.id,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "helpUri": INFO_URI,
            "defaultConfiguration": {"level": _level(rule.severity, rule.threat_class)},
            "properties": {
                "category": rule.category,
                "tags": [rule.category, *owasp_ids],
            },
        }
        if rule.threat_class == ThreatClass.CAPABILITY:
            # No security-severity: GitHub would rank it as a security alert by that number.
            descriptor["properties"]["tags"].append("capability")
        else:
            descriptor["properties"]["security-severity"] = _SECURITY_SEVERITY[rule.severity]
        relationships = _owasp_relationships(rule.id)
        if relationships:
            descriptor["relationships"] = relationships
        descriptors.append(descriptor)
    return descriptors


def _results(report: Report, uri_prefix: str = "") -> list[dict]:
    results = []
    for finding in report.findings:
        for ev in finding.evidence:
            results.append(
                {
                    "ruleId": finding.id,
                    "level": _level(finding.severity, finding.threat_class),
                    "message": {"text": f"{finding.title}: {finding.description}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": artifact_uri(ev.file, uri_prefix)},
                                "region": {
                                    "startLine": ev.line_start,
                                    "endLine": ev.line_end,
                                    "snippet": {"text": ev.snippet},
                                },
                            }
                        }
                    ],
                }
            )
    return results
