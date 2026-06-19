"""SARIF 2.1.0 rendering for GitHub Code Scanning / IDE integration.

Each evidence occurrence becomes one SARIF result so it maps to a specific line; the tool
driver advertises the full rule registry. Severity maps to SARIF ``level`` plus a numeric
``security-severity`` property understood by GitHub.
"""

from __future__ import annotations

import json

from skilltotal import __version__
from skilltotal.models import Report, Severity
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


def render_sarif(report: Report) -> str:
    return json.dumps(_sarif_doc(report), indent=2, ensure_ascii=False)


def _sarif_doc(report: Report) -> dict:
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillTotal",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": _rule_descriptors(),
                    }
                },
                "taxonomies": _taxonomies(),
                "results": _results(report),
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
            "defaultConfiguration": {"level": _LEVEL[rule.severity]},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[rule.severity],
                "category": rule.category,
                "tags": [rule.category, *owasp_ids],
            },
        }
        relationships = _owasp_relationships(rule.id)
        if relationships:
            descriptor["relationships"] = relationships
        descriptors.append(descriptor)
    return descriptors


def _results(report: Report) -> list[dict]:
    results = []
    for finding in report.findings:
        for ev in finding.evidence:
            results.append(
                {
                    "ruleId": finding.id,
                    "level": _LEVEL[finding.severity],
                    "message": {"text": f"{finding.title}: {finding.description}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": ev.file},
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
