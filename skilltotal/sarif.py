"""SARIF 2.1.0 rendering for GitHub Code Scanning / IDE integration.

Each evidence occurrence becomes one SARIF result so it maps to a specific line; the tool
driver advertises the full rule registry. Severity maps to SARIF ``level`` plus a numeric
``security-severity`` property understood by GitHub.
"""

from __future__ import annotations

import json

from skilltotal import __version__
from skilltotal.models import Report, Severity
from skilltotal.rules import get_rules

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://example.com/skilltotal"

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
                "results": _results(report),
                "properties": {
                    "risk_score": report.risk_score,
                    "risk_level": report.risk_level.value,
                    "component": report.component.to_dict(),
                },
            }
        ],
    }


def _rule_descriptors() -> list[dict]:
    descriptors = []
    for rule in get_rules():
        descriptors.append(
            {
                "id": rule.id,
                "name": rule.title,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "helpUri": INFO_URI,
                "defaultConfiguration": {"level": _LEVEL[rule.severity]},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[rule.severity],
                    "category": rule.category,
                    "tags": [rule.category],
                },
            }
        )
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
