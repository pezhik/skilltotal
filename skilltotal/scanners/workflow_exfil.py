"""A GitHub Actions *workflow* that harvests provider keys and ships them off GitHub.

The GhostAction wave (CSA, Oct 2026) pushed a workflow under ``.github/workflows/`` whose name
looks like routine security tooling (``security-audit`` / ``security-check`` style) to hundreds of
compromised repositories. It checks the repo out at full depth (``fetch-depth: 0``), walks the
whole git history for a dozen credential regexes led by AI-provider key prefixes (Anthropic,
OpenAI-project, OpenRouter) plus AWS / GitHub / Google / Slack, maps the Actions secrets into its
environment, and posts the results to a hard-coded bare IP over plain HTTP.

Unlike a composite action (``action.yml``, handled by ``shell_script``), a workflow runs on the
*scanned* repository's own CI with that repository's secrets, so a scan of the repo should flag
it. The engine otherwise demotes ``.github/workflows/`` evidence as the project's own CI config;
this rule is listed in ``engine._CI_SCORED_RULES`` so this one malicious co-occurrence still
scores. The precise, low-false-positive signal is the harvest PLUS the off-GitHub exfiltration:
an honest secret-scanning workflow greps history for leaked keys but never posts the results to a
host the maintainer does not control. Both halves must be present.

Detection is regex over the workflow source and its decoded ``run:`` steps; nothing is executed.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)
from skilltotal.scanners.shell_script import (
    _NET_CLIENT,
    _action_commands,
    _command_segments,
    _to_github,
)

R_WORKFLOW_HISTORY_EXFIL = "ST-WORKFLOW-HISTORY-EXFIL"

# Credential-key prefixes a harvest greps for. Grouped so distinct providers can be counted: a
# single prefix is ordinary (a repo's own secret-scan allow-list), several together is a sweep.
_KEY_PREFIXES: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-ant-"),                       # Anthropic
    re.compile(r"sk-proj-|sk-[A-Za-z0-9]{20}"),   # OpenAI (project / legacy)
    re.compile(r"sk-or-v1-"),                      # OpenRouter
    re.compile(r"\bAKIA[0-9A-Z]"),                 # AWS
    re.compile(r"ghp_|gho_|ghs_|github_pat_"),     # GitHub
    re.compile(r"glpat-"),                          # GitLab
    re.compile(r"AIza[0-9A-Za-z_\-]"),             # Google / Firebase
    re.compile(r"xox[baprs]-"),                     # Slack
    re.compile(r"SG\.[A-Za-z0-9_\-]{10,}"),        # SendGrid
)
_WORKFLOW_RE = re.compile(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", re.IGNORECASE)


def _is_workflow(f: IndexedFile) -> bool:
    return bool(_WORKFLOW_RE.search(f.relpath.replace("\\", "/")))


def _distinct_prefixes(text: str) -> int:
    return sum(1 for pat in _KEY_PREFIXES if pat.search(text))


class WorkflowExfilScanner(Scanner):
    name = "workflow_exfil"
    rules = [
        RuleSpec(
            id=R_WORKFLOW_HISTORY_EXFIL,
            category="exfiltration_path",
            severity=Severity.HIGH,
            title="GitHub Actions workflow harvests credentials and sends them off GitHub",
            description=(
                "A workflow under .github/workflows/ scans for several provider credential "
                "prefixes (Anthropic/OpenAI/OpenRouter API keys, AWS/GitHub/Google/Slack tokens) "
                "and a run step sends data to a host that is not GitHub (a hard-coded IP or an "
                "external domain) through a network client. Run on the repository's own CI with "
                "its secrets and full git history, this exfiltrates every credential it can find. "
                "A legitimate secret-scanning workflow greps for leaked keys but never posts the "
                "results off GitHub (GhostAction, 2026)."
            ),
            recommendation=(
                "Remove this workflow and treat every secret in the repository and its history as "
                "compromised - rotate them. Never send scan results or secrets to a host outside "
                "GitHub from a workflow."
            ),
            capability=None,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        for f in index.files:
            if not _is_workflow(f):
                continue
            if _distinct_prefixes(f.text) < 2:
                continue
            exfil = self._offsite_exfil(f)
            if exfil is None:
                continue
            # Anchor to a key-prefix match and to the off-GitHub network client.
            for pat in _KEY_PREFIXES:
                m = pat.search(f.text)
                if m:
                    evidence.append(f.evidence_for_span(m.start(), m.end()))
                    break
            evidence.append(exfil)
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
        if evidence:
            return ScanResult(findings=[_finding_from_rule(self.rules[0], evidence)])
        return ScanResult()

    @staticmethod
    def _offsite_exfil(f: IndexedFile) -> Evidence | None:
        """A run-step command segment that invokes a network client to a non-GitHub destination."""
        for command, idx in _action_commands(f.text):
            for start, end in _command_segments(command):
                piece = command[start:end]
                client = _NET_CLIENT.search(piece)
                if client is None or _to_github(piece):
                    continue
                s = start + client.start()
                e = start + client.end()
                return f.evidence_for_span(idx[s], idx[e - 1] + 1)
        return None
