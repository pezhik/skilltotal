"""Risk scoring engine.

Score = sum of severity weights of the findings that represent *risk* — i.e. malicious
indicators and risky constructs — capped at 100. Neutral CAPABILITY findings (can read the
filesystem / reach the network / run a shell) are shown but do NOT add to the score:
capability is not risk, so a legitimate-but-powerful component is not pushed into the red by
what it can do. The numeric score maps to a :class:`~skilltotal.models.RiskLevel` band.

Sensitive-data access (a credential-location reference or an embedded secret) combined with
network egress synthesizes a critical risky-construct finding — the genuine credential-
exfiltration pattern. Plain filesystem + network is intentionally NOT flagged: reading ordinary
files and using the network is a neutral capability, so a legitimate-but-powerful tool is not
painted as an exfiltration path.
"""

from __future__ import annotations

import re

from skilltotal.models import (
    Capability,
    Component,
    Evidence,
    Finding,
    RiskLevel,
    Severity,
    ThreatClass,
)

SCORE_CAP = 100

# Cloud instance-metadata endpoints. Reaching one IS itself a network call (a token is fetched
# over HTTP), not a local credential-file read — and it is the legitimate managed-identity auth
# path used by Azure/AWS/GCP SDKs. So a metadata-endpoint reference must NOT be counted as the
# "read a secret from disk" side of the exfiltration combo (that double-counts one fetch and
# mislabels normal cloud auth as a credential-exfiltration path). It still fires as its own
# sensitive-path finding (an SSRF / token-theft surface worth reviewing).
_CLOUD_METADATA_RE = re.compile(
    r"169\.254\.169\.254|metadata\.google\.internal|metadata\.google\b", re.IGNORECASE
)

# Only these threat classes contribute to the risk score; CAPABILITY is informational.
_SCORED_CLASSES = frozenset({ThreatClass.MALICIOUS_INDICATOR, ThreatClass.RISKY_CONSTRUCT})

COMBO_FINDING_ID = "ST-COMBO-EXFIL"
TRIFECTA_FINDING_ID = "ST-FLOW-TRIFECTA"
CONVERGENCE_FINDING_ID = "ST-CONVERGENCE"
INSTALL_DROPPER_FINDING_ID = "ST-INSTALL-DROPPER"
_INSTALL_HOOK_IDS = frozenset({"ST-INSTALL-NPM", "ST-INSTALL-NPM-PREPARE", "ST-INSTALL-PY"})
# Payloads that turn an install-time hook into a dropper: decode-and-execute, or credential access.
_DROPPER_PAYLOAD_IDS = frozenset(
    {
        "ST-OBF-DECODE-EXEC", "ST-OBF-DECODE-EXEC-PY", "ST-OBF-DECODE-EXEC-SH",
        "ST-SENS-PATH", "ST-SENS-PATH-PY",
    }
)
# Findings that represent access to sensitive data (credential locations / embedded secrets).
# Plain filesystem access is deliberately NOT here — reading ordinary files is a capability,
# not a risk, so a normal "reads files + uses network" tool is not flagged as exfiltration.
_SENSITIVE_DATA_IDS = frozenset({"ST-SENS-PATH", "ST-SENS-PATH-PY", "ST-SECRET-EMBEDDED"})
# A confirmed untrusted-instruction surface (the "untrusted content" axis of the trifecta).
_UNTRUSTED_CONTENT_IDS = frozenset({"ST-PROMPT-INJECTION"})

# Credential-location DOMAINS: which provider a sensitive-path reference belongs to. A package
# whose own identity IS that provider reads that provider's credentials as its documented function
# (botocore reads ~/.aws), so that specific access is not, by itself, an exfiltration signal. This
# is matched against the evidence snippet (the sensitive_paths scanner's own path alternation).
_CREDENTIAL_DOMAINS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)~/\.aws|\.aws/credentials"), "aws"),
    (re.compile(r"(?i)\.docker/config\.json"), "docker"),
    (re.compile(r"(?i)~/\.config/gcloud|application_default_credentials\.json"), "gcp"),
    (re.compile(r"(?i)~/\.azure"), "azure"),
    (re.compile(r"(?i)~/\.kube"), "kube"),
    (re.compile(r"(?i)\.git-credentials"), "git"),
    (re.compile(r"(?i)~/\.ssh|\bid_rsa\b"), "ssh"),
)

# Known official SDK / client packages mapped to the credential domain(s) they exist to use.
# A CURATED allowlist keyed on the EXACT package name (never a substring — "python-aws-post"
# contains "aws" but is NOT the AWS SDK, so it must still fire). Reading its OWN provider's
# credentials is the package's documented purpose; off-domain access (an AWS SDK reading ~/.ssh)
# and embedded secrets are unaffected and still synthesize the exfil combo.
_SDK_PROVIDER_DOMAINS: dict[str, frozenset[str]] = {
    "botocore": frozenset({"aws"}), "boto3": frozenset({"aws"}), "boto": frozenset({"aws"}),
    # awscli's `eks update-kubeconfig` writes ~/.kube/config.
    "awscli": frozenset({"aws", "kube"}), "aiobotocore": frozenset({"aws"}),
    "aioboto3": frozenset({"aws"}), "s3transfer": frozenset({"aws"}),
    # docker's SSH transport (docker-over-ssh) reads ~/.ssh/config.
    "docker": frozenset({"docker", "ssh"}),
    "gcsfs": frozenset({"gcp"}), "google-cloud-storage": frozenset({"gcp"}),
    "google-auth": frozenset({"gcp"}), "google-cloud-core": frozenset({"gcp"}),
    "snowflake-connector-python": frozenset({"snowflake"}),
    "kubernetes": frozenset({"kube"}), "kubernetes-asyncio": frozenset({"kube"}),
    "paramiko": frozenset({"ssh"}), "asyncssh": frozenset({"ssh"}), "fabric": frozenset({"ssh"}),
    # git implementations legitimately read ~/.git-credentials AND ~/.ssh/config (git-over-ssh).
    "dulwich": frozenset({"git", "ssh"}), "gitpython": frozenset({"git", "ssh"}),
    "pygit2": frozenset({"git", "ssh"}),
    # Data / IO libraries with a first-class cloud-filesystem layer legitimately read cloud creds
    # (pyarrow.fs S3/GCS filesystems; s3fs/adlfs are the fsspec cloud backends).
    "pyarrow": frozenset({"aws", "gcp"}), "s3fs": frozenset({"aws"}),
    "adlfs": frozenset({"azure"}), "fsspec": frozenset({"aws", "gcp", "azure"}),
}
_AZURE_SDK_PREFIX = "azure-"  # the azure-* SDK family (azure-identity, azure-storage-blob, …)


def _credential_domain(snippet: str) -> str | None:
    """The provider domain a sensitive-path evidence snippet refers to, or None."""
    for pat, dom in _CREDENTIAL_DOMAINS:
        if pat.search(snippet):
            return dom
    return None


def _package_base_name(component: Component) -> str:
    """The base package name, without a version suffix. A PyPI sdist's ``Component.name`` is the
    ``package-version`` dir (``botocore-1.43.42``), so match on the clean source spec
    (``pypi:botocore``) when present, else strip a trailing ``-<version>`` from the name."""
    src = (component.source or "").strip().lower()
    for prefix in ("pypi:", "npm:"):
        if src.startswith(prefix):
            return re.split(r"[@=]", src[len(prefix):], maxsplit=1)[0].strip()
    name = (component.name or "").strip().lower()
    return re.sub(r"-\d+(?:\.\d+)*.*$", "", name)


def _package_provider_domains(component: Component | None) -> frozenset[str]:
    """Credential domains this package legitimately accesses as its own documented function."""
    if component is None:
        return frozenset()
    name = _package_base_name(component)
    if name in _SDK_PROVIDER_DOMAINS:
        return _SDK_PROVIDER_DOMAINS[name]
    if name.startswith(_AZURE_SDK_PREFIX):
        return frozenset({"azure"})
    return frozenset()


def _dedupe(evidence: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, int, int]] = set()
    out: list[Evidence] = []
    for e in evidence:
        key = (e.file, e.line_start, e.line_end)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def compute_score(findings: list[Finding]) -> int:
    """Sum severity weights of risk-bearing findings (malicious + risky), capped at SCORE_CAP.

    CAPABILITY findings are informational and contribute 0 — capability is not risk.
    """
    total = sum(f.severity.weight for f in findings if f.threat_class in _SCORED_CLASSES)
    return min(total, SCORE_CAP)


def risk_level(score: int) -> RiskLevel:
    return RiskLevel.from_score(score)


def exfiltration_finding(
    findings: list[Finding],
    capabilities: dict[Capability, list[Evidence]],
    component: Component | None = None,
) -> Finding | None:
    """Synthesize a critical risky-construct finding for a credential-exfiltration path.

    Fires only when the component BOTH accesses sensitive data (a credential-location reference
    or an embedded secret — see ``_SENSITIVE_DATA_IDS``) AND can reach the network. This is the
    genuinely risky combination (read a secret, send it off-host); plain filesystem + network is
    a neutral capability and is intentionally not flagged here. Evidence is drawn from the
    contributing findings/capabilities so the "no finding without evidence" invariant holds.

    A provider SDK reading its OWN provider's credentials (``botocore`` -> ``~/.aws``) is that
    package's documented function, not exfiltration, so a sensitive-path evidence whose domain
    matches the package's provider (``component`` identity, see ``_SDK_PROVIDER_DOMAINS``) is
    excluded. Off-domain access (an AWS SDK reading ``~/.ssh``), a non-SDK package reading any
    credential path, and embedded secrets (``ST-SECRET-EMBEDDED`` has no path domain) all keep
    firing, so recall for a genuine credential-stealer is preserved.
    """
    provider_domains = _package_provider_domains(component)
    sens_evidence: list[Evidence] = [
        e
        for f in findings
        if f.id in _SENSITIVE_DATA_IDS
        for e in f.evidence
        if not _CLOUD_METADATA_RE.search(e.snippet)  # metadata fetch is network, not a secret read
        and not (
            provider_domains
            and f.id in ("ST-SENS-PATH", "ST-SENS-PATH-PY")
            and _credential_domain(e.snippet) in provider_domains
        )
    ]
    net_evidence = capabilities.get(Capability.NETWORK_EGRESS, [])

    if not sens_evidence or not net_evidence:
        return None

    evidence = _dedupe(sens_evidence)[:3] + _dedupe(net_evidence)[:3]
    return Finding(
        id=COMBO_FINDING_ID,
        severity=Severity.CRITICAL,
        category="exfiltration_path",
        title="Sensitive-data access combined with network egress",
        description=(
            "The component references credential/secret locations and can also send data over "
            "the network. Together these form a credential-exfiltration path."
        ),
        evidence=evidence,
        recommendation=(
            "Verify that secrets read from disk are never transmitted off-host without "
            "explicit, auditable user consent."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )


def trifecta_finding(
    findings: list[Finding],
    capabilities: dict[Capability, list[Evidence]],
    *,
    combo_fired: bool,
) -> Finding | None:
    """Synthesize the "lethal trifecta" exfiltration flow for an AI component.

    Fires when ALL THREE coincide: an untrusted-instruction surface (a confirmed
    prompt-injection finding), the ability to read files, and network egress — i.e. the
    component is exposed to instructions an attacker controls AND has the file-access + egress
    means to act on them. This is the combination that turns an injected instruction into data
    exfiltration.

    Gated to stay false-positive-free and low-noise: it requires an *actual* prompt-injection
    finding (not mere capability), and it is suppressed when the credential-specific
    ``ST-COMBO-EXFIL`` already fired (that stronger finding covers the same exfil concern).
    """
    if combo_fired:
        return None
    injection = [e for f in findings if f.id in _UNTRUSTED_CONTENT_IDS for e in f.evidence]
    fs_read = capabilities.get(Capability.FILESYSTEM_READ, [])
    net = capabilities.get(Capability.NETWORK_EGRESS, [])
    if not injection or not fs_read or not net:
        return None

    evidence = _dedupe(injection)[:2] + _dedupe(fs_read)[:2] + _dedupe(net)[:2]
    return Finding(
        id=TRIFECTA_FINDING_ID,
        severity=Severity.HIGH,
        category="exfiltration_path",
        title="Untrusted-instruction surface with file access and network egress",
        description=(
            "The component is exposed to untrusted instructions (a prompt-injection surface) and "
            "also can read files and send data over the network. Together these are the 'lethal "
            "trifecta' an attacker needs to turn an injected instruction into data exfiltration."
        ),
        evidence=evidence,
        recommendation=(
            "Remove the injectable instruction surface, or constrain the component so untrusted "
            "input cannot drive file reads and outbound network requests."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )


def install_dropper_finding(findings: list[Finding]) -> Finding | None:
    """Synthesize the install-time dropper pattern: an install/build hook paired with a payload.

    Fires when the component runs code at install time (`ST-INSTALL-*`) AND contains a
    decode-and-execute payload or accesses credential locations — the exact shape behind recent
    npm/PyPI supply-chain compromises (a postinstall hook that drops/runs an obfuscated second
    stage or steals secrets). FP-safe: the install hook alone is a neutral capability; this only
    fires when it co-occurs with an already-suspicious payload.
    """
    hooks = [f for f in findings if f.id in _INSTALL_HOOK_IDS]
    payloads = [f for f in findings if f.id in _DROPPER_PAYLOAD_IDS]
    if not hooks or not payloads:
        return None
    evidence = (
        _dedupe([e for f in hooks for e in f.evidence])[:2]
        + _dedupe([e for f in payloads for e in f.evidence])[:3]
    )
    return Finding(
        id=INSTALL_DROPPER_FINDING_ID,
        severity=Severity.HIGH,
        category="install_time_execution",
        title="Install-time hook paired with a dropper payload",
        description=(
            "The component executes code at install time (a package lifecycle / build hook) and "
            "also contains a decode-and-execute payload or accesses credential locations. This is "
            "the install-time dropper pattern behind recent supply-chain compromises."
        ),
        evidence=evidence,
        recommendation=(
            "Inspect the install/build hook and the payload it runs; do not install until the "
            "install-time behavior is understood and trusted."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )


def convergence_finding(findings: list[Finding]) -> Finding | None:
    """Synthesize an elevation finding when multiple distinct malicious indicators co-occur.

    Real malicious components stack deception and payload (e.g. an obfuscated dropper *and* a
    prompt injection); the convergence of two or more distinct malicious-indicator rules in one
    component sharply raises confidence that it is malicious. False-positive-free by construction:
    a benign component has zero malicious indicators, so this can never fire on one.

    Must run after ``_assign_threat_classes`` so each finding's ``threat_class`` is final.
    """
    malicious = [f for f in findings if f.threat_class is ThreatClass.MALICIOUS_INDICATOR]
    distinct_ids = {f.id for f in malicious}
    if len(distinct_ids) < 2:
        return None
    evidence = _dedupe([f.evidence[0] for f in malicious if f.evidence])[:6]
    titles = sorted({f.title for f in malicious})
    return Finding(
        id=CONVERGENCE_FINDING_ID,
        severity=Severity.HIGH,
        category="malware_convergence",
        title="Multiple malicious indicators in one component",
        description=(
            f"{len(distinct_ids)} distinct malicious indicators co-occur in this component "
            f"({', '.join(titles[:4])}). Real malware stacks deception with a payload, so their "
            "convergence sharply raises confidence the component is malicious."
        ),
        evidence=evidence,
        recommendation=(
            "Treat the component as malicious: do not install it, and review each indicator above."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )
