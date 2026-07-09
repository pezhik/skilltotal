"""Scoped / least-privilege identity detection.

Another *execution-context* signal (not a risk): the component authenticates its tool/API calls
with a **short-lived, scoped, assumed** identity — an STS assumed role, a cloud managed / workload
identity, an impersonated service account, a projected Kubernetes service-account token, or a
dynamic-secret broker — rather than a long-lived embedded credential. In the Cloud Security
Alliance trait model this is the "Least-Privilege Service Identity" execution context: the
smallest blast radius of the three (embedded static credential > user delegation > least-privilege
scoped identity), because the credential is narrowly scoped and expires.

Neutral ``capability`` finding (0-score); it populates the ``scoped_identity`` trait so a report
can show that a component uses least-privilege short-lived credentials, completing the
execution-context picture alongside ``embedded_credential`` (Agent Service Identity) and
``delegated_authentication`` (User Delegated Credentials).
"""

from __future__ import annotations

import re

from skilltotal.models import Capability, Severity
from skilltotal.scanners.base import PatternScanner, RuleSpec, alternation

CODE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

CATEGORY = "execution_context"


class ScopedIdentityScanner(PatternScanner):
    name = "scoped_identity"
    rules = [
        RuleSpec(
            id="ST-AUTH-SCOPED",
            category=CATEGORY,
            severity=Severity.LOW,
            title="Scoped / least-privilege identity",
            description=(
                "A short-lived, scoped, assumed identity was detected — an STS AssumeRole / "
                "session token, a cloud managed or workload identity, an impersonated service "
                "account, a projected Kubernetes service-account token, or a dynamic-secret "
                "broker. Tools authenticate with a narrowly-scoped credential that expires, "
                "rather than a long-lived embedded service credential."
            ),
            recommendation=(
                "A scoped, short-lived identity is the smallest-blast-radius execution context. "
                "Confirm the assumed role / requested scope grants only the permissions the tool "
                "needs, and that the token lifetime is minimal."
            ),
            capability=Capability.SCOPED_IDENTITY,
            suffixes=CODE_SUFFIXES,
            pattern=alternation(
                # AWS STS assumed / temporary credentials.
                r"\bAssumeRole(?:WithWebIdentity|WithSAML)?\b",
                r"\bassume_role(?:_with_web_identity)?\b",
                r"\bget_session_token\b|\bGetSessionToken\b",
                # GCP short-lived / impersonated credentials + workload identity federation.
                r"\bimpersonated_credentials\b",
                r"\bgenerateAccessToken\b|generateIdToken",
                r"\bworkload[_-]?identity\b",
                # Azure managed / workload identity (no static secret).
                r"\bDefaultAzureCredential\b|\bManagedIdentityCredential\b"
                r"|\bWorkloadIdentityCredential\b",
                # Kubernetes projected service-account token.
                r"kubernetes\.io/serviceaccount/token",
                # HashiCorp Vault client (dynamic / short-lived secrets).
                r"['\"]hvac['\"]|\bhvac\.Client\b|['\"]node-vault['\"]",
                flags=re.MULTILINE,
            ),
        ),
    ]
