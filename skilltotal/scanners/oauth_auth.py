"""Delegated-authentication (OAuth 2.0 / OpenID Connect) detection.

This is an *execution-context* signal, not a risk: it records that a component authenticates
tool/API calls with the end user's **delegated, scoped** OAuth/OIDC credentials rather than a
long-lived embedded service credential. In the Cloud Security Alliance trait model this is the
"User Delegated Credentials" execution context — a smaller blast radius than the "Agent Service
Identity" (static embedded credential) captured by the embedded-credential trait. It is a neutral
``capability`` finding (0-score); it exists to populate the ``delegated_authentication`` trait so a
report can show *how* a component authenticates, not just that it holds a secret.

Only user-delegation signals are matched — ``authorization_code`` / ``refresh_token`` /
token-exchange grants, an OIDC authorize/discovery endpoint, an ``id_token``, or a delegation
library. The ``client_credentials`` grant is deliberately NOT matched: it is a static
service-to-service identity, not user delegation.
"""

from __future__ import annotations

import re

from skilltotal.models import Capability, Severity
from skilltotal.scanners.base import PatternScanner, RuleSpec, alternation

CODE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

CATEGORY = "execution_context"


class OAuthAuthScanner(PatternScanner):
    name = "oauth_auth"
    rules = [
        RuleSpec(
            id="ST-AUTH-DELEGATED",
            category=CATEGORY,
            severity=Severity.LOW,
            title="Delegated authentication (OAuth 2.0 / OIDC)",
            description=(
                "An OAuth 2.0 / OpenID Connect delegated-authentication flow was detected "
                "(authorization-code / refresh-token / token-exchange grant, an OIDC "
                "authorize/discovery endpoint or id_token, or a delegation library). Tools "
                "authenticate with the end user's delegated, scoped credentials rather than a "
                "long-lived embedded service credential."
            ),
            recommendation=(
                "Delegated auth is a lower-blast-radius execution context than an embedded static "
                "credential. Confirm the requested scopes are minimal and that tokens are never "
                "logged or forwarded off-host."
            ),
            capability=Capability.DELEGATED_AUTHENTICATION,
            suffixes=CODE_SUFFIXES,
            pattern=alternation(
                # User-delegation grant flows (client_credentials is excluded on purpose — that is
                # a static service identity, not delegation).
                r"grant_type\b['\"]?\s*[:=]\s*['\"]?(?:authorization_code|refresh_token)\b",
                r"urn:ietf:params:oauth:grant-type:token-exchange",
                # OAuth2 / OIDC user-facing endpoints and discovery.
                r"\boauth2?/authorize\b",
                r"\bauthorization_endpoint\b",
                r"\.well-known/openid-configuration\b",
                r"\bid_token\b",
                # Delegation libraries / SDKs (Python).
                r"\b(?:oauthlib|requests_oauthlib|authlib|msal|google_auth_oauthlib)\b",
                # Delegation libraries / SDKs (Node), matched as an import/require string.
                r"['\"](?:requests-oauthlib|simple-oauth2|openid-client|oauth4webapi|next-auth|"
                r"passport-oauth2|passport-google-oauth20)['\"]",
                flags=re.IGNORECASE | re.MULTILINE,
            ),
        ),
    ]
