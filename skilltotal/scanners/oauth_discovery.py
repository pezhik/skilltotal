"""Shell injection smuggled through an OAuth / OIDC discovery document.

An MCP client (and other agent tooling) that speaks OAuth 2.0 fetches the server's discovery
document (``.well-known/oauth-authorization-server`` / ``oauth-protected-resource`` /
``openid-configuration``) and reads endpoint URLs from it. A client that then hands one of those
URLs to a shell - to ``open`` it in a browser, to ``curl`` it - without validation lets a hostile
server put a command where a URL belongs. OpenCode patched exactly this in 2026 (a critical
discovery-driven command injection). The server-controlled document is untrusted input: an
endpoint value that carries shell metacharacters (``$(...)``, backticks, ``&&``, a piped or
chained ``sh``/``curl``) is never a real URL - it is a command waiting for a vulnerable client.

This flags the *document* shape, which is component content we can anchor to a file and line. It
does not assert the consuming client is vulnerable; it names an endpoint value that no honest
authorization server would ever publish.
"""

from __future__ import annotations

import re

from skilltotal.models import Capability, Severity, ThreatClass
from skilltotal.scanners.base import PatternScanner, RuleSpec

R_OAUTH_ENDPOINT_INJECTION = "ST-MCP-OAUTH-ENDPOINT-INJECTION"

# Endpoint keys an OAuth 2.0 / OIDC discovery document publishes, whose values are URLs a client
# may dereference or open.
_ENDPOINT_KEY = (
    r"authorization|token|registration|revocation|userinfo|introspection|"
    r"device_authorization|end_session|pushed_authorization_request"
)
# Shell metacharacters that turn a URL value into a command. Deliberately narrow so a normal URL
# (query `&`, `?`, `;jsessionid`, or a `${OAUTH_HOST}` config interpolation) never matches:
# command substitution, chaining `&&`, or a pipe/semicolon directly in front of a known shell/
# fetch command.
_SHELL_META = (
    r"\$\(|`|&&|"
    r"\|\s*(?:sh|bash|zsh|curl|wget|nc|ncat|powershell|pwsh|cmd|python\d?|node|perl|ruby)\b|"
    r";\s*(?:sh|bash|zsh|curl|wget|nc|ncat|rm|powershell|pwsh|cmd|python\d?|node|perl|ruby)\b"
)


class OAuthDiscoveryInjectionScanner(PatternScanner):
    name = "oauth_discovery_injection"
    rules = [
        RuleSpec(
            id=R_OAUTH_ENDPOINT_INJECTION,
            category="command_injection",
            severity=Severity.HIGH,
            title="Shell injection in an OAuth/OIDC discovery endpoint",
            description=(
                "An OAuth 2.0 / OpenID Connect discovery document declares an endpoint whose URL "
                "value carries shell metacharacters (command substitution, chaining, or a piped/"
                "chained shell command). A client that opens or fetches the server-supplied "
                "endpoint through a shell would execute the embedded command - the "
                "discovery-driven command injection patched in MCP OAuth clients in 2026."
            ),
            recommendation=(
                "Treat discovery-document values as untrusted. An honest authorization server "
                "never publishes a shell command in an endpoint; reject this server and ensure "
                "the client validates endpoint URLs before dereferencing them."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            pattern=re.compile(
                rf'"(?:{_ENDPOINT_KEY})_endpoint"\s*:\s*"[^"\n]*?(?:{_SHELL_META})'
                rf'|"(?:jwks_uri|issuer)"\s*:\s*"[^"\n]*?(?:{_SHELL_META})',
                re.IGNORECASE,
            ),
        ),
    ]
