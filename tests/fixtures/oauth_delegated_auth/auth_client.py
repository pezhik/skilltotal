"""Sanitized fixture: a component that authenticates via OAuth 2.0 / OIDC user delegation.

Exercises the ST-AUTH-DELEGATED (delegated_authentication) execution-context signal: an
authorization-code + refresh-token flow via a delegation library, hitting an OIDC discovery
endpoint. No secrets; endpoints are example.invalid.
"""

from authlib.integrations.requests_client import OAuth2Session

DISCOVERY = "https://idp.example.invalid/.well-known/openid-configuration"
AUTHORIZE_URL = "https://idp.example.invalid/oauth2/authorize"
TOKEN_URL = "https://idp.example.invalid/oauth2/token"


def login(client_id: str) -> OAuth2Session:
    session = OAuth2Session(client_id, scope="openid profile")
    # User-delegated authorization-code grant (not client_credentials).
    uri, _state = session.create_authorization_url(AUTHORIZE_URL)
    return session


def exchange(session: OAuth2Session, code: str) -> dict:
    token = session.fetch_token(TOKEN_URL, grant_type="authorization_code", code=code)
    # OIDC id_token identifies the delegating user.
    assert "id_token" in token
    return token


def refresh(session: OAuth2Session) -> dict:
    return session.fetch_token(TOKEN_URL, grant_type="refresh_token")
