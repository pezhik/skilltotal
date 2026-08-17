"""`server.json` is the registry listing — it must stay valid and in step with the release.

The MCP registry is where this ecosystem actually discovers servers, and a listing that points at
a version PyPI does not serve is worse than no listing. The version drift guard exists because the
same failure already happened once with the documented GitHub Action pin, which advertised a
28-releases-old version for months.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import skilltotal

ROOT = Path(__file__).resolve().parent.parent
SERVER_JSON = ROOT / "server.json"


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads(SERVER_JSON.read_text(encoding="utf-8"))


def test_declares_the_released_version(manifest):
    """Both the server version and the pypi package pin track __version__."""
    assert manifest["version"] == skilltotal.__version__
    pypi = [p for p in manifest["packages"] if p["registryType"] == "pypi"]
    assert pypi, "the listing must point at the published PyPI package"
    assert pypi[0]["identifier"] == "skilltotal"
    assert pypi[0]["version"] == skilltotal.__version__


def test_carries_the_fields_the_registry_requires(manifest):
    for field in ("name", "description", "version"):
        assert manifest.get(field), field
    # The registry caps this at 100 characters; a longer one is rejected at publish time.
    assert len(manifest["description"]) <= 100
    # Reverse-DNS with exactly one slash separating namespace from server name.
    assert manifest["name"].count("/") == 1
    namespace, _, server_name = manifest["name"].partition("/")
    assert "." in namespace and server_name

    package = manifest["packages"][0]
    for field in ("registryType", "identifier", "transport"):
        assert package.get(field), field
    assert package["transport"]["type"] == "stdio"


def test_runs_the_mcp_subcommand(manifest):
    """The console script is `skilltotal`, so the listing must pass `mcp`.

    Without it a client launches the plain CLI, which prints usage and breaks the handshake.
    """
    args = manifest["packages"][0].get("packageArguments") or []
    assert any(a.get("value") == "mcp" for a in args), (
        "without a positional 'mcp' argument the client would launch the plain CLI, which "
        "prints usage to stdout and breaks the JSON-RPC handshake"
    )


def test_readme_carries_the_ownership_marker(manifest):
    """PyPI ownership is proved by an `mcp-name:` marker in the package description.

    The registry reads the README as published on PyPI (pyproject uses it as the long
    description) and refuses the listing unless it names exactly this server, so the marker and
    server.json must never drift apart.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"mcp-name: {manifest['name']}" in readme


def test_matches_the_official_schema(manifest):
    """Validated against the schema the registry publishes, when it is reachable."""
    jsonschema = pytest.importorskip("jsonschema")
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(manifest["$schema"], timeout=15) as resp:  # nosec B310
            schema = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):  # offline / CI without network
        pytest.skip("schema not reachable")
    jsonschema.validate(manifest, schema)
