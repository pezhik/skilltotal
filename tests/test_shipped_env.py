"""A .env that escaped into a released package (ST-ENV-SHIPPED).

The mechanism is the one behind the MCP publisher's leaked tokens: the packer captured the
project root. `.env` is where a project keeps its environment secrets, so in a working tree it is
correct and gitignored, and only its presence in a *published artifact* is a finding.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal import engine
from skilltotal.collector import Component
from skilltotal.file_index import FileIndex
from skilltotal.scanners.sensitive_paths import SensitivePathScanner

SECRET = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0"
ENV_BODY = (
    f"DATABASE_URL=postgres://user:hunter2@db.internal/app\nOPENAI_API_KEY={SECRET}\nDEBUG=true\n"
)


def _write(tmp_path: Path, name: str, body: str) -> Path:
    (tmp_path / "package.json").write_text('{"name":"t","version":"1.0.0"}\n', encoding="utf-8")
    (tmp_path / name).write_text(body, encoding="utf-8", newline="\n")
    return tmp_path


def _scanner_ids(tmp_path: Path) -> set[str]:
    return {f.id for f in SensitivePathScanner().scan(FileIndex.build(tmp_path)).findings}


def _report(tmp_path: Path, component_type: str) -> dict:
    component = Component(name="t", type=component_type, version="1.0.0", source="local")
    return engine.analyze_directory(tmp_path, component).to_dict()


def test_env_in_a_published_package_is_a_finding(tmp_path):
    report = _report(_write(tmp_path, ".env", ENV_BODY), "npm_package")
    finding = next(f for f in report["findings"] if f["id"] == "ST-ENV-SHIPPED")
    assert finding["severity"] == "high"
    assert [e["file"] for e in finding["evidence"]] == [".env"]


def test_the_report_never_carries_the_values(tmp_path):
    """The values are the whole reason this is a finding, so the report must not republish them."""
    report = _report(_write(tmp_path, ".env", ENV_BODY), "npm_package")
    snippet = next(f for f in report["findings"] if f["id"] == "ST-ENV-SHIPPED")["evidence"][0][
        "snippet"
    ]
    assert SECRET not in snippet
    assert "hunter2" not in snippet
    # The names ARE reported: they tell a reader which credentials to go and rotate.
    assert "OPENAI_API_KEY" in snippet and "DATABASE_URL" in snippet


def test_a_local_env_is_not_scored_outside_a_published_package(tmp_path):
    """In a checkout this is how dotenv is meant to be used; scoring it would fire on everything."""
    report = _report(_write(tmp_path, ".env", ENV_BODY), "git_repository")
    assert not [f for f in report["findings"] if f["id"] == "ST-ENV-SHIPPED"]
    assert any("Local .env file" in n["title"] for n in report["needs_review"])


def test_example_env_is_documentation_not_a_leak(tmp_path):
    assert "ST-ENV-SHIPPED" not in _scanner_ids(_write(tmp_path, ".env.example", ENV_BODY))


def test_environment_specific_env_files_still_count(tmp_path):
    assert "ST-ENV-SHIPPED" in _scanner_ids(_write(tmp_path, ".env.production", ENV_BODY))


def test_an_empty_env_is_not_a_leak(tmp_path):
    assert "ST-ENV-SHIPPED" not in _scanner_ids(_write(tmp_path, ".env", "\n\n"))


def test_a_commented_out_env_is_not_a_leak(tmp_path):
    body = "# DATABASE_URL=\n# OPENAI_API_KEY=\nEMPTY=\n"
    assert "ST-ENV-SHIPPED" not in _scanner_ids(_write(tmp_path, ".env", body))


def test_env_in_build_output_is_still_scored(tmp_path):
    """The build-output demotion must not swallow this rule.

    That layer exists because a bundler inlines third-party code and destroys the path signals the
    other demotions rely on. It has nothing to say about a whole file the packer copied in: a .env
    under build/ ships to every installer exactly like one at the root. Found on a real package
    whose credentials our own demotion was hiding.
    """
    (tmp_path / "package.json").write_text('{"name":"t","version":"1.0.0"}\n', encoding="utf-8")
    build = tmp_path / "build"
    build.mkdir()
    (build / ".env").write_text(ENV_BODY, encoding="utf-8", newline="\n")

    component = Component(name="t", type="npm_package", version="1.0.0", source="local")
    report = engine.analyze_directory(tmp_path, component).to_dict()
    finding = next(f for f in report["findings"] if f["id"] == "ST-ENV-SHIPPED")
    assert [e["file"] for e in finding["evidence"]] == ["build/.env"]
    assert report["risk_score"] > 0
