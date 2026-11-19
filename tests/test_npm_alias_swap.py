"""``ST-DEP-TYPOSQUAT`` over npm aliases (``"name": "npm:other@1"``).

The package an alias installs is checked like any dependency name, and a well-known name that
stands for an unscoped, unrelated package is reported. The honest uses of an alias (another
version, a scoped fork, a build named after the original, another well-known package) stay clean.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.typosquatting import alias_replaces_known_name

RULE = "ST-DEP-TYPOSQUAT"


def _analyze(tmp_path: Path, manifest: dict):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "notes-tools", "version": "1.0.0", **manifest}, indent=2),
        encoding="utf-8", newline="\n",
    )
    return analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))


def _finding(report):
    return next((f for f in report.findings if f.id == RULE), None)


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("lodash", "lodahs-utils-core"),
        ("express", "fast-http-core-utils"),
        ("axios", "net-request-kit"),
        ("react-dom", "ui-runtime-shim"),
        ("mcp-remote", "bridge-helper-kit"),
    ],
)
def test_well_known_name_for_an_unrelated_package(name, target):
    assert alias_replaces_known_name(name, target)


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("react", "react"),  # another version of itself
        ("react-17", "react"),  # the key is not a well-known name
        ("lodash", "lodash-es"),  # a build named after the original
        ("vite", "rolldown-vite"),
        ("prettier", "wp-prettier"),
        ("react-dom", "preact-compat"),  # carries a word of the name
        ("react", "@preact/compat"),  # a scope has an owner
        ("node-fetch", "@acme/node-fetch"),
        ("underscore", "lodash"),  # another well-known package
        ("moment", "dayjs"),
        ("lodash", "es-toolkit"),  # a known drop-in replacement
        ("my-http", "fast-http-core-utils"),  # not a well-known name
    ],
)
def test_honest_aliases(name, target):
    assert not alias_replaces_known_name(name, target)


def test_alias_in_dependencies_is_a_risky_construct(tmp_path):
    report = _analyze(tmp_path, {
        "dependencies": {"express": "npm:fast-http-core-utils@4.18.2", "react": "^18.3.1"},
    })
    finding = _finding(report)
    assert finding is not None
    assert finding.threat_class.value == "risky_construct"
    assert "'express' is an alias of 'fast-http-core-utils'" in finding.description
    [ev] = finding.evidence
    assert ev.file == "package.json" and ev.line_start == 5
    assert '"express": "npm:fast-http-core-utils@4.18.2"' in ev.snippet
    assert not (report.verdict or {}).get("has_malicious_indicators")


def test_alias_target_is_read_as_a_dependency_name(tmp_path):
    # The key is nothing special; the package it installs is a look-alike of a popular one.
    report = _analyze(tmp_path, {"devDependencies": {"http-client": "npm:axois@1.6.0"}})
    finding = _finding(report)
    assert finding is not None
    assert "'axois' reads as 'axios'" in finding.description
    assert "http-client" in finding.evidence[0].snippet


def test_alias_in_overrides(tmp_path):
    report = _analyze(tmp_path, {
        "dependencies": {"axios": "^1.6.0"},
        "overrides": {"axios@^1": "npm:net-request-kit@1.6.0"},
        "pnpm": {"overrides": {"parent>lodash": "npm:collection-kit@4.0.0"}},
        "resolutions": {"**/express": "npm:@acme/express@4.18.2"},
    })
    finding = _finding(report)
    assert finding is not None
    assert sorted(ev.line_start for ev in finding.evidence) == [8, 12]
    assert "'axios' is an alias of 'net-request-kit'" in finding.description
    assert "'lodash' is an alias of 'collection-kit'" in finding.description


def test_honest_aliases_stay_clean(tmp_path):
    report = _analyze(tmp_path, {
        "dependencies": {
            "react-17": "npm:react@17.0.2",
            "lodash": "npm:lodash-es@^4.17.21",
            "react": "npm:@preact/compat@17.1.2",
            "react-dom": "npm:preact-compat@3.19.0",
            "node-fetch": "npm:@acme/node-fetch@2.6.7",
            "underscore": "npm:lodash@4",
            "types-react": "npm:@types/react@18",
            "string-width-cjs": "npm:string-width@^4.2.0",
            "vite": "npm:rolldown-vite@latest",
            "typescript": "npm:@typescript/native-preview",
        },
        "overrides": {"esbuild": "npm:esbuild-wasm@0.25.0", "nested": {"chalk": "npm:x@1"}},
    })
    assert _finding(report) is None
