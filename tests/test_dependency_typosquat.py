"""``ST-DEP-TYPOSQUAT``: a dependency or a launched package named like a popular one.

Only the ways a name is mistyped or disguised count (swapped, doubled or dropped letters, digits
and look-alike characters, separators, a look-alike scope). Honest packages that sit one letter
from a popular one must stay clean.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.scanners.mcp_pinning import launched_packages
from skilltotal.typosquatting import name_lookalike

RULE = "ST-DEP-TYPOSQUAT"


def _analyze(tmp_path: Path, files: dict[str, str]):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="\n")
    return analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))


def _finding(report):
    return next((f for f in report.findings if f.id == RULE), None)


def _package_json(deps: dict[str, str], section: str = "dependencies") -> str:
    return json.dumps({"name": "notes-tools", "version": "1.0.0", section: deps}, indent=2)


@pytest.mark.parametrize(
    ("name", "ecosystem", "popular"),
    [
        ("axois", "npm", "axios"),
        ("loadsh", "npm", "lodash"),
        ("expres", "npm", "express"),
        ("mongose", "npm", "mongoose"),
        ("crossenv", "npm", "cross-env"),
        ("l0dash", "npm", "lodash"),
        ("rnongoose", "npm", "mongoose"),
        ("electorn", "npm", "electron"),
        ("reаct", "npm", "react"),  # Cyrillic a
        ("ex​press", "npm", "express"),  # zero-width space
        ("reqeusts", "pypi", "requests"),
        ("urlib3", "pypi", "urllib3"),
        ("requ3sts", "pypi", "requests"),
        ("djang0", "pypi", "django"),
        ("nurnpy", "pypi", "numpy"),
        ("colourama", "pypi", "colorama"),
        ("python-dotnev", "pypi", "python-dotenv"),
        ("mcp-server-fetchh", "pypi", "mcp-server-fetch"),
        ("@modelcontextprotocoI/server-github", "npm", "@modelcontextprotocol"),
        ("@modelcontextprotocl/server-github", "npm", "@modelcontextprotocol"),
    ],
)
def test_disguised_or_mistyped_names_are_recognised(name, ecosystem, popular):
    found = name_lookalike(name, ecosystem)
    assert found is not None and found[0] == popular, found


@pytest.mark.parametrize(
    ("name", "ecosystem"),
    [
        # the popular packages themselves, and known packages near them
        ("lodash", "npm"), ("requests", "pypi"), ("preact", "npm"), ("vitest", "npm"),
        ("scapy", "pypi"), ("psycopg", "pypi"),
        # real packages one edit from a popular one: a letter added inside or at an end,
        # a letter dropped at an end, a plain substitution
        ("graphiql", "npm"), ("reactn", "npm"), ("expresso", "npm"), ("requests", "npm"),
        ("classname", "npm"), ("inquire", "npm"), ("pedantic", "pypi"), ("ptest", "pypi"),
        ("request", "pypi"), ("pandasql", "pypi"), ("websocket", "pypi"), ("flash", "pypi"),
        # digits that are part of an honest name
        ("d3-scale", "npm"), ("es6-promise", "npm"), ("i18next", "npm"), ("web3-utils", "npm"),
        ("h5py", "pypi"), ("py2neo", "pypi"), ("base64-js", "npm"),
        # scoped names: the scope decides
        ("@types/lodahs", "npm"), ("@modelcontextprotocol/server-filesytem", "npm"),
        ("@acme/axois", "npm"),
        # PyPI treats - _ . alike
        ("python_dotenv", "pypi"), ("Python.Dotenv", "pypi"),
        # too short to judge
        ("vuee", "npm"), ("jset", "npm"),
    ],
)
def test_honest_neighbours_are_not_flagged(name, ecosystem):
    assert name_lookalike(name, ecosystem) is None


def test_package_json_dependencies(tmp_path):
    report = _analyze(tmp_path, {
        "package.json": _package_json({"axois": "^1.6.0", "express": "^4.19.0"}),
        "index.js": "module.exports = 1;\n",
    })
    finding = _finding(report)
    assert finding is not None
    assert finding.threat_class.value == "risky_construct"
    assert "'axois' reads as 'axios'" in finding.description
    [ev] = finding.evidence
    assert ev.file == "package.json" and "axois" in ev.snippet
    assert not (report.verdict or {}).get("has_malicious_indicators")


def test_dev_dependency_and_other_sources(tmp_path):
    report = _analyze(tmp_path, {
        "package.json": json.dumps({
            "name": "notes-tools", "version": "1.0.0",
            "devDependencies": {"crossenv": "^7.0.0"},
            # another source than the registry: not a registry name
            "dependencies": {
                "lodash": "npm:lodash-es@^4.17.21",
                "axois": "file:../axois",
                "loadsh": "github:someone/loadsh",
                "expres": "https://pkgs.example.test/expres.tgz",
            },
        }),
    })
    finding = _finding(report)
    assert finding is not None
    assert len(finding.evidence) == 1 and "crossenv" in finding.evidence[0].snippet
    assert "axois" not in finding.description and "loadsh" not in finding.description


def test_requirements_and_pyproject(tmp_path):
    report = _analyze(tmp_path, {
        "requirements.txt": (
            "# pinned\nrequ3sts==2.31.0\nurllib3>=2\n-r base.txt\n-e ./vendor/reqeusts\n"
            "git+https://code.example.test/reqeusts.git\n"
        ),
        "pyproject.toml": (
            '[project]\nname = "report-tools"\nversion = "1.0.0"\n'
            'dependencies = [\n    "nurnpy>=1.26",\n    "click>=8",\n]\n'
            '[tool.other]\nkeywords = ["reqeusts"]\n'
        ),
        "app.py": "VALUE = 1\n",
    })
    finding = _finding(report)
    assert finding is not None
    assert {(ev.file, ev.line_start) for ev in finding.evidence} == {
        ("requirements.txt", 2), ("pyproject.toml", 5),
    }


def test_honest_manifests_stay_clean(tmp_path):
    report = _analyze(tmp_path, {
        "package.json": _package_json({
            "graphql": "^16.0.0", "graphiql": "^3.0.0", "preact": "^10.0.0", "reactn": "^2.2.7",
            "i18next": "^23.0.0", "@types/lodash": "^4.14.0",
        }),
        "requirements.txt": "requests==2.31.0\npedantic==2.1.0\nscapy==2.5.0\nh5py==3.10.0\n",
        "index.js": "module.exports = 1;\n",
    })
    assert _finding(report) is None


def test_mcp_launch_command(tmp_path):
    config = {"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocoI/server-github@1.0.0"]},
        "fetch": {"command": "uvx", "args": ["mcp-server-fetchh==1.0.0"]},
        "files": {"command": "npx",
                  "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/srv"]},
        "local": {"command": "node", "args": ["./axois/server.js"]},
    }}
    report = _analyze(tmp_path, {".mcp.json": json.dumps(config, indent=2)})
    finding = _finding(report)
    assert finding is not None
    snippets = sorted(ev.snippet for ev in finding.evidence)
    assert len(snippets) == 2
    assert "modelcontextprotocoI" in snippets[0] and "mcp-server-fetchh" in snippets[1]


def test_honest_mcp_launch_commands_stay_clean(tmp_path):
    config = {"mcpServers": {
        "files": {"command": "npx",
                  "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/srv"]},
        "fetch": {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]},
        "api": {"command": "uvx", "args": ["some-mcp-server==1.4.2"]},
    }}
    assert _finding(_analyze(tmp_path, {".mcp.json": json.dumps(config)})) is None


def test_install_command_in_an_instruction_file(tmp_path):
    skill = (
        "---\nname: pdf-helper\ndescription: Helps convert documents to PDF.\n---\n# PDF helper\n\n"
        "Setup:\n\n```bash\npip install -U requ3sts pandas\nnpm install rnongoose\n"
        "npx playwright install chromium\n```\n"
    )
    finding = _finding(_analyze(tmp_path, {"SKILL.md": skill}))
    assert finding is not None
    assert sorted(ev.line_start for ev in finding.evidence) == [10, 11]


def test_launched_packages_reads_the_package_word():
    assert launched_packages(["npx", "-y", "pkg@1.2.3", "--flag"]) == ("npm", ["pkg@1.2.3"])
    assert launched_packages(["uvx", "--from", "tool==1.0", "run"]) == ("pypi", ["tool==1.0"])
    assert launched_packages(["pnpm", "dlx", "-p", "a", "-p", "b", "cmd"]) == ("npm", ["a", "b"])
    assert launched_packages(["npx", "./local.js"]) == ("npm", [])
    assert launched_packages(["node", "server.js"]) == ("", [])
    assert launched_packages([]) == ("", [])


def test_a_large_manifest_is_read_in_bounded_time(tmp_path):
    deps = {f"package-number-{i}": "^1.0.0" for i in range(5000)}
    lines = "".join(f"library-number-{i}==1.0\n" for i in range(20000))
    start = time.process_time()
    report = _analyze(tmp_path, {"package.json": _package_json(deps), "requirements.txt": lines})
    assert _finding(report) is None
    assert time.process_time() - start < 20
