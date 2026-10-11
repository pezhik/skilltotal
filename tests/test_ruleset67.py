"""Ruleset 67: false positives a pre-launch review found on well-known packages.

Each case is pinned beside a test that the construct it resembles still fires. Sanitized fixtures
only: nothing here is executed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import Component


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


# --- ST-EXPOSE-BIND: an address literal handed to a string method is text, not a bind --------

@pytest.mark.parametrize(
    "line",
    [
        # pytest's terminal summary: a test id split at "::", maxsplit 1 (it scored pytest 30).
        'counts = Counter(item.nodeid.split("::", 1)[0] for item in items)\n',
        'head, _, tail = nodeid.rpartition("::")\n',
        'parts = name.rsplit("::", 2)\n',
        'host = url.replace("0.0.0.0", "localhost", 1)\n',
        'if addr.startswith("0.0.0.0", 0):\n    pass\n',
    ],
)
def test_an_address_passed_to_a_string_method_is_not_a_bind(tmp_path, line):
    assert "ST-EXPOSE-BIND" not in _ids(_write(tmp_path, {"terminal.py": line}))


@pytest.mark.parametrize(
    "line",
    [
        'web.TCPSite(runner, "0.0.0.0", 8080)\n',
        'web.TCPSite(runner, "::", 8080)\n',
        'app.run(host="0.0.0.0", port=80)\n',
        "server.listen(3000, '0.0.0.0')\n",
    ],
)
def test_a_real_bind_still_fires(tmp_path, line):
    assert "ST-EXPOSE-BIND" in _ids(_write(tmp_path, {"srv.py": line}))
