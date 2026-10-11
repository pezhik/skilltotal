"""JSON read the same way on every Python: values nested past MAX_DEPTH are cut off.

``json`` recurses in C, and how deep it can go depends on the interpreter and the platform:
Python 3.14 on Linux reads 100,000 levels that 3.10-3.13, or 3.14 on Windows, cannot. A component
decides how deep its JSON nests, so the same file used to be read on one machine and refused as
unparseable on another, and a deep value beside a hook made a whole agent settings file
unreadable, which hid the hook. Manifests and agent settings configure nothing that deep, so a
value nested past MAX_DEPTH is read as ``null`` and the rest of the file is read everywhere.

For JSON a third party writes: a component's own files and registry documents built from them.
"""

from __future__ import annotations

import json
import re
from typing import Any

# Deeper than anything a manifest or an agent setting configures, and far below where any
# supported Python's json gives up (Python 3.10 allows about 1,000 frames in all).
MAX_DEPTH = 200

# A JSON string, escapes included, or a bracket. Strings are matched so that the brackets inside
# them are skipped, not counted.
_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[\[\]{}]')


def loads(text: str | bytes) -> Any:
    """``json.loads``, with each value nested past MAX_DEPTH read as ``None``."""
    return loads_cut(text)[0]


def loads_cut(text: str | bytes) -> tuple[Any, bool]:
    """``json.loads`` with values nested past MAX_DEPTH read as ``None``, and whether any was.

    Raises ``ValueError`` (``json.JSONDecodeError``) for text that is not JSON, as ``json.loads``
    does, and never ``RecursionError``: depth is counted on the text before parsing, so the result
    is the same on every Python and platform.
    """
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode(json.detect_encoding(text), "surrogatepass")  # as json.loads
    if text.count("[") + text.count("{") <= MAX_DEPTH:
        return json.loads(text), False  # cannot nest that deep: the common case, read as it is
    shallow, cut = _cut_deep(text)
    return json.loads(shallow), cut


def _cut_deep(text: str) -> tuple[str, bool]:
    """``text`` with every value that opens past MAX_DEPTH replaced by ``null``."""
    pieces: list[str] = []
    depth = 0
    kept = 0  # the text from here on has not been copied yet
    cutting = False
    for m in _TOKEN.finditer(text):
        mark = m.group()
        if mark[0] == '"':
            continue
        if mark in "[{":
            depth += 1
            if depth == MAX_DEPTH + 1 and not cutting:
                pieces.append(text[kept : m.start()])
                pieces.append("null")
                cutting = True
        else:
            if depth == MAX_DEPTH + 1 and cutting:
                kept = m.end()
                cutting = False
            depth -= 1
    if cutting:
        # A value opened past MAX_DEPTH and never closed: not JSON, whatever lies before it.
        raise json.JSONDecodeError("unterminated array or object", text, len(text))
    if not pieces:
        return text, False
    pieces.append(text[kept:])
    return "".join(pieces), True
