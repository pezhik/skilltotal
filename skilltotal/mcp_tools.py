"""The MCP tools a component defines, as fingerprints, for comparing two versions.

A "rug pull" changes what a tool tells the model after it was approved: the description gains a
sentence, the schema gains a parameter. When the new text matches no detection pattern, a diff of
findings shows nothing. So every report records, per tool, a hash of its description and of its
input schema (``metadata.mcp_tools``), and :mod:`skilltotal.diff` lists the tools that were
added, removed or changed. It is a statement of fact about the files, never scored.

Read from what the files declare, without running anything:

* a tool listing or manifest in JSON (``tools.json``, a saved ``tools/list``, ``server.json``);
* Python functions registered with a ``.tool`` decorator: the docstring or ``description=`` and
  the parameter list;
* JavaScript / TypeScript ``server.tool("name", "description", ...)`` and ``registerTool``: the
  description when it is a plain string.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from itertools import islice

from skilltotal import bounded_json
from skilltotal.file_index import FileIndex, IndexedFile, is_test_path
from skilltotal.scanners.mcp import _CODE_SURFACE, _SCHEMA_KEYS, _dicts, is_mcp_listing

MAX_TOOLS = 500
_MAX_FILES = 200
_JS_TOOL = re.compile(
    r"\.(?:registerTool|tool)\s*\(\s*['\"]([\w.-]{1,200})['\"]"
    r"(?:\s*,\s*(?:(\"(?:[^\"\\\n]|\\.){0,20000}\")|('(?:[^'\\\n]|\\.){0,20000}')"
    r"|(`(?:[^`\\]|\\.){0,20000}`)))?"
)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _entry(name: str, f: IndexedFile, description: str, schema: str) -> dict[str, str]:
    return {
        "name": name[:200],
        "file": f.relpath,
        "description_sha256": _digest(description),
        "schema_sha256": _digest(schema),
    }


def tool_definitions(index: FileIndex) -> list[dict[str, str]]:
    """One entry per MCP tool the component's files define (at most ``MAX_TOOLS``), sorted."""
    tools: list[dict[str, str]] = []
    files = 0
    for f in index.files:
        if len(tools) >= MAX_TOOLS or files >= _MAX_FILES:
            break
        if is_test_path(f.relpath):
            continue
        if f.suffix == ".json":
            if '"tools"' not in f.text:
                continue
            files += 1
            tools.extend(_json_tools(f))
        elif f.suffix in (".py", ".pyw"):
            if ".tool" not in f.text or not _CODE_SURFACE.search(f.text):
                continue
            files += 1
            tools.extend(_python_tools(f))
        elif f.suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            if "ool(" not in f.text or not _CODE_SURFACE.search(f.text):
                continue
            files += 1
            tools.extend(
                _entry(m.group(1), f, m.group(2) or m.group(3) or m.group(4) or "", "")
                for m in islice(_JS_TOOL.finditer(f.text), MAX_TOOLS)
            )
    tools.sort(key=lambda t: (t["file"], t["name"]))
    return tools[:MAX_TOOLS]


def _json_tools(f: IndexedFile) -> list[dict[str, str]]:
    try:
        data = bounded_json.loads(f.text)
    except (ValueError, RecursionError):
        return []
    if not is_mcp_listing(data):
        return []
    found = []
    for tool in islice(_dicts(data.get("tools")), MAX_TOOLS):
        name = tool.get("name")
        if not isinstance(name, str) or not name:
            continue
        schema = {key: tool[key] for key in _SCHEMA_KEYS if key in tool}
        try:
            schema_text = json.dumps(schema, sort_keys=True, ensure_ascii=False)
        except (TypeError, ValueError, RecursionError):
            schema_text = repr(sorted(schema))
        found.append(_entry(name, f, str(tool.get("description", "")), schema_text))
    return found


def _python_tools(f: IndexedFile) -> list[dict[str, str]]:
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if not (isinstance(target, ast.Attribute) and target.attr == "tool"):
                continue
            name, description = node.name, ast.get_docstring(node) or ""
            for kw in dec.keywords if isinstance(dec, ast.Call) else ():
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    if kw.arg == "name":
                        name = kw.value.value
                    elif kw.arg == "description":
                        description = kw.value.value
            try:
                schema = ast.unparse(node.args)
            except (RecursionError, ValueError):
                schema = ""
            found.append(_entry(name, f, description, schema))
            break
        if len(found) >= MAX_TOOLS:
            break
    return found


def tool_changes(old: list[dict], new: list[dict]) -> list[dict[str, object]]:
    """Tools added, removed or changed between two ``metadata.mcp_tools`` lists."""

    def keyed(tools: list[dict]) -> dict[tuple[str, str], dict]:
        return {
            (str(t.get("file", "")), str(t.get("name", ""))): t
            for t in tools if isinstance(t, dict)
        }

    before, after = keyed(old), keyed(new)
    changes: list[dict[str, object]] = []
    for key in sorted(before.keys() | after.keys()):
        file, name = key
        if key not in before:
            changes.append({"name": name, "file": file, "change": "added", "changed": []})
        elif key not in after:
            changes.append({"name": name, "file": file, "change": "removed", "changed": []})
        else:
            parts = [
                part for part in ("description", "schema")
                if before[key].get(f"{part}_sha256") != after[key].get(f"{part}_sha256")
            ]
            if parts:
                changes.append({"name": name, "file": file, "change": "changed", "changed": parts})
    return changes
