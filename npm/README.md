# skilltotal

Run the SkillTotal scanner with npx. It checks MCP servers, agent skills and npm/PyPI packages for tool poisoning, malicious install scripts, credential exfiltration and hidden Unicode. Every finding cites the file and line it came from. The analysis is static: the scanner never runs the code it reads and never calls an LLM.

```bash
npx -y skilltotal scan https://github.com/owner/repo
npx -y skilltotal scan npm:some-package --fail-on-high
```

To use it as a local MCP server in Claude Code, Claude Desktop, Cursor or any other MCP client:

```json
{ "mcpServers": { "skilltotal": { "command": "npx", "args": ["-y", "skilltotal", "mcp"] } } }
```

## How it runs

The scanner itself is the `skilltotal` Python package (Python 3.10+). This npm package (Node.js 18 or later) has no scanner code. It starts the engine with the first of these it finds:

1. `uvx` from [uv](https://docs.astral.sh/uv/), which runs the PyPI release matching this package's version in an isolated environment.
2. `pipx run`, which runs the same release, also isolated.
3. An installed Python 3.11 or later that already has `skilltotal`, run as `python -P -m skilltotal`. This uses whatever version is installed. The `-P` flag, added in Python 3.11, keeps the current directory off the import path, so a `skilltotal/` or `json.py` in the folder you run it from (such as a repository you are scanning) cannot run in place of the engine.

On Windows, the package looks for `uvx`, `pipx` and Python only in the directories on PATH, never in the current directory, so a `uvx.exe` or `python.exe` committed to a repository you scan cannot run in place of the real one.

The package does not install anything itself, and it has no install scripts or dependencies. If none of the three is available, it exits with code 127 and prints how to install uv, pipx or the Python package.

## Links

- Documentation and full usage: https://github.com/pezhik/skilltotal
- Python package: https://pypi.org/project/skilltotal/
- Website: https://www.skilltotal.ai

License: Apache-2.0
