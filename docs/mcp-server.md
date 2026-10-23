# MCP server

Let your agent check a component *before* installing it. `skilltotal mcp` runs the engine
as a stdio MCP server (stdlib-only, still zero dependencies). The Claude Code plugin already
registers it, so don't add it a second time there. In Claude Code without the plugin:

```bash
claude mcp add skilltotal -- skilltotal mcp
```

For Claude Desktop, Cursor, Windsurf or any client that reads `mcpServers`:

```json
{ "mcpServers": { "skilltotal": { "command": "skilltotal", "args": ["mcp"] } } }
```

For VS Code (`.vscode/mcp.json` or the user `mcp.json`):

```json
{ "servers": { "skilltotal": { "type": "stdio", "command": "skilltotal", "args": ["mcp"] } } }
```

A desktop app started from the Dock, Start menu or Finder does not see the `PATH` that pipx set
up in your shell. If it cannot start `skilltotal`, give the full path that `which skilltotal`
(`where skilltotal` on Windows) prints as `command`.

If you have not installed it locally, use `"command": "uvx", "args": ["skilltotal@0.80.0", "mcp"]`
(pinned) or `"command": "npx", "args": ["-y", "--package=skilltotal@0.80.0", "--", "skilltotal",
"mcp"]` (with `--package`, npx does not run whatever `skilltotal` program the `node_modules/.bin`
of the client's folder holds). The npx form needs uv, pipx, or Python 3.11+ with
`skilltotal`; if it falls back to an installed Python `skilltotal` of another release, it warns on
stderr (stdout stays the MCP session).

Tools exposed, all annotated read-only:

- `scan_component` scans a local path, git URL, `npm:` or `pypi:` source. By default it answers
  with a summary of a few kilobytes: the verdict, the risk, why (each finding with up to three
  locations), the capabilities, notes to check by hand and what the scan does not cover. Pass
  `detail: "full"` for the complete report.
- `diff_components` reviews an upgrade: what changed between two versions. It takes the same
  `detail`.
- `list_rules` lists the detection rules. Narrow it with `ids` or `query`; pass `verbose: true`
  for each rule's description and recommendation.

A local path must be absolute, because the server's working directory is not the client's. The
home folder (under any name for it, a link included), any folder above it and a filesystem root
are refused, and `~` is not expanded. So are network shares and device paths (`\\host\share`,
`\\?\...`) and NTFS streams. The server runs two requests at a time and answers `ping` at once; a cancelled request gets no
answer. Scans run locally with the same never-execute static engine; the component's code is not
uploaded anywhere. To raise a size limit for the server, set the variable in the `env` of its
entry in the client's config.
