# Ruleset changelog

Tracks changes to the **detection ruleset**, keyed by `RULESET_VERSION`
(`skilltotal/__init__.py`). A consumer that stored reports at an older ruleset version may
re-scan to pick up newer findings. See `docs/contributing-rules.md` for the process.

## ruleset 3 (engine 0.1.0)

New detection for **MCP tool poisoning** (cf. MCPTox, arXiv:2508.14925): malicious
instructions embedded in a tool's *description/metadata* that steer the agent when the tool
is merely listed — no execution required.

- **`ST-MCP-TOOL-POISONING`** (HIGH, capability `prompt_surface_risk`) — fires when an MCP
  tool description (JSON manifest) or a code-defined tool's docstring/metadata (in a file that
  exposes an MCP tool surface) contains agent-directed imperatives or fake-authority markers:
  `<IMPORTANT>`/`[system]` tags, `system note:`/`developer instruction:`, `before using this
  tool …`, `always call … first`, `ignore the tool's description`, `do not tell the user`,
  `secretly`/`without telling the user`. These are distinct from the generic
  `ST-PROMPT-INJECTION` phrases (prompt_surface) and are scoped to MCP surfaces to stay
  high-signal / low-FP. Benign descriptions (e.g. "Adds two numbers") are not flagged.

## ruleset 2 (engine 0.1.0)

False-positive calibration against reputable real-world repos (requests, flask, urllib3,
axios, context7). Precision-only; no rule ids, severities, or categories changed.

- **`ST-SENS-PATH`** — the bare ``.env`` file token is no longer flagged in documentation
  files (`.md`/`.mdx`/`.rst`/`.txt`/`.adoc`) or ignore files
  (`.gitignore`/`.dockerignore`/`.npmignore`/`.prettierignore`/`.eslintignore`), where it
  almost always describes dotenv support or lists `.env` for exclusion. Strong, path-like
  indicators (`~/.ssh`, `~/.aws`, `.aws/credentials`, `id_rsa`, …) still fire in **all**
  file types, so prompt-injection instructions to read credentials in an `.md` are still
  caught. Eliminated FPs in flask/requests/urllib3 (docs) and `.env` ignore-list entries.
- **`ST-DYN-PY`** — dynamic *module import by name* (`__import__`,
  `importlib.import_module`) is routed to `needs_review` ("Dynamic module import") instead
  of a high-severity finding; it is a common, low-signal pattern (optional dependencies,
  plugin loaders). True arbitrary-code execution (`eval`/`exec`/`compile`) remains a
  confirmed `ST-DYN-PY` finding. Eliminated the requests FP.

## ruleset 1 (engine 0.1.0)

Initial ruleset (27 rules across 11 scanners):

- **Shell execution** — `ST-SHELL-PY` (subprocess/os.system/os.popen, `asyncio.create_subprocess_*`,
  process-spawning libs sh/plumbum/pexpect/invoke/fabric), `ST-SHELL-NODE` (child_process,
  zx/execa/cross-spawn/shelljs/spawn-rx/tinyexec/node-pty).
- **Filesystem** — `ST-FS-PY-READ/WRITE`, `ST-FS-NODE-READ/WRITE`.
- **Sensitive paths** — `ST-SENS-PATH` (strong: ~/.ssh, ~/.aws, .aws/credentials, id_rsa,
  .env file), `ST-SENS-WORD` (ambiguous → needs_review).
- **Network egress** — `ST-NET-PY`, `ST-NET-NODE`.
- **Install-time** — `ST-INSTALL-NPM` (preinstall/install/postinstall), `ST-INSTALL-NPM-PREPARE`
  (medium), `ST-INSTALL-PY`.
- **Dynamic code** — `ST-DYN-PY`, `ST-DYN-NODE`.
- **Obfuscation** — `ST-OBF-DECODE-EXEC`; needs_review heuristics (base64 blob, hex, minified).
- **MCP** — `ST-MCP-DETECTED`, `ST-MCP-DANGEROUS-TOOL` (JSON + code-defined tools),
  `ST-MCP-SERVER-EXEC`.
- **Prompt surface** — `ST-PROMPT-INJECTION`; `ST-PROMPT-WEAK` (needs_review).
- **Hidden Unicode** — `ST-HIDDEN-UNICODE` (tags/bidi/zero-width); `ST-HIDDEN-UNICODE-AMBIG`.
- **Combination** — `ST-COMBO-FS-NET` (synthesized critical when filesystem + network).
