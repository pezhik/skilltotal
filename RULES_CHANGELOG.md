# Ruleset changelog

Tracks changes to the **detection ruleset**, keyed by `RULESET_VERSION`
(`skilltotal/__init__.py`). A consumer that stored reports at an older ruleset version may
re-scan to pick up newer findings. See `docs/contributing-rules.md` for the process.

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
