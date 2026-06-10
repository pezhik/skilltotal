# Ruleset changelog

Tracks changes to the **detection ruleset**, keyed by `RULESET_VERSION`
(`skilltotal/__init__.py`). A consumer that stored reports at an older ruleset version may
re-scan to pick up newer findings. See `docs/contributing-rules.md` for the process.

## ruleset 6 (engine 0.6.0)

Adds detectors for the **unintentional risky-construct** classes (the bulk of real-world MCP
issues catalogued at vulnerablemcp.info). All are `threat_class = risky_construct`: they are
real, exploitable risks regardless of author intent, but they do NOT raise the malware
verdict (which stays reserved for deliberate deception). Corpus-calibrated against the
trusted real-world corpus with zero false positives.

- **`ST-SECRET-EMBEDDED`** — hardcoded credentials shipped in the component: known-prefix
  tokens (AWS/GitHub/GitLab/OpenAI/Anthropic/Slack/Google/Stripe), private-key blocks, and a
  secret-named-variable assignment rule. Placeholder/example values and test paths are
  filtered; the secret value is **redacted** in evidence so the report never re-leaks it.
- **`ST-CMDI-PY` / `ST-CMDI-NODE`** — command injection: a shell sink (os.system/os.popen,
  `subprocess(..., shell=True)`, `child_process.exec`) fed a command built by interpolation/
  concatenation/variable. Safe argv-without-shell and constant commands are excluded.
- **`ST-DESERIALIZE-PY`** — unsafe deserialization: pickle/cPickle/dill/marshal/jsonpickle,
  and `yaml.load` without a Safe loader (a Safe loader is recognized and not flagged).
- **`ST-EXPOSE-BIND` / `ST-EXPOSE-DEBUG`** — network-exposure posture: binding to 0.0.0.0 /
  all interfaces, and debug servers (e.g. Flask `debug=True`).

## ruleset 5 (engine 0.5.0)

Adds an MCP **exfiltration-surface** heuristic (toxic agent flow / lethal trifecta),
inspired by the Invariant Labs GitHub MCP writeup
(<https://invariantlabs.ai/blog/mcp-github-vulnerability>).

- When a component's MCP tools span a **network** channel AND **data access**
  (`filesystem` / `browser` / `credential`), a `needs_review` note is emitted:
  *"MCP exfiltration surface (network + data access)"*. Shell tools are excluded (already
  flagged HIGH on their own).
- Deliberately a **needs_review**, never a scored finding: the exploit is architectural
  (indirect prompt injection in runtime data + the agent's permissions), not a flaw in the
  server code, and legitimate servers (e.g. a GitHub server) share this surface. We only
  surface the capability combination and point to runtime permissioning as the mitigation —
  consistent with the "interpret evidence only, never assert intent" invariant. No score
  impact, so no false-positive pressure on the trusted corpus.

## ruleset 4 (engine 0.1.0)

Broadens **`ST-MCP-TOOL-POISONING`** (still cf. MCPTox, arXiv:2508.14925) and fixes a
false positive in ruleset 3:

- **Cross-tool precondition hijack** — a mandatory precondition forced on *another* tool's
  operation (e.g. "before any file operation, you must ...") and fake-authority "mandatory
  security/verification check" framing are now detected.
- **Parameter descriptions** — `inputSchema` property descriptions are now scanned for the
  same poisoning patterns, not just the top-level tool `description`.
- **Precision fix** — bare `silently` (ruleset 3) flagged benign text like "fails silently".
  It now requires an adjacent action verb (`silently read|send|exfiltrate|include|pass|…`);
  `secretly` and `without telling the user` remain. Regression test added.

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
