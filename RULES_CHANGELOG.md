# Ruleset changelog

Tracks changes to the **detection ruleset**, keyed by `RULESET_VERSION`
(`skilltotal/__init__.py`). A consumer that stored reports at an older ruleset version may
re-scan to pick up newer findings. See `docs/contributing-rules.md` for the process.

## ruleset 10 (engine 0.8.1)

**Prompt-injection FP calibration.** `ST-PROMPT-INJECTION`'s "ignore … above" alternative was
bare (`ignore (everything )?above`) and over-matched benign text. The expanded calibration
corpus surfaced two trusted-package false positives:
- Jupyter `notebook` — `// IGNORE ABOVE ELSE` in a minified JS bundle (and its `.js.map`).
- `ruff` — "ignore above a multi-line statement" in the linter's own suppression test docs.

The pattern now requires intent: an `everything`/`all` quantifier (`ignore everything above`) or
an explicit instruction object (`ignore the above instructions|prompts|context|…`). Genuine
overrides ("ignore everything above", "ignore the above instructions") still fire; bare
"ignore above …" no longer does. Regression tests added in `tests/test_scanners.py`.

## ruleset 9 (engine 0.8.0)

Two themes: **stop the scanner from flagging non-executed context** (its own pattern literals,
prose, docs) and **stop scoring neutral capability as risk**. Driven by a self-scan that
verdicted SkillTotal's own repo "malicious" (100/100) — a false-positive class shared by any
security tool, docs-heavy repo, or README that shows an example attack.

- **Code-context demotion (new).** A regex match inside a Python string literal or comment is a
  pattern literal / docstring example, not behavior. Per a rule's `code_context` policy, such
  `.py` matches are demoted to `needs_review`:
  - `strings_and_comments`: `ST-OBF-DECODE-EXEC`, `ST-MCP-TOOL-POISONING`, `ST-PROMPT-INJECTION`,
    `ST-SENS-PATH` (real positives are code calls / JSON-manifest text / instruction files /
    path values — never a `.py` pattern-literal).
  - `comments`: `ST-EXPOSE-BIND`, `ST-EXPOSE-DEBUG` (real positives are value-strings like
    `host="0.0.0.0"`; the FP is the same token in a `#` comment).
- **Documentation/prose demotion (new).** Findings whose evidence is only in human-facing docs
  (README/CHANGELOG/LICENSE/`docs/`/`*.egg-info`/ignore-files) → `needs_review`. AI-instruction
  surfaces (`SKILL.md`, `AGENTS.md`, `.cursorrules`, MCP manifests, …) are explicitly excluded,
  so a real injection there still fires.
- **`ST-COMBO-FS-NET` → `ST-COMBO-EXFIL`.** The combination finding is now sensitivity-gated:
  critical `risky_construct` only when sensitive-data access (`ST-SENS-PATH` / `ST-SECRET-EMBEDDED`)
  co-occurs with network egress. Plain filesystem + network no longer synthesizes a critical.
- **Bare `.env`** moved out of the scored `ST-SENS-PATH` finding into `needs_review` (dotenv is
  ubiquitous in legitimate apps; `.env` + network would otherwise flag most web apps as exfil).
- **`ST-SENS-PATH-PY` (new, AST).** For Python, sensitive-path access is now detected
  structurally: a credential location (`~/.ssh`, `~/.aws/credentials`, `id_rsa`, …) passed to a
  filesystem / process / network call (`open`, `os.path.expanduser`, `subprocess`, `requests`, …)
  is a scored `risky_construct`, and feeds `ST-COMBO-EXFIL`. Because it matches by call argument,
  it catches real credential reads (`open(expanduser("~/.ssh/id_rsa"))`) while the regex
  `ST-SENS-PATH` (demoted in `.py` strings/comments) no longer flags a detector's own pattern
  literals or docstrings. The regex rule still covers non-Python files (`.js`, manifests, docs/
  instruction surfaces).
- **Scoring:** `capability` findings contribute 0 to `risk_score` (malicious + risky only). No
  detection rule was removed; malicious-indicator detection is unchanged, so genuine malware
  (obfuscated exec, prompt injection, tool poisoning, hidden unicode, credential+egress) still
  scores and verdicts as before.

## ruleset 8 (engine 0.7.4)

False-positive recalibration after scanning 37 real MCP servers (the labeled corpus was
general packages, not MCP servers, and missed these). 6 popular servers were wrongly flagged
malicious; all fixed, with regression tests. No new rules; existing rules narrowed/demoted.

- **`ST-MCP-TOOL-SHADOWING`** → demoted from `malicious_indicator` finding to **`needs_review`**.
  Steering between tools ("use X instead", "do not use the Y tool") can't be distinguished by
  pattern from legitimate intra-server routing ("DO NOT use this tool for PDFs; use `write_pdf`")
  or code comments ("# override create_broker tool"). Still surfaced, never scored.
- **`ST-MCP-TOOL-POISONING`** — removed the bare "before using/calling this tool" imperative
  (matched benign prerequisites like awslabs "ask the user before calling this tool"). The
  cross-tool precondition now requires a sensitive read/send target (`~/.ssh`, credentials,
  tokens, …) to fire.
- **`ST-PROMPT-INJECTION`** — narrowed: dropped `print`/`show` from "reveal the system prompt"
  (legit `print-system-prompt` CLI), dropped the standalone "hidden instruction" phrase (FP'd on
  a hidden-char scanner's own comment), and suppressed "send <secret> to" when negated (MCP spec
  prose "MUST NOT send tokens to the MCP server").

## ruleset 7 (engine 0.7.1; 0.7.0 yanked)

Closes MCP/skill coverage gaps confirmed against agent-scan and agent-audit, removes a
high-volume source of report noise, and recalibrates three `malicious_indicator` rules that a
labeled-corpus run found false-positiving on trusted packages. Net: 0 benign false positives
on the calibration corpus.

- **`ST-MCP-TOOL-SHADOWING`** (`malicious_indicator`, HIGH) — a tool description that steers
  the agent's choice *between* tools (e.g. "use this tool instead of the X tool", "do not use
  the X tool", "overrides the X tool"). Distinct from tool-poisoning (which hides imperatives
  about the tool itself). Scanned in JSON manifests and code-defined tool descriptions.
- **`ST-MCP-AUTO-APPROVE`** (`risky_construct`, MEDIUM) — an `mcpServers` entry with a
  non-empty `autoApprove` / `alwaysAllow` list (or `"trust": true`): pre-authorized tool
  calls remove the per-call human confirmation gate for the whole server.
_(An `ST-PROMPT-EXFIL-MD` markdown-exfiltration rule was added in the yanked 0.7.0 and
removed in 0.7.1: it false-positived on any markdown link with a literal `$`/`{` in the URL.
Reliable detection needs prompt-instruction context — deferred to the runtime/paid layer.)_

### Changed
- **`ST-OBF-MINIFIED`** — skips build artifacts that are long-line by design (`.map`,
  `.d.ts`/`.d.mts`/`.d.cts`, `*.min.*`, `package-lock.json`) and aggregates the rest into a
  single `needs_review` entry instead of one row per file. Eliminates the dozens of identical
  rows a legitimate SDK (e.g. an OpenAI client with bundled source maps) used to produce.
- **`ST-HIDDEN-UNICODE`** — now scores only Unicode **tag characters** (U+E0000+, the
  unambiguous ASCII-smuggling signal). **Bidi overrides and zero-width characters** moved to
  `ST-HIDDEN-UNICODE-AMBIG` (`needs_review`): they appear legitimately in RTL-locale `.po`
  files (django), CJK i18n (typescript), HTML-entity tables (webpack), and emoji.
- **`ST-MCP-TOOL-POISONING`** — dropped the over-broad `always/first … before` sub-pattern
  (fired on benign "Always call X before Y" ordering guidance).
- **`ST-PROMPT-INJECTION`** — `do not tell the user` / `without telling the user` moved to
  `needs_review` (also a benign UX guardrail, e.g. GitHub's MCP server's "do NOT tell the user
  the issue was updated; the user MUST click Submit"). Stronger scored signals still apply.

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
