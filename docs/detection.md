# What SkillTotal detects

SkillTotal performs **static** security analysis of AI components: MCP servers, agent
skills/plugins, npm and PyPI packages, VS Code extensions, and AI-generated projects/repositories. The engine
combines capability analysis, dangerous-pattern detection, privilege analysis, supply-chain
(install-time) analysis, prompt-surface analysis, and data-flow correlation (e.g. secret
access combined with network egress). Findings are mapped to risk categories and contribute to
a **0–100 risk score**; capabilities are reported but never inflate the score (capability ≠ risk).
Nothing is executed and no LLM is called, so results are deterministic and reproducible.

| Category | Examples |
|----------|----------|
| Shell execution | `subprocess.*`, `os.system`, `child_process.exec`, `curl … \| bash` handed to a shell call |
| Filesystem access | `open`, `read_text`/`write_text`, `fs.readFile`/`writeFile` |
| Sensitive paths | `~/.ssh`, `~/.aws`, `.env`, `id_rsa`, `credentials`, `secrets` |
| Network egress | `requests`, `urllib`, `aiohttp`, `fetch`, `axios` |
| Install-time execution | npm `preinstall`/`postinstall`/`prepare`, `setup.py` hooks, a lifecycle script that downloads or decodes code and runs it |
| Dynamic code execution | `eval`, `exec`, `compile`, `new Function`, `vm.runInNewContext` |
| Obfuscation | decode-and-execute chains, base64 blobs, hex escaping, minification |
| MCP risks | manifests, dangerous tools (shell/fs/network/credential), server commands, tool annotations the handler's code contradicts |
| Prompt surface | "ignore previous instructions", "reveal system prompt", exfiltration phrasing |
| Post-exploitation | reverse tunnels and shells, a key written into `authorized_keys`, autostart entries (LaunchAgents, cron `@reboot`, Run keys, logon tasks), entries named after the OS vendor, antivirus or Gatekeeper switched off, host details sent home |

`skilltotal rules list` prints every rule. Which rules catch which malware archetype is in
[docs/detection-coverage.md](https://github.com/pezhik/skilltotal/blob/main/docs/detection-coverage.md).

## Coverage by component type

Legend: **✅** analyzed by default for this component type · **⚠️** the engine detects this, but
that surface is uncommon for this type, so it is flagged only when the component actually contains
it (e.g. prompt-injection text inside an npm/PyPI package) · **❌** not applicable to this type.

Columns are the component types SkillTotal scans. **VS Code** = a VS Code extension (a `.vsix`
or an unpacked extension folder, including installed Cursor, Windsurf and VSCodium extensions).
**AI project** = a scanned repository or folder (an agent skill/plugin, an AI-generated codebase,
or a set of prompts/configs) that is not a published package.

| Category | MCP | npm | PyPI | VS Code | AI project |
|---|---|---|---|---|---|
| Prompt injection / instruction override | ✅ | ⚠️ | ⚠️ | ⚠️ | ✅ |
| Tool poisoning (MCP tool and schema text, prompts, resources, server instructions) | ✅ | ❌ | ❌ | ❌ | ⚠️ |
| Dangerous capabilities (shell / fs / network) | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Data exfiltration (secret access + egress) | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Secret theft / sensitive-path access | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Dynamic code execution | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Obfuscation (decode-and-execute) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Post-exploitation (remote access, persistence, masquerading, beacons, defense evasion) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Hidden text (tag characters, variation selectors, invisible operators, zero-width characters inside words, ANSI escapes in agent-facing text) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Embedded secrets (hardcoded keys/tokens) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Install-time / supply-chain hooks | ⚠️ | ✅ | ✅ | ⚠️ | ❌ |
| Overprivileged tools, auto-approve in MCP server entries and agent settings | ✅ | ❌ | ❌ | ❌ | ⚠️ |

Each row names what the engine checks today. The code-behavior rows (dangerous capabilities, data
exfiltration, dynamic code execution, decode-and-execute) cover Python and JavaScript/TypeScript;
shell, PowerShell and batch scripts are checked for download-and-run, decode-and-run, evasion and
post-exploitation idioms. Code in other languages gets only the secret, sensitive-path and
hidden-text checks (see [Limitations](#limitations)). Bidi controls and lone zero-width
characters are listed for review and left out of the score, because locale and CJK files use them
legitimately.

A VS Code extension usually ships one minified bundle as its entry point. SkillTotal reads it (up
to 8 MiB) and judges it like build output: capabilities and the post-exploitation rules count,
while other risk findings in the bundle go to `needs_review`, because a bundle carries the code of
every dependency.

## Typical findings

- An MCP tool can execute arbitrary shell commands
- A package downloads and runs code from an external URL, for example in an npm install script
- Access to credential locations (`~/.aws`, `~/.ssh`, `.env`) detected
- Dynamic code execution (`eval` / `exec`) detected
- Prompt-injection / instruction-override phrasing in a tool description or skill
- Sensitive-data access combined with outbound network egress
- Hardcoded API keys or tokens
- An MCP server with auto-approved or overprivileged tools
- An MCP tool annotated `readOnlyHint: true` whose handler writes or deletes files, runs a
  process or sends a POST/PUT/PATCH/DELETE request, or annotated `destructiveHint: false` whose
  handler deletes files or sends a DELETE request (`ST-MCP-ANNOTATION-MISMATCH`). Clients read
  these hints to decide which calls run without asking.
- Untrusted input (environment, `sys.argv`, a request/response body) flowing into `exec` or a
  shell: a traced path, not just a dangerous API in isolation
- Code that opens a way into the machine (a reverse tunnel to the local SSH port, a key written
  into `authorized_keys`) and makes itself start again after a reboot: two post-exploitation
  steps in one component combine into `ST-POSTEX-CHAIN`
- An **agent skill** whose bundled code does more than its declared `allowed-tools` cover. The
  field pre-approves tools and does not limit the skill's code, so a narrow list can make a skill
  look safer than it is.

## Verdict

Every report has a one-line verdict next to the score: `Malicious indicators found` whenever a
malicious indicator fired, whatever the score; `High risk - review before installing` or
`Critical risk - review before installing` for a high or critical score without one;
`Some risk - review before installing` for a medium score; and, for a low score, wording that
says what was found ("No significant risks found", "No malicious
indicators - review capabilities before installing", ...). A low verdict never sounds clean over
code that was not read: it reads `Partially analyzed - ...` when the component ships code in a
language whose behavior is not analyzed, or code files that were not read
(`Partially analyzed - 2 code files not read (2 minified)`), and `Not analyzed - nothing in this
component could be read` when nothing could be read. That wording does not change the score.

## Limitations

- **Files over 2 MiB are not read**, and minified JavaScript/TypeScript bundles are listed but not
  analyzed. Two kinds of file are read even when minified: the scripts npm runs at install (also
  when filed in a skipped folder) and the entry points a `package.json` names (`main`, `module`,
  `browser`, `bin`, `exports`). A VS Code extension's entry points are read up to 8 MiB. A low
  verdict over unread code reads "Partially analyzed", and the report counts the files in
  `verdict.unanalyzed_files`.
- **Dependency and environment folders are skipped:** `node_modules/`, `vendor/` (and
  `vendored-*`), Python virtual environments and installed `site-packages`, and in a repository
  (not a published package) the build output in `dist/` and `build/`. Code the component loads
  from those folders by a literal path (a relative `require`/`import`, a Python import, a
  `package.json` or `pyproject.toml` entry point) is read anyway. A package it loads by name (a
  bundled dependency in its own `node_modules/`) is not. A loaded file that cannot be read there
  (a native addon, a file over 2 MiB, one you excluded with `--exclude`) gets a `needs_review`
  note saying it was not analyzed.
- **Dependencies are not scanned.** A scan covers the component's own files, not what it installs.
- **Code that is not in the files is not analyzed:** code fetched or generated at run time, and
  binaries or compiled artifacts (counted in `metadata.files_skipped_binary`).
- **Languages.** Shell execution, network access, file access and dynamic code are analyzed in
  Python and JavaScript/TypeScript. Shell, PowerShell and batch scripts are checked for
  download-and-run, decode-and-run, evasion and post-exploitation idioms. Go, Rust, Java, Ruby, PHP, C/C++, C#, Swift,
  Kotlin, Scala, Dart, Lua, Perl, Elixir, Groovy, Haskell, Clojure, Erlang, R and Zig files get only
  the secret, sensitive-path and hidden-Unicode checks; the report adds a `needs_review` note, and
  a low verdict reads "Partially analyzed". See
  [docs/language-scope.md](https://github.com/pezhik/skilltotal/blob/main/docs/language-scope.md).
- **Symbolic links and junctions** in a scanned folder are not followed, and links inside an
  archive are not extracted.
- **The default gate does not count unread code, and unread code never passes in silence.**
  `--fail-on` (and the action's `fail-on`) pass a component with code the scan could not analyze,
  unless you add `--fail-on-unanalyzed` (action: `fail-on-unanalyzed: 'true'`). Either way the log
  says `Not everything was analyzed: ...`, the report carries a coverage note naming the files, and
  a low verdict reads "Partially analyzed". Compiled code shipped without its source (a `.pyc`,
  `.pyo` or `.class` with no `.py` or `.java` of the same name beside it) is one such gap:
  bytecode is never read, so a payload shipped only as bytecode is reported as not analyzed.
- **Detection is at the call/import level.** A capability used through an *unrecognized*
  higher-level library (a git library that writes files internally, a browser library) may not be
  flagged as a raw filesystem/shell call. Capabilities indicate *presence*, not proven misuse.

## Out of scope

SkillTotal statically analyzes a **single component's own files**. It does not execute code,
observe runtime behavior, or assess your environment, deployment, or infrastructure. It is **not**
a substitute for:

- a penetration test
- an application-security (app-sec) review
- an architecture / design review
- a cloud-security or infrastructure assessment
- a Kubernetes / container runtime audit
- a business-logic review
- a manual code review

## Accuracy notes

- Python is analyzed via an **AST** (resolves import aliases, tells `open(p,'w')` from a
  read, ignores API names that only appear in strings/comments). Node.js/config use regex.
  The AST parser comes from the Python interpreter that runs the scan, and a file written in
  newer syntax than it understands falls back to regex and is listed for review, so run the scan
  on the newest Python you can.
- **Test code** (`__tests__/`, `*.test.*`, `tests/`, `conftest.py`, …) is demoted to
  `needs_review`: it is not executed by consumers, so it does not affect the score.
- Ambiguous signals (bare `secrets`/`credentials` words, lone base64 blobs, "before
  answering" phrasing, minified files) go to `needs_review`, never to `findings`.
- **Hidden Unicode** (ASCII-smuggling tag characters, variation selectors and invisible math
  operators used as bytes, zero-width characters threaded through words, Hangul filler
  identifiers) is detected; where it encodes text, that text is decoded into the evidence.
  Trojan-Source bidi overrides and lone zero-width characters go to `needs_review`. Attackers
  use hidden text to smuggle instructions past human review. See `tests/manual_eval/` for
  calibration against real-world attacks.
- Shell execution covers `subprocess`/`os.system`, `asyncio.create_subprocess_*`, Node
  `child_process`, and common process-spawning libraries (Python `sh`/`plumbum`/`pexpect`/
  `invoke`/`fabric`; Node `zx`/`execa`/`cross-spawn`/`shelljs`/`tinyexec`/`node-pty`).
- MCP dangerous tools are classified by name/description both in JSON manifests **and when
  defined in code** (`server.tool("run_command", …)`, `@mcp.tool` over `def read_file`).
- **MCP tool annotations** are checked against the tool's handler: TypeScript/JavaScript
  `server.registerTool(name, { annotations }, handler)` and `server.tool(name, …, annotations,
  handler)`, Python `@mcp.tool(annotations=…)` (a dict or `ToolAnnotations(…)`) and
  `mcp.add_tool(fn, annotations=…)`. The annotations can be inline or a constant of the same file;
  the handler can be inline, the decorated function, or a function of the same file passed by
  name. Only the handler's own body is read. A call it makes to a helper function is not followed,
  in the same file or another, so a write done in a helper is not reported against the
  annotation (the write itself is still reported as a filesystem write). A missing
  `destructiveHint` is never reported: the MCP specification defaults it to true. Annotations a
  server builds at run time (a helper that returns them, a low-level `tools/list` handler) are not
  read.
- SARIF, JSON and baseline files that SkillTotal wrote into the scanned folder are recognised by
  their content, listed in `needs_review` and not scanned (their rule descriptions quote detection
  patterns).
