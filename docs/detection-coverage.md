# Detection coverage — malware archetypes → engine rules

This maps the common real-world malicious-package archetypes (as catalogued by the
[OSSF malicious-packages](https://github.com/ossf/malicious-packages) dataset and supply-chain
incident reports) to the SkillTotal rules that detect them. It documents *what the engine
already covers* and is exercised by the in-repo fixtures under `tests/manual_eval/malicious/`
(see `tests/test_offline_calibration.py`, the offline detection floor).

> **Why fixtures, not the OSSF packages directly:** OSSF stores OSV *metadata only* (hashes,
> IOCs, advisories) — **no code** — and the packages themselves are pulled from npm/PyPI after
> detection. So they cannot be fetched and scanned (`CollectionError → skipped`). The reliable,
> deterministic way to prove coverage is sanitized in-repo fixtures modelled on each archetype,
> exercised offline by `tests/test_offline_calibration.py`.

## Archetype → rules

| Archetype | Engine rules | Fixture |
|---|---|---|
| **Install-time execution** (npm pre/post/install, `setup.py`/cmdclass) | `ST-INSTALL-NPM`, `ST-INSTALL-NPM-PREPARE`, `ST-INSTALL-PY` | `npm-postinstall-exfil`, `pypi-typosquat-dropper` |
| **Import-time / second-stage download-and-execute** | `ST-OBF-DECODE-EXEC` (malicious), `ST-DYN-PY`/`ST-DYN-NODE`, `ST-NET-PY`/`ST-NET-NODE` | `pypi-typosquat-dropper`, `pypi-importtime-stealer` |
| **Credential / secret exfiltration** (read `~/.aws`, `~/.ssh`, `.env` → POST; the path written out or joined onto the home directory) | `ST-COMBO-EXFIL` (critical), `ST-SENS-PATH`/`ST-SENS-PATH-PY`, `ST-FS-*-READ` + `ST-NET-*` | `npm-postinstall-exfil`, `npm-trapdoor-stealer` |
| **Obfuscation** (base64/hex/codecs decode → `exec` / `eval` / `new Function`, directly or through a variable) | `ST-OBF-DECODE-EXEC` (malicious); heuristics `ST-OBF-BASE64-BLOB`/`ST-OBF-HEX`/`ST-OBF-MINIFIED` (needs_review) | `pypi-importtime-stealer` |
| **Decrypt-and-execute** (symmetric-decrypt → dynamic-code sink in one file) | `ST-OBF-DECRYPT-EXEC` (malicious) | `decrypt-and-execute` |
| **Unsafe deserialization** (pickle/marshal/dill loader) | `ST-DESERIALIZE-PY` | `py-marshal-loader` |
| **Deserialize-and-execute dropper** (`exec(marshal.loads(<remote>))`) | `ST-OBF-DECODE-EXEC-PY` (malicious) | `py-marshal-loader` |
| **Shell / command execution & injection** | `ST-SHELL-PY`/`ST-SHELL-NODE`, `ST-CMDI-PY`/`ST-CMDI-NODE` | `pypi-typosquat-dropper` |
| **Hidden-Unicode / Trojan-Source instruction smuggling** (tag characters, variation-selector or invisible-operator payloads, Hangul-filler identifiers, ANSI that hides agent-facing text) | `ST-HIDDEN-UNICODE`, `ST-HIDDEN-ANSI` (malicious); `ST-HIDDEN-UNICODE-AMBIG` (needs_review) | `zero-width-injection` |
| **Prompt injection / instruction override** | `ST-PROMPT-INJECTION` (malicious); `ST-PROMPT-WEAK` (needs_review) | `agent-instruction-override` |
| **MCP tool poisoning** (agent-directed instructions in tool metadata) | `ST-MCP-TOOL-POISONING` (malicious); `ST-MCP-DANGEROUS-TOOL`, `ST-MCP-SERVER-EXEC`, `ST-MCP-AUTO-APPROVE`, `ST-MCP-TOOL-SHADOWING` | `mcp-tool-poisoning` |
| **MCP sampling abuse** (server-written prompt asks the client's model for credentials or a command, and for silence) | `ST-MCP-SAMPLING-INJECTION` (malicious) | `mcp-sampling-injection` |
| **MCP concealed launcher** (server command launches a script hidden under ≥2 dot-directories) | `ST-MCP-SERVER-HIDDEN-EXEC` (malicious) | `mcp-hidden-dotpath-launcher` |
| **node-gyp install-time substitution** (`binding.gyp` `<!(…)` running hidden commands) | `ST-INSTALL-GYP` (malicious) | `gyp-command-substitution` |
| **Auto-run agent / editor configuration** (Claude/Gemini/Cursor hooks, VS Code folder-open tasks) | `ST-AGENT-AUTORUN` (risky), `ST-AGENT-AUTORUN-REMOTE` (malicious), `ST-AGENT-CLI-BYPASS` (risky) | `agent-config-autorun` |
| **Password-protected payload download** | `ST-ARCHIVE-PASSWORD-EXTRACT` (malicious) | `password-archive` |
| **Network/debug exposure** | `ST-EXPOSE-BIND`, `ST-EXPOSE-DEBUG` | — |
| **Shell decode-and-execute / remote pipe-to-shell in a shell script** (`… base64 -d \| bash`, `curl \| bash` in `.sh` and other shell files) | `ST-OBF-DECODE-EXEC-SH` (malicious), `ST-SHELL-PIPE-EXEC` | `sh-base64-exec` |
| **npm lifecycle script that fetches or decodes code and runs it** (`"preinstall": "curl … \| bash"`, `node -e "eval(Buffer.from(…,'base64')…)"`) | `ST-INSTALL-NPM-REMOTE-EXEC` (malicious) | `npm-lifecycle-remote-exec` |
| **Remote pipe-to-shell handed to a shell call** (`os.system("curl … \| bash")`, `execSync("curl … \| sh")`) | `ST-SHELL-PIPE-EXEC-PY`, `ST-SHELL-PIPE-EXEC-NODE` | — |
| **Analysis evasion** (password-protected archive bundled in a component) | `ST-ENCRYPTED-ARCHIVE` | — |
| **Instruction-driven exfiltration** (lethal trifecta: injection + file read + egress) | `ST-FLOW-TRIFECTA` | — |
| **Stacked malicious indicators** (deception + payload in one component) | `ST-CONVERGENCE` | — |
| **`.pth` startup persistence** (auto-exec on interpreter start) | `ST-PTH-EXEC` (malicious) | `pypi-pth-backdoor` |
| **Defense-evasion idioms** (PS bypass/-enc, codesign, run-from-temp) | `ST-SHELL-EVASION` | — |
| **Install-time dropper** (lifecycle hook + decode-exec / credential payload) | `ST-INSTALL-DROPPER` | `npm-postinstall-exfil` |
| **Over-broad MCP scope** (wildcard / full-access permission) | `ST-MCP-OVERBROAD-SCOPE` | — |
| **MCP tool that misstates its annotations** (`readOnlyHint: true` over a handler that writes, deletes, sends a PUT/PATCH/DELETE request, or runs a command it is handed or one that changes things; `destructiveHint: false` over one that deletes) | `ST-MCP-ANNOTATION-MISMATCH` (risky) | `tests/eval_corpus/rules/ST-MCP-ANNOTATION-MISMATCH/` |
| **E-mail/SMTP credential exfiltration** (read secret → e-mail it out) | `ST-COMBO-EXFIL` via smtplib/nodemailer egress | `py-email-stealer` |
| **Mail backdoor** (hardcoded BCC/CC copies outgoing mail) | `ST-EMAIL-BCC-EXFIL` | — |
| **CI-token exfiltration from a composite action** (a `run:` step sends `GITHUB_TOKEN` / a `${{ secrets.* }}` to a non-GitHub host) | `ST-ACTION-SECRET-EXFIL` (malicious) | — |
| **Trojanized editor extension / SSH backdoor** (a loader in an extension's bundle or a package's install script opens a reverse tunnel to the local SSH port, plants a key, adds an autostart entry) | `ST-POSTEX-CHAIN` (malicious), `ST-POSTEX-REMOTE-ACCESS`, `ST-POSTEX-PERSIST`; `ST-POSTEX-MASQUERADE` (malicious) when the autostart entry is named after the OS vendor | `vscode-ssh-backdoor-vsix`, `vscode-ssh-backdoor-folder`, `shell-ssh-backdoor`, `python-ssh-backdoor` |
| **Reverse shell at install or reboot** (`bash -i >& /dev/tcp/...`, `nc -e`, a socket duplicated onto stdin/stdout, a cron `@reboot` line) | `ST-POSTEX-REMOTE-ACCESS`, `ST-POSTEX-PERSIST` → `ST-POSTEX-CHAIN` | `npm-postinstall-reboot-revshell` |
| **Tunnel client with an embedded credential** (`cloudflared --token`, `ngrok authtoken`, `code tunnel`) plus a Run key or shell-profile entry | `ST-POSTEX-REMOTE-ACCESS`, `ST-POSTEX-PERSIST` → `ST-POSTEX-CHAIN` | `python-cloudflared-runkey`, `node-code-tunnel-zshrc` |
| **Security controls switched off** (antivirus exclusions, Gatekeeper or quarantine stripped, history and logs cleared) | `ST-POSTEX-EVASION`, `ST-SHELL-EVASION`; `ST-POSTEX-MASQUERADE` (malicious) for a task named after the OS vendor | `vscode-ps-defender-exclusion-task` |
| **Host beacon** (host name, user name, secret env-var names or the public IP sent to a server) | `ST-POSTEX-BEACON` | `python-ssh-backdoor`, `vscode-ssh-backdoor-vsix` |

The post-exploitation samples live in `tests/eval_corpus/positive/AST01/post-exploitation/`, with
honest look-alikes (a CLI that installs its own LaunchAgent, a dotfiles installer, a devcontainer
feature that enables sshd, a security tool's signature list) under `negative/` that must stay
below a malicious verdict. How tactics combine into `ST-POSTEX-CHAIN` is in
[scoring.md](scoring.md#post-exploitation-tactics).

Only `malicious_indicator` rules drive the "malicious" verdict; `risky_construct` rules raise
risk; `exposure` rules (`ST-SECRET-EMBEDDED`, `ST-ENV-SHIPPED`) report a credential the component
ships without scoring it; `capability` rules are informational (capability ≠ risk).

## Measured efficacy (recall / precision)

Coverage above is also **measured**, not just asserted. `tests/eval_corpus/` holds a labeled
offline corpus of synthetic samples — `positive/` (malware that must be flagged) and `negative/`
(benign look-alikes that must stay clean) — one technique per directory. The harness
`tests/manual_eval/efficacy.py` runs the static engine over it and computes recall (overall + per
technique + per OWASP class), precision / false-positive rate, and a per-language coverage matrix;
`tests/test_efficacy_floor.py` enforces **100% recall** and **zero false positives** on every
commit (alongside the smoke floor in `tests/test_offline_calibration.py`). The current numbers and
the coverage matrix are published in `docs/efficacy-report.md`.

Recall is per sample, so it cannot measure a rule that does not flag a sample on its own, such as
a capability rule. The report also has a rule coverage table: for each rule mapped to an OWASP class,
the samples it fired on, plus labeled per-rule samples under `tests/eval_corpus/rules/<rule>/`
(`fires/` must trigger the rule, `silent/` must not). Every rule behind an OWASP class count in
`docs/mcp-registry-survey.md` has such samples, and the floor test holds them to their
expectation.

Detection depth varies by language (Python AST + Node/TS/shell regex + cross-language signals; Go/
Rust/Java/Ruby/PHP semantic exec/network/deser is a documented gap). See `docs/language-scope.md`.

## Known gaps (candidate rule improvements)

- **`exec(marshal.loads(<remote>))` / `exec(pickle.loads(...))`** — CLOSED (ruleset 14): the
  remote-deserialize-then-exec dropper used to score only *low* (`ST-DESERIALIZE-PY` +
  `ST-DYN-PY`, no malicious indicator). The new `ST-OBF-DECODE-EXEC-PY` malicious-indicator rule
  (AST-based, alias-aware, non-literal-payload guard) now flags `exec`/`eval`/`compile` of a
  `pickle`/`marshal`/`dill`/`jsonpickle` load and supersedes `ST-DESERIALIZE-PY` on the same node.
  Fixture `py-marshal-loader`; calibrated benign FP = 0.
- **Obfuscated natural-language injection** — CLOSED (ruleset 11): instruction-override and
  tool-poisoning phrases hidden behind homoglyphs, full-width, diacritics, or zero-width-in-word
  are now de-obfuscated before matching (`skilltotal.text_normalize`). Still out of scope for the
  free static engine (and deferred to the paid SkillTotal Cloud): semantic paraphrase and arbitrary
  *non-English* natural-language understanding — those need an LLM, not a keyword list.
