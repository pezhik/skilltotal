# Ruleset changelog

Tracks changes to the **detection ruleset**, keyed by `RULESET_VERSION`
(`skilltotal/__init__.py`). A consumer that stored reports at an older ruleset version may
re-scan to pick up newer findings. See `docs/contributing-rules.md` for the process.

## ruleset 23 (engine 0.22.0)

**Evasion hardening — three detector bypasses closed, FP-safe.** The new detection-efficacy
benchmark (`tests/eval_corpus/` + `tests/manual_eval/efficacy.py`) probes realistic evasion variants
with non-literal payloads; three genuine misses were found and fixed (each verified to keep the FP
floor and benign corpus at zero false positives):

- **base64 module-alias decode-exec.** `import base64 as b; exec(b.b64decode(<remote>))` evaded the
  decode-exec regex, which required a literal `base64.` prefix or a bare `b64decode`. The
  `_DECODE_EXEC` pattern in `obfuscation.py` now accepts an optional `\w+\.` alias prefix before
  `b64decode` (a method literally named `b64decode` is essentially always base64). `from base64
  import b64decode`, hex (`bytes.fromhex`) and `codecs.decode` forms already detected.
- **indirect eval.** `(0, eval)(atob(<remote>))` / `(0, eval)(Buffer.from(...))` dodged the literal
  `eval(` token; a new `_DECODE_EXEC` alternative matches the `(0, eval)(decode(` idiom.
- **concatenation-built credential paths.** `os.path.expanduser('~') + '/.aws/credentials'` and
  `os.environ['HOME'] + '/.ssh/id_rsa'` never appear as a single `open()` argument, so the AST
  sensitive-path rule (literal-arg only) missed them and the credential-exfil combo did not fire. A
  new `visit_BinOp` in `python_ast.py` flags a strong credential-path string literal used as an
  operand of `+` → `ST-SENS-PATH-PY`, restoring `ST-COMBO-EXFIL`. A bare literal, a list element, or
  a comparison is not a `BinOp`, so the ruleset-20 denylist/guardrail FP fix is preserved.

Tests: `tests/eval_corpus/positive/AST01/{decode-exec,credential-exfil}/*evasion*`, gated by
`tests/test_efficacy_floor.py` (recall 100%, FP 0).

## ruleset 22 (engine 0.21.0)

**Inline Rust test code is demoted, like path-based test code (no detection removed).** Rust unit
tests are written in the same `.rs` file as production code, gated by `#[cfg(test)]` (on a module)
or `#[test]` (on a function). That code compiles only under `cargo test` and is never part of the
shipped artifact, so a credential-shaped string there — a fake `sk-…`/`xoxb-…` key, a
`~/.ssh/id_rsa` path — is a fixture, not behavior. The path-based `is_test_path` cannot see it
(the file is a normal source path). New `file_index.py` helpers locate those spans
(`_rust_test_spans`, exposed as `IndexedFile.in_rust_test`), masking comments / strings / char
literals first so braces and the word `test` inside them do not skew matching; `#[cfg(not(test))]`
(code compiled when *not* testing) is deliberately not matched. `engine.py::_split_test_evidence`
now treats evidence inside those spans as test evidence and routes it to `needs_review`, before
capability extraction and the synthesized combos. Consequence on the trusted corpus: **tandem**
drops from `critical` (90) to `medium` — its `ST-SECRET-EMBEDDED` and the resulting
`ST-COMBO-EXFIL` came entirely from fake keys in `#[test]` functions (redaction/keystore/slack
tests) — and **codescene** drops from `high` (70) to `low` — its `ST-SENS-PATH` + `ST-COMBO-EXFIL`
came from a fake `"secret token=abc123 …/.ssh/id_rsa"` string inside a `#[test]` error-formatting
test. Genuine secrets/paths in production Rust still fire (counter-fixtures + offline floor).
Also fixed: `ST-SECRET-EMBEDDED` evidence now keeps its match offset through snippet redaction, so
the string/comment and inline-test demotion gates can locate embedded secrets. Tests:
`tests/test_context_demotion.py`, fixtures `fp_rust_inline_test_secret` / `fp_rust_prod_secret`.

## ruleset 21 (engine 0.20.0)

**Cloud instance-metadata endpoints no longer feed the exfiltration combo.** A reference to a
cloud metadata endpoint (`169.254.169.254`, `metadata.google.internal`) is itself a *network*
call that fetches a token — the legitimate managed-identity auth path used by Azure/AWS/GCP SDKs
— not a local credential-file read. Counting it as the "read a secret" side of `ST-COMBO-EXFIL`
double-counted one fetch and mislabeled normal cloud auth as a credential-exfiltration path
(e.g. the official `openai` npm SDK's Azure workload-identity auth read as `high` / exfil).
`scoring.py::exfiltration_finding` now excludes metadata-endpoint evidence from the sensitive-data
side; the endpoint still fires as its own `ST-SENS-PATH` finding (an SSRF / token-theft surface),
and a genuine credential-FILE read (`~/.ssh`, `.aws/credentials`) plus network still synthesizes
the combo. Test: `tests/test_flow_and_convergence.py`.

## ruleset 20 (engine 0.19.0)

**False-positive calibration: context demotion for inert/defensive code (no detection removed).**
Five real-world FP classes were over-scoring legitimate components (and, in one case, mislabeling a
benign tool `malicious`). Each is fixed by demoting evidence in a non-behavioral context to
`needs_review` — the genuine attack shape still fires, guarded by the offline detection floor.

- **Data/eval/benchmark corpus demotion.** New `is_data_corpus_path` (`file_index.py`) + gate
  `_split_data_corpus_evidence` (`engine.py`): a pattern that appears only in an inert corpus *data*
  file (`eval_datasets/poisoning.yaml`, `fixtures/*.json`, `benchmarks/…`) is a detector test
  vector, not behavior. Restricted to non-code suffixes, so a real payload shipped as code in such a
  directory is still scanned. This stops a prompt-injection sample in an eval dataset from raising
  `ST-PROMPT-INJECTION` and falsely verdicting the component `malicious`.
- **Shell-comment demotion.** Code-context demotion now covers shell `#` comments
  (`IndexedFile.in_shell_comment`, `_is_noncode_context`); `ST-SHELL-PIPE-EXEC` set to
  `code_context="comments"`. A `# Usage: curl … | bash` install instruction is no longer a runnable
  remote pipe-to-shell.
- **C-family comment demotion + defensive phrasing.** Code-context demotion also covers `//` and
  `/* */` comments in C-family files (`.ts/.js/.go/.rs/…`, `IndexedFile.in_c_comment`), so security
  prose in a code/JSDoc comment (e.g. `* exfiltrate authorization codes to it`) is a description,
  not behavior. Strings are NOT demoted there (real access is a string argument). `ST-PROMPT-INJECTION`
  also gained negative-lookbehinds for defensive phrasing (`refuse/refusing/refuses to send
  credentials to …`). Fixes the official MCP TypeScript SDK being mislabeled `malicious`.
- **Sensitive-path denylist/guardrail context.** `sensitive_paths.py` routes a strong credential
  path to `needs_review` when it appears in a denylist/guardrail context: a `policy`/`guard`/
  `security`/`sandbox`/`denylist` token in any path segment *or filename* (so `net_guard.rs`,
  `path_guard.rs` count), a deny/block/forbid keyword on the line, or a bare string-list element. A
  policy that *protects* `~/.ssh`/`id_rsa` is the opposite of accessing it; real access (a path
  passed to a read call) still fires. This also removes the spurious `ST-COMBO-EXFIL` it fed.
- **Localized-documentation recognition.** `is_doc_path` now splits a prose filename's stem on `.`
  as well as `-`/`_`, so a localized/variant doc (`README.zh-CN.md`, `CHANGELOG.fr.md`) is demoted
  like its base file instead of being scored as behavior.
- **Public Algolia DocSearch keys allowlisted.** `secrets.py` no longer flags a 32-hex search key
  sitting next to an Algolia app id / index name (a public, read-only key); routed to `needs_review`.
  Known-prefix provider keys (`AKIA…`, `sk-…`, …) are never allowlisted.
- **Compound test-tree demotion.** `is_test_path` now recognizes compound test directories
  (`cli-e2e-tests`, `integration-tests`, `unit_test`) via a `[-_]`-bounded suffix match, so
  command-injection in e2e test helpers is demoted like other test code (`latest` etc. excluded).

Tests: `tests/test_context_demotion.py` (demote + counter-fixture per class),
`tests/test_offline_calibration.py` (`MUST_NOT_BE_ELEVATED` floor + unchanged `MUST_DETECT` gate),
sanitized fixtures under `tests/fixtures/fp_*`.

## ruleset 19 (engine 0.18.0)

**Package-name typosquatting (deterministic, no LLM).** Closes the one named parity gap from the
competitive analysis: a package whose name impersonates a popular one.

- **`ST-TYPOSQUAT`** (`skilltotal/typosquatting.py`; risky_construct, high): an npm/PyPI component
  whose (canonicalized) name is 1–2 Levenshtein edits from a curated set of widely-used packages
  (~100 per ecosystem), e.g. `loddash`/`lodash`, `reqests`/`requests`. Synthesized in `engine.py`
  off component identity (not file content), with evidence anchored to the `name` field in
  `package.json`/`pyproject.toml`/`setup.py` so the no-finding-without-evidence invariant holds.
  Maps to **AST02** (Supply Chain Compromise). FP-safe by construction: exact matches, scoped npm
  names (`@scope/…`), and names shorter than 5 chars are never flagged, and distance-2 matches
  require length ≥ 6. The curated popular-name lists are refreshed alongside this ruleset version.
  Tests: `tests/test_typosquatting.py`.

## ruleset 18 (engine 0.17.0)

**OWASP Agentic Skills Top 10 mapping (metadata only — no detection change).** Each rule id is
mapped to its OWASP Agentic Skills Top 10 category/categories (`skilltotal/owasp.py`,
`OWASP_BY_RULE`), projected onto findings as `Finding.owasp` and emitted in SARIF taxonomies. No
detection logic, scoring, or rule pattern changed; the bump signals that stored reports can be
re-read to pick up the new taxonomy field. Coverage maps to AST01–AST05 where statically honest;
AST06–AST10 (runtime/governance) and classic code-level findings (CMDI/taint/raw capabilities) are
intentionally unmapped (empty), never forced. See `docs/owasp-agentic-skills-mapping.md`.

## ruleset 17 (engine 0.16.0)

**E-mail/SMTP exfiltration channel (deterministic, no LLM).** Closes the gap where a component
that reads secrets and e-mails them out was invisible to the exfiltration combos (egress was
HTTP-only). Motivated by the Postmark MCP BCC-exfil backdoor.

- **E-mail-send → `NETWORK_EGRESS`.** Python (`scanners/python_ast.py`): `smtplib` added to
  `NETWORK_HEADS` + `ST-NET-PY` regex. Node (`scanners/network.py`): `ST-NET-NODE` extended with
  `nodemailer`, `.sendMail(`, `@sendgrid/mail`, `SendEmailCommand` (AWS SES v3), `mailgun`.
  `ST-COMBO-EXFIL` / `ST-FLOW-TRIFECTA` consume `NETWORK_EGRESS`, so they now fire on email exfil
  with no further change. FP-safe: email-send alone stays a 0-weight capability; it only elevates
  combined with sensitive-data access.
- **`ST-EMAIL-BCC-EXFIL`** (`scanners/email_exfil.py`; risky_construct, medium): in a file that
  sends email, a `bcc`/`cc` field assigned a hardcoded string-literal address (e.g.
  `bcc: "phan@giftshop.club"`). Catches the Postmark-style constant-BCC backdoor even with no
  credential read. Dynamic recipients (`bcc: userInput`) and a bcc literal in a non-email file are
  not flagged.

Fixture: `py-email-stealer` (reads `~/.aws` + `smtplib` → `ST-COMBO-EXFIL` via email; offline floor).

## ruleset 16 (engine 0.15.0)

**Real-world supply-chain attack signatures + MCP/OWASP coverage (deterministic, no LLM).**
Driven by recent compromises (auto-exec `.pth` credential stealers, postinstall RATs, MCP backdoors).

- **`ST-PTH-EXEC`** (`scanners/pth_exec.py`; malicious_indicator, high): a `.pth` file that
  decodes / deserializes / spawns / networks (`base64`/`b64decode`/`bytes.fromhex`/`codecs.decode`/
  `subprocess`/`os.system`/`os.popen`/`marshal`/`pickle`/`socket`/`urllib.request`/`requests.`).
  Python executes `.pth` `import` lines at every interpreter startup → stealthy persistence/auto-exec.
  A bare `exec`/`eval` is intentionally NOT flagged: coverage.py's subprocess bootstrap legitimately
  does `exec('… coverage.process_startup() …')` (calibration FP). Editable-install / namespace
  `.pth` files (bare `import`, finder `.install()`) also stay clean.
- **`ST-SHELL-EVASION`** (`scanners/shell_evasion.py`; risky_construct, high): defense-evasion
  idioms over script/code files — PowerShell `-ExecutionPolicy Bypass` / `-EncodedCommand` /
  `-WindowStyle Hidden`, `codesign … --force … --deep`, `nohup … /tmp/…`, `chmod +x … /tmp|/dev/shm`,
  `IEX (… DownloadString)`. Scoped so `grep -w hidden` / plain `chmod +x` don't match.
- **`ST-INSTALL-DROPPER`** (synthesized in `scoring.py`; risky_construct, high): an install/build
  hook (`ST-INSTALL-NPM`/`-NPM-PREPARE`/`-PY`) co-occurring with a decode-and-execute payload
  (`ST-OBF-DECODE-EXEC`/`-PY`/`-SH`) or credential access (`ST-SENS-PATH`/`-PY`). FP-safe: the hook
  alone is a neutral capability.
- **`ST-MCP-OVERBROAD-SCOPE`** (`scanners/mcp.py`; risky_construct, medium): a manifest declaring a
  wildcard / over-broad permission/scope (`*`, `full_access`, `mail.full_access`, `read_write_all`).
- **`ST-SENS-PATH`** path set expanded: Docker `config.json`, `~/.azure`, `.git-credentials`,
  `application_default_credentials.json`, cloud-metadata IP `169.254.169.254`, crypto keystores
  (`wallet.dat`, `.ethereum/keystore`, `~/.config/solana`) — strengthens `ST-COMBO-EXFIL` recall.

Fixtures: `pypi-pth-backdoor` (offline floor). New CLI/MCP-doc work doesn't change the report shape.
Calibrated benign FP = 0. `docs/mcp-owasp-mapping.md` documents OWASP MCP coverage + runtime gaps.

## ruleset 15 (engine 0.14.0)

**Breadth, data-flow, and convergence (all deterministic, no LLM).**

- **Shell-script scanner** (`scanners/shell_script.py`; `.sh`/`.bash`/`.zsh` + shebang scripts):
  `ST-OBF-DECODE-EXEC-SH` (malicious_indicator, high) — decode-and-execute idioms
  (`… base64 -d | bash`, `eval "$(… base64 -d)"`); `ST-SHELL-PIPE-EXEC` (risky_construct, high) —
  remote pipe-to-shell (`curl/wget … | sh`). `sh` is matched without catching `ssh`.
- **`ST-ENCRYPTED-ARCHIVE`** (`scanners/encrypted_archive.py`; risky_construct, medium): a
  password-protected ZIP (GP-flag bit 0) bundled in a component is a scanning-evasion signal.
  Inspects archives directly from the component root (they are binary, so the text index skips
  them). Conservative (risky, not malicious) so it never trips the benign false-positive gate.
- **`ST-FLOW-TRIFECTA`** (synthesized in `scoring.py`; risky_construct, high): the lethal trifecta
  — a confirmed prompt-injection surface + filesystem-read + network egress in one component.
  Requires an actual `ST-PROMPT-INJECTION` finding (not mere capability) and is suppressed when the
  credential-specific `ST-COMBO-EXFIL` already fired, so it stays false-positive-free.
- **`ST-CONVERGENCE`** (synthesized in `scoring.py`; risky_construct, high): elevates a component
  when ≥2 distinct malicious-indicator rules co-occur. False-positive-free by construction (a
  benign component has zero malicious indicators).
- **`ST-PROMPT-INJECTION`** extended with jailbreak / safety-disable directives ("do anything now",
  "disable your safety filters", "ignore all safety guidelines") via the existing de-obfuscation
  pass; objects are safety-specific so security prose is not matched.
- **`ST-SKILL-CAP-MISMATCH`** severity MEDIUM → HIGH (calibrated benign FP = 0 on a 16-skill
  corpus).

Fixtures: `sh-base64-exec` (offline floor). New CLI/config features (`--fail-on`,
`--fail-on-score`, `--exclude`, `.skilltotal.toml`, inline `# skilltotal:ignore`) do not change
detection rules and leave the report shape unchanged.

## ruleset 14 (engine 0.13.0)

**Deserialize-and-execute (deterministic, no LLM).** New malicious-indicator rule
`ST-OBF-DECODE-EXEC-PY` closes the documented gap where a remote `exec(marshal.loads(<remote>))` /
`exec(pickle.loads(...))` dropper scored only *low* (`ST-DESERIALIZE-PY` risky_construct +
`ST-DYN-PY` capability, no malicious indicator).

- Fires when a dynamic-exec call (`eval`/`exec`/`compile`) has, as its first positional argument,
  a call resolving to an unsafe deserializer (`pickle`/`cPickle`/`_pickle`/`dill`/`marshal`
  `.load`/`.loads`, or `jsonpickle.decode`/`.loads`) **and** that deserialize call's argument is
  non-literal (a constant payload is not a dropper — false-positive guard).
- `malicious_indicator`, severity high, capability `dynamic_code_execution` — same treatment as the
  language-agnostic `ST-OBF-DECODE-EXEC` (which only covered base64/hex/codecs decode chains).
- AST-based and alias-aware (`import marshal as m` → `m.loads`, `from pickle import loads`); the
  RuleSpec also carries a regex so files that fail `ast.parse` still flag via the fallback.
- On the same call node it supersedes the weaker `ST-DESERIALIZE-PY` (dropped via an id() set in
  `_CallVisitor`), so the construct is scored once; the capability `ST-DYN-PY` is left as-is.
- Lives in `skilltotal/scanners/python_ast.py` (alias resolution needs the AST scanner).
  Calibrated benign FP = 0. Fixture `tests/manual_eval/malicious/py-marshal-loader/`.

## ruleset 13 (engine 0.12.0)

**Agent Skill: declared-vs-actual capability mismatch (deterministic, no LLM).** A folder with a
`SKILL.md` is detected as an `agent_skill` component. New synthesized finding
`ST-SKILL-CAP-MISMATCH` compares the skill's declared `allowed-tools` against the capabilities its
bundled code actually exhibits.

- Fires only when the root `SKILL.md` declares a non-empty, non-wildcard `allowed-tools` list (an
  explicit least-privilege claim) AND a dangerous capability is exhibited that none of the declared
  tools grant.
- Capability → tool mapping: shell / install-time ← `Bash`; network ← `WebFetch`/`WebSearch`;
  filesystem write ← `Write`/`Edit`/`NotebookEdit`; dynamic code execution ← (no tool grants it).
  `filesystem_read` is intentionally not checked (benign / ubiquitous).
- `risky_construct`, severity medium (conservative start; may rise after calibration on a skills
  corpus). Evidence pairs the `allowed-tools` line with the offending capability's evidence.
- Synthesized in `skilltotal/agent_skill.py` after capabilities (mirrors `ST-COMBO-EXFIL`);
  registered in the rules registry so `rules list` / SARIF include it. Deterministic, component-only.

## ruleset 12 (engine 0.11.0)

**Intra-procedural taint / data-flow for Python (deterministic, no LLM).** Beyond the existing
"dynamic command" heuristic (`ST-CMDI-PY`), the AST scanner now tracks a value from an untrusted
SOURCE to a dangerous SINK within a single function body and reports a proven flow.

- Sources (v1, conservative): `os.environ` / `os.getenv` / `os.environ.get`, `sys.argv`,
  `input()`, a network response body (`requests`/`httpx`/`aiohttp` `.text`/`.content`/`.json()`),
  and the parameters of an MCP tool handler (a function decorated `@*.tool`).
- Sinks → finding (`risky_construct`, high): `eval`/`exec`/`compile` (`ST-TAINT-EXEC-PY`); a shell
  (`os.system`/`os.popen`/`subprocess(..., shell=True)`) (`ST-TAINT-SHELL-PY`); unsafe
  deserialization (`ST-TAINT-DESERIAL-PY`).
- Propagation is default-deny: assignments, f-strings, `+`/`%`, `str` methods (`.format`/`.join`/…)
  and literal containers carry taint; `shlex.quote`/`shlex.join`/`int()`/`float()` and
  re-assignment to a clean value clear it. Inter-procedural flow, attribute/container aliasing and
  closures are intentionally NOT tracked (false-positive control). Unparseable files get no taint
  (already flagged `needs_review`).
- `ST-TAINT-SHELL-PY` supersedes `ST-CMDI-PY` on the same node (the injection is scored once).
- The 0-weight capability findings (`ST-DYN-PY`/`ST-SHELL-PY`/`ST-DESERIALIZE-PY`) still fire for
  the sink itself; taint is the upgrade to a scored risk. Calibrated benign FP = 0.

## ruleset 11 (engine 0.9.0)

**De-obfuscation pass for instruction surfaces (deterministic, no LLM).** Attackers hide
instruction-override / tool-poisoning phrases from byte-for-byte regex by swapping Latin letters
for look-alikes (Cyrillic `а`, Greek `ο`), adding combining accents, using full-width forms, or
splicing zero-width characters mid-word — none of which changes what a model reads.

New module `skilltotal/text_normalize.py` (`normalize_with_map`) folds those away and returns an
index map so a match on the normalized text anchors back to the exact ORIGINAL span (evidence
invariant preserved). `scanners/base.py::deobfuscated_spans` runs a pattern over the normalized
text only for files that actually contain non-ASCII obfuscation (normalized == original → skipped,
so it's nearly free on ordinary repos).

- `ST-PROMPT-INJECTION` now also matches the strong phrases after normalization.
- `ST-MCP-TOOL-POISONING` / `ST-MCP-TOOL-SHADOWING` match manifest tool/parameter descriptions
  and code-defined tool surfaces after normalization (`_match_phrase`).
- Curated confusable table covers the common Cyrillic/Greek→Latin homoglyph set; only multi-word
  English phrases are matched, so folding does not create matches on genuine non-Latin text.
- Scope: deterministic only. Semantic paraphrase and arbitrary-language understanding stay in the
  paid Deep Analysis layer (open-core boundary). Calibrated benign FP = 0.

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
