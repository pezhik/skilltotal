# Changelog

All notable changes to the SkillTotal engine. Format loosely follows
[Keep a Changelog](https://keepachangelog.com); the project uses
[SemVer](https://semver.org). See `RULES_CHANGELOG.md` for detection-rule changes.

## [0.10.0]

### Added
- **Scan a project archive or a single file.** `scan <path>` now accepts, besides a directory,
  a project archive (`.zip`, `.tar.gz`/`.tgz`, `.tar`, `.tar.bz2`, `.tar.xz`) or a single code
  file — both are staged into a temp directory and analyzed by the same engine, then cleaned up.
  This brings AI-generated projects that don't live in a public git repo (e.g. a downloaded ZIP)
  into scope. Reuses the existing safe extractor (zip-slip guard, symlink rejection,
  decompression-bomb cap) and adds an archive entry-count cap. Project type is labelled
  (`go_project` / `java_project` / `project`) for the report header.
- Archive caps are env-overridable so a hosted upload path can tighten them:
  `SKILLTOTAL_MAX_ARCHIVE_MB`, `SKILLTOTAL_MAX_EXTRACT_MB`, `SKILLTOTAL_MAX_ARCHIVE_MEMBERS`.

No detection-rule changes (RULESET 11 unchanged); detection on the new sources uses the same rules.

## [0.9.1]

### Documentation
- **Coverage documentation.** README now states scope explicitly: a per-ecosystem coverage
  matrix (MCP / npm / PyPI / AI project), a typical-findings list, an out-of-scope section
  (SkillTotal is static analysis, not a pentest / app-sec / architecture / cloud review), and
  a one-paragraph methodology statement. No detection-rule or behavior changes (RULESET 11
  unchanged); the goal is that a reader understands in 30 seconds what the engine does and does
  not do.

## [0.9.0]

### Added
- **De-obfuscated instruction detection (no LLM).** Prompt-injection (`ST-PROMPT-INJECTION`)
  and MCP tool-poisoning (`ST-MCP-TOOL-POISONING`) are now matched after a deterministic
  Unicode-normalization pass — folding homoglyphs (Cyrillic/Greek look-alikes), full-width
  forms, combining diacritics, and zero-width-spliced characters — so instructions hidden
  behind look-alike characters are caught. Matches are mapped back to the exact original span,
  so evidence stays anchored to the real file/line. New module `skilltotal.text_normalize`.
  Pure stdlib + a curated confusable table (zero runtime deps); semantic/paraphrase and
  arbitrary-language understanding remain out of scope for the static engine. (RULESET 11.)

## [0.8.1]

### Fixed
- **Prompt-injection false positives on trusted packages.** The `ST-PROMPT-INJECTION`
  "ignore … above" pattern was too broad and flagged benign text — a minified Jupyter
  `notebook` bundle (`// IGNORE ABOVE ELSE`) and ruff's own suppression docs ("ignore above a
  multi-line statement"). It now requires an intent quantifier (`everything`/`all`) or an
  explicit instruction object, surfaced by the expanded calibration corpus. (RULESET 10.)

## [0.8.0]

### Added
- **Large-repository protection.** Git sources are size-bounded before/during clone: a GitHub
  API pre-check rejects oversized repos instantly, and a host-agnostic watchdog aborts a clone
  whose working tree grows past the cap (`SKILLTOTAL_MAX_CLONE_MB`, default 200) — no more hangs
  or OOM on huge repos.
- **Smart git URL parsing.** Browser URLs are understood: a branch/tag, a subfolder
  (`/tree/<ref>/<path>`), a file (`/blob/<ref>/<file>` → its folder), or a specific commit
  (`/commit/<sha>`) are scanned directly; non-code pages (`/issues`, `/pull`, …) are reduced to
  the repository root (default branch) with a note in the report.
- **`ST-SENS-PATH-PY` (AST).** Credential-location access in Python is detected structurally —
  a sensitive path passed to a filesystem/process/network call — so real reads are caught while
  a detector's own pattern literals are not (see RULES_CHANGELOG).

### Security
- **Hidden/deceptive Unicode neutralized in displayed snippets (Trojan-Source).** Evidence shown
  to a human renders bidi overrides, zero-width/format chars, Unicode tag chars and control chars
  as visible `<U+XXXX>` tokens, so a scanned repo can't visually spoof the reviewed code.
- **Package-name validation is ASCII-only.** Prevents non-ASCII input from passing validation and
  being reflected back via a registry error.

### Changed
- **Capability is no longer scored as risk.** `risk_score` now sums only `malicious_indicator`
  and `risky_construct` findings; neutral `capability` findings (shell / filesystem / network)
  are shown but contribute 0. A legitimate-but-powerful component (including SkillTotal's own
  engine) is no longer pushed into the red by what it *can* do — capabilities stay visible as
  findings + chips, but the score and verdict reflect actual risk. (ruleset 9)
- **Exfiltration signal is now sensitivity-gated.** The old `ST-COMBO-FS-NET` (any filesystem +
  network ⇒ critical) is replaced by **`ST-COMBO-EXFIL`**: a critical `risky_construct` raised
  only when *sensitive-data access* (a credential-location reference or an embedded secret) is
  combined with network egress. Plain "reads files + uses network" no longer flags.
- Verdict copy: a clean component that still has real capabilities now reads
  *"No malicious indicators — review capabilities before installing"* instead of
  *"No significant risks found"*.

### Fixed
- **A security scanner no longer flags itself (or other security tools / docs) as malicious.**
  Two new evidence-demotion gates (mirroring the existing test-code gate) move matches that are
  not executed/agent-facing behavior to `needs_review` so they never drive the score or verdict:
  - **Documentation/prose** (README, CHANGELOG, LICENSE, `docs/`, `*.egg-info/PKG-INFO`,
    ignore-files) — a pattern described in prose isn't the behavior. AI-instruction surfaces
    (`SKILL.md`, `AGENTS.md`, manifests, …) are explicitly kept in scope.
  - **Python string-literals / comments** — a detector matching its own regex literals or a
    docstring example is not behavior (`ST-OBF-DECODE-EXEC`, `ST-MCP-TOOL-POISONING`,
    `ST-PROMPT-INJECTION`, `ST-SENS-PATH`: string+comment; `ST-EXPOSE-*`: comment only).
- Bare `.env` file references are routed to `needs_review` (legitimate dotenv usage is ubiquitous)
  instead of being a scored sensitive-path finding.

## [0.7.4]

### Fixed
- **False-positive "malicious" verdicts on real MCP servers** (ruleset 8). A scan of 37 popular
  MCP servers flagged 6 legitimate ones (awslabs, apify, exa, Figma-Context-MCP,
  DesktopCommander, serena) as malicious. Recalibrated:
  - `ST-MCP-TOOL-SHADOWING` → **needs_review** (no longer a scored malicious indicator): "use X
    instead" / "do not use the Y tool" is indistinguishable from legitimate intra-server routing
    and code comments.
  - `ST-MCP-TOOL-POISONING`: dropped the bare "before using/calling this tool" imperative (legit
    prerequisite/UX guidance); the cross-tool precondition now requires a sensitive read/send
    target (e.g. `~/.ssh`, credentials) to fire.
  - `ST-PROMPT-INJECTION`: "print"/"show the system prompt" no longer match (legit
    `print-system-prompt` CLI features); dropped the lone "hidden instruction" phrase; "send
    <secret> to" is suppressed when negated ("MUST NOT send tokens to…", spec prose).
  - Added regression tests for all six.

## [0.7.3]

### Changed
- **Packaging & project metadata** for the public release: PyPI card now carries the website
  (`Homepage = https://www.skilltotal.ai`), Documentation/Issues/Changelog URLs, Python
  3.10–3.13 + OS-Independent classifiers, and README badges. Added `CODE_OF_CONDUCT.md`,
  GitHub issue/PR templates, and `contact@skilltotal.ai` as a security report channel. No
  detection or schema changes (ruleset 7, schema 1.3 unchanged).

## [0.7.2]

### Security
- **Bounded git clone**: `git clone --depth 1` now runs with a timeout
  (`SKILLTOTAL_CLONE_TIMEOUT`, default 300s) and `GIT_TERMINAL_PROMPT=0` /
  `GCM_INTERACTIVE=never`, so a slow/huge remote or a private-URL credential prompt can no
  longer hang the caller (important for a long-lived server that runs scans inline). Timeout
  surfaces as a `CollectionError`.

## [0.7.1]

Calibration hardening: a labeled-corpus run (django, numpy, typescript, webpack, the MCP
SDK, github-mcp-server, …) surfaced false "malicious" verdicts on trusted packages. All were
over-broad `malicious_indicator` rules; this release fixes them and adds regression tests so
they cannot recur. Net effect: 0 benign false positives on the calibration corpus.

### Fixed
- **Removed `ST-PROMPT-EXFIL-MD`** (added in the yanked 0.7.0): it fired on any markdown
  link whose URL contained a literal `$`/`{` (e.g. AngularJS `$http` doc links, dynamic
  shields badges), wrongly flagging trusted packages (axios, django, numpy, typescript, …)
  as malicious. Reliable markdown-exfil detection needs prompt-instruction context that
  pure static regex can't supply — deferred to the runtime/paid layer (see open-core.md).
- **`ST-HIDDEN-UNICODE` now flags only tag characters (U+E0000+)** as malicious — the
  unambiguous ASCII-smuggling signal. **Bidi overrides and zero-width characters** moved to
  `needs_review` (`ST-HIDDEN-UNICODE-AMBIG`): they appear legitimately in RTL-locale `.po`
  files, CJK text, HTML-entity tables (webpack), and emoji, so they no longer raise a malware
  verdict on their own.
- **`ST-MCP-TOOL-POISONING`**: dropped the over-broad `always/first … before` sub-pattern,
  which fired on benign call-ordering guidance ("Always call list_tables before queries" in
  the MCP TypeScript SDK examples).
- **`ST-PROMPT-INJECTION`**: `do not tell the user` / `without telling the user` moved from a
  scored finding to `needs_review` — a genuine concealment marker that also appears in benign
  UX guardrails (GitHub's official MCP server: "Do NOT tell the user the issue was updated;
  the user MUST click Submit"). Real concealment still co-occurs with stronger scored signals.
- Regression tests added for each of the above (the calibration corpus cases).

## [0.7.0] — YANKED

Yanked from PyPI: shipped `ST-PROMPT-EXFIL-MD` which produced false "malicious" verdicts on
popular trusted packages. Superseded by 0.7.1.

### Added
- **MCP detectors (ruleset 7)** closing gaps from agent-scan / agent-audit:
  - `ST-MCP-TOOL-SHADOWING` (`malicious_indicator`) — a tool description steering the agent
    to prefer/override/avoid *other* tools (tool shadowing).
  - `ST-MCP-AUTO-APPROVE` (`risky_construct`) — an `mcpServers` entry pre-authorizing tool
    calls (`autoApprove` / `alwaysAllow` / `trust`), removing the human confirmation gate.
- **Version pinning** for package sources: `npm:name@1.2.3` and `pypi:name==1.2.3`
  (`pypi:name@1.2.3` accepted too) download that exact release instead of latest.
- **Calibration harness** (`tests/manual_eval/calibrate.py`): run the engine over a labeled
  CSV and report benign false-positive rate, detection rate, and `needs_review` noise.

### Changed
- **Minified-line noise** (`ST-OBF-MINIFIED`) no longer floods reports: build artifacts that
  are long-line by design (`.map`, `.d.ts`/`.d.mts`/`.d.cts`, `*.min.*`, `package-lock.json`)
  are skipped, and the remaining minified files collapse into a single aggregated
  `needs_review` entry instead of one per file.

## [0.6.0]

### Added
- **Threat-class axis** on findings (`malicious_indicator` | `risky_construct` |
  `capability`) and a top-level **`verdict`** (fast "is this likely malware?" read,
  independent of `risk_score`). Lets consumers separate a malware verdict from code-safety
  hygiene. Existing rules tagged: prompt-injection, MCP tool-poisoning, decode-and-exec, and
  hidden-unicode are `malicious_indicator`; sensitive-path is `risky_construct`; capability
  rules (shell/fs/network/dynamic/MCP/combo) stay `capability`. Report schema **1.3**
  (finding.threat_class + verdict; additive).
- **Risky-construct detectors** (ruleset 6) covering the unintentional-mistake classes from
  vulnerablemcp.info, all `risky_construct`:
  - `ST-SECRET-EMBEDDED` — hardcoded credentials/keys shipped in the component (known-prefix
    tokens + private keys + secret-variable assignment); values redacted in evidence.
  - `ST-CMDI-PY` / `ST-CMDI-NODE` — command injection: a shell sink fed a dynamically built
    command (excludes safe argv-without-shell).
  - `ST-DESERIALIZE-PY` — unsafe deserialization (pickle/marshal/jsonpickle, yaml.load
    without SafeLoader).
  - `ST-EXPOSE-BIND` / `ST-EXPOSE-DEBUG` — network exposure (bind 0.0.0.0, debug server).
  Corpus-calibrated (no false positives on the trusted real-world corpus).
- **`skilltotal inventory`** — discover AI components already installed on this machine
  (MCP servers + skills from Claude Desktop/Code, Cursor, Windsurf, VS Code, Gemini configs),
  derive an `npm:`/`pypi:`/local source for each, and scan them. Pure local discovery (reads
  config files only, never launches). `--json`, `--no-scan`, `--project DIR`. No change to the
  report schema or the `analyze`/`analyze_directory` API.

## [0.5.1]

### Fixed
- MCP exfiltration-surface signal now treats **browser** as an off-host channel (web
  automation can ingest untrusted content and exfiltrate), so a browser+credential or
  browser+filesystem server is flagged even without a `network` tool. The 0.5.0 logic
  anchored only on `network` and missed this (e.g. the `mcp` package itself).

## [0.5.0]

### Added
- MCP **exfiltration-surface** signal (ruleset 5): when one component's MCP tools span a
  network channel AND data access (filesystem/browser/credential), emit a `needs_review`
  note — the capability surface a "toxic agent flow" (lethal trifecta) needs. Emitted as
  needs_review, never scored: legitimate servers have this surface too; the real risk is
  architectural (runtime agent permissions). Inspired by the Invariant Labs GitHub MCP
  toxic-flow writeup. See `RULES_CHANGELOG.md`.

## [0.4.0]

### Added
- `Component.download_url`: for npm/PyPI sources, the exact distribution artifact that was
  fetched and analyzed (null for git/local). Lets consumers deep-link evidence to the
  published artifact — e.g. a PyPI `files.pythonhosted.org` URL maps to inspector.pypi.io.
  Report schema **1.2** (additive; 1.1 readers unaffected).

## [0.3.1]

### Fixed
- PyPI page (long description) shipped with 0.3.0 still showed pre-PyPI install
  instructions; README now leads with `pipx install skilltotal` (PEP 668-safe) and the
  page is refreshed by this release. Added `tests/test_release_hygiene.py` so the release
  gate mechanically blocks tagging with a stale CHANGELOG/README/schema-id.

## [0.3.0]

### Added
- `NeedsReview.line` (optional, 1-based): heuristics now record the exact line when they
  know it (ambiguous words/phrases, zero-width unicode, obfuscation hints, dynamic imports,
  unparseable Python/JSON, test-only demotions), so consumers can deep-link straight to the
  location. Report schema **1.1** (additive; 1.0 reports remain valid for readers).

## [0.2.0]

### Added
- **npm / PyPI package collection** (`collector.py`): `collect()` now resolves `npm:<name>`
  and `pypi:<name>` specs (and `npmjs.com` / `pypi.org` URLs) by downloading the latest
  published release from the registry and extracting it safely (path-traversal and
  decompression-bomb guards; links skipped). New helpers `classify_source`,
  `npm_package_name`, `pypi_package_name`.
- Versioned engine contract: `ENGINE_VERSION`, `REPORT_SCHEMA_VERSION`, `RULESET_VERSION`
  (`skilltotal/__init__.py`); `schema_version` and `ruleset_version` in report `metadata`.
- Formal report contract `docs/report.schema.json` (schema version 1.0) and a contract-guard
  test (`tests/test_report_schema.py`) that validates every fixture report against it.
- Process docs: `docs/contributing-rules.md`, `docs/releasing.md`.

## [0.1.0]

### Added
- Initial CLI engine: collector, file index/evidence engine, 11 scanners, capability
  extraction, scoring (filesystem+network combo critical), text/JSON/SARIF reports, baseline
  suppression, AST-based Python analysis, hidden-Unicode detection, MCP tool classification
  (JSON + code). Zero runtime dependencies.
