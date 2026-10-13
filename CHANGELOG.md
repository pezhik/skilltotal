# Changelog

All notable changes to the SkillTotal engine. Format loosely follows
[Keep a Changelog](https://keepachangelog.com); the project uses
[SemVer](https://semver.org). See `RULES_CHANGELOG.md` for detection-rule changes.

## [Unreleased]

### Plugin
- In CI the hook waits for the full check of a large package, up to 10 minutes by default and
  14 at most (`SKILLTOTAL_HOOK_BUDGET`), instead of denying it after 60 seconds. Outside CI the
  wait is unchanged. The plugin's hook timeout is now 15 minutes.

### CLI
- A source over a size limit is refused with its size, the limit and the setting that raises it
  (`SKILLTOTAL_MAX_ARCHIVE_MB`, `_EXTRACT_MB`, `_ARCHIVE_MEMBERS`, `_CLONE_MB`, `_READABLE_MB`).
  The hook names the same setting instead of saying the scan failed.

## [0.65.0]

Nothing the engine skips is skipped in silence, and agent auto-run commands are read. Ruleset 69.

### Detection (ruleset 69)
Details in `RULES_CHANGELOG.md`. Detection-efficacy corpus: 90 malicious and 62 benign samples,
90/90 flagged, 0 false positives.
- Every command an agent host or editor runs on its own is read with one parser: MCP server
  launch commands (Claude, VS Code, Codex, Gemini and bundles), hooks (including http hooks),
  status lines and helper commands, and the hooks, monitors, LSP and MCP servers of plugins,
  skills and subagents. Reading a key, the whole environment or a CLI token and sending it out
  from such a command is a malicious indicator (`ST-SECRET-EXFIL`), as is passing the whole
  `process.env` / `os.environ` to a network call.
- A JSON string that is a command is no longer read as a deny-list entry, so a credential path
  inside an agent's launch command is no longer set aside for review.
- Code in `env/`, `venv/` or `vendor/` is analyzed unless the folder is a real virtual
  environment, and code loaded by path from a skipped folder is followed; what stays unread
  gets a note.
- A name bound to `__import__`, `importlib.import_module` or `getattr(<module>, ...)` and called
  later is read as the call it resolves to.
- A composite GitHub Action step that sends a CI token to a host outside GitHub is a malicious
  indicator (`ST-ACTION-SECRET-EXFIL`).
- An all-interfaces address inside the text of a warning or log message is no longer read as
  a server bind.

### Breaking for CI
- **In CI the Claude Code hook denies what it could not check.** Strict mode is on when `CI` (or
  `TF_BUILD`, `JENKINS_URL`, `TEAMCITY_VERSION`, `CODEBUILD_BUILD_ID`, `BUILDKITE`, `GITLAB_CI`) is
  set. `SKILLTOTAL_STRICT=0` turns it off, and `SKILLTOTAL_STRICT=1` turns it on anywhere. In
  strict mode the hook denies:
  - everything it would otherwise ask about;
  - installs that name no package (kind `lockfile`): `npm ci`, `npm install`, `pip install -r`,
    `uv sync`, `poetry install`, updates, and `uv run` in a project;
  - `pip install -e .` and other local paths (`local`);
  - a downloaded script that is run (`script`);
  - a package only partly analyzed (`partial`).

  To let some of these kinds through, list them in `SKILLTOTAL_ALLOW_UNCHECKED` (any of
  `lockfile`, `local`, `script`, `partial`), for example
  `SKILLTOTAL_ALLOW_UNCHECKED=lockfile,local`. Without a working CLI, or with one older than the
  plugin, every command is denied in CI.

### Added
- Every install command gets one line in the Claude Code console: what was checked and its score,
  the decision, or what was not checked and why.
- `skilltotal scan --fail-on-unanalyzed`, `fail_on_unanalyzed = true` in `.skilltotal.toml` and the
  Action input `fail-on-unanalyzed`: exit 2 when part of the component could not be analyzed.
- A text file too large to analyze (over 2 MiB) gets a `needs_review` note.
- The report names code in C/C++, C#, Swift, Kotlin, Scala, Dart, Lua, Perl, Elixir, Groovy,
  Haskell, Clojure, Erlang, R and Zig as not analyzed for behavior, as it already did for Go,
  Rust, Java, Ruby and PHP. Scores do not change. A low verdict reads "Partially analyzed".

### Changed
- README and docs name exactly what each coverage row checks and what is not checked yet. A
  skill's `allowed-tools` is described as what it is: it pre-approves tools and does not limit
  the skill's code (`ST-SKILL-CAP-MISMATCH` text updated).

## [0.64.0]

Found while preparing the launch. Ruleset 68.

### Detection (ruleset 68)
Five constructs a blind red-team used to get past ruleset 67, each now read the way its plain form
already was; details in `RULES_CHANGELOG.md`. Detection-efficacy corpus: 73 malicious and 50 benign
samples, 73/73 flagged, 0 false positives.
- A credential path joined onto the home directory (`path.join(os.homedir(), '.aws',
  'credentials')`, `Path.home() / '.aws' / 'credentials'`) is judged like the written path.
- Agent rule folders (`.clinerules/`, `.cursor/rules/`, `.windsurf/rules/`) are instruction
  surfaces, and an instruction to send credentials out while keeping it from the user is prompt
  injection.
- Hex decoded and executed (`new Function(Buffer.from(h, 'hex').toString())()`, also across two
  statements) is decode-and-execute, and forms a dropper with an install hook.
- An all-interfaces address bound through a variable is network exposure.
- An MCP tool description split across concatenated strings is read whole.
- A provider SDK reading its own provider's credentials goes to review, and only for a name the
  registry gives: a repository naming itself after a provider SDK gets no allowance.

### Security
- **A large package gets a verdict instead of the same question every time.** The hook killed a
  scan at its deadline and kept nothing, so a package too large to check in the 20 seconds an
  install command had was asked about on every attempt, downloaded and scanned again each time,
  and never installed in `claude -p`, where a question becomes a denial. A check the hook stops
  waiting for now goes on in the background, at most two at once and for up to 20 minutes, and
  saves its verdict, so the same command run again is answered from it. The background processes
  hold none of the hook's handles and outlive it; a check whose hook is gone (Esc, a timeout) is
  adopted within the same two-at-once limit or stopped. All checks of one command share 60 seconds
  (was 20; `SKILLTOTAL_HOOK_BUDGET` still sets it, up to 100); once a package is downloaded, its
  size tells whether its check fits in the time left, and if not, the person is asked right away.
  A package whose check would take more than 20 minutes is not started: the person is told to run
  `skilltotal scan`. Every wait after the budget is bounded, so the hook answers within its budget
  plus 5 seconds. The processes that finish a check act only on a check directory the hook created,
  proved by a one-time secret passed in the environment.
- **Deep nesting no longer hides what an agent config or a manifest sets up.** Python's json gives
  up at a depth that depends on the interpreter and the platform (Python 3.14 on Linux read
  100,000 levels that Python 3.10-3.13, and Windows, could not), so padding beside a hook in
  `.claude/settings.json` or a server in `mcp.json` made the whole file unreadable on some
  machines and hid what it configured, and the same component gave different reports by platform.
  JSON a component ships, and registry documents built from it, are now read with a depth bound: a
  value nested more than 200 levels deep is read as null, the rest of the file is analyzed, and the
  report notes "Deeply nested JSON partly analyzed". A `claude mcp add-json` config beside such
  padding is checked like any other, and a deep npm version document no longer breaks release
  resolution in the hook.
- **Many matches on one long line cost linear time.** Each match rebuilt its evidence from the whole
  line, so a 60 KB line of repeated credential paths or injection phrases took over 100 s, in the
  hook and in a hosted scan, where it held a scan slot until the timeout. A 2 MB line now scans in
  about 10 s. Reports are unchanged.

### Changed
- The engine source carries no invisible or control characters; a test keeps it that way.

## [0.63.0]

Found by pre-launch reviews of 0.62.0. Ruleset 67.

### Security
- **What npm runs at install time is read and scored wherever it is filed**, including in the
  package's build output and test folders, and through dependencies the package bundles. A NUL
  byte no longer hides a JS, `.pth` or shell file from the scan.
- **Code the scan could not read is never called clean.** A component of which no file could be
  read gets the headline "Not analyzed - nothing in this component could be read"; files that
  could not be read and links that were not followed are listed for review. `guard` blocks such
  a component, and `--fail-on` fails on it, as both do on an install script the scan could not
  analyze.
- **Links do not lead out of the component.** Symbolic links and Windows junctions are not
  followed: a repository could link a file to one elsewhere on the machine and have it quoted in
  the report. A `package.json` that is a link is not read.
- **Hostile archives fail cleanly.** A corrupt, truncated or password-protected archive is a
  collection error instead of a traceback; links, FIFOs and devices inside a tar are never
  extracted; size and entry limits apply while entries are read, so a compressed bomb stops at
  the limit. MCP bundles (`.mcpb`, `.dxt`), wheels and `.vsix` files are recognized as zip
  archives and scanned, not read as one binary file.
- **Deep nesting degrades, never crashes.** A manifest, agent config or Python file nested
  thousands of levels deep is reported as unparseable, and the rest of the component is still
  analyzed.
- **git:** the scanned repository's Git LFS settings are not followed (`GIT_LFS_SKIP_SMUDGE=1`),
  and a sparse checkout path is passed after `--end-of-options`.
- **`guard` blocks a name a letter or two from a popular package**, as the Claude Code hook asks
  about it.
- **The Claude Code hook reads a command line the way the shell does.** It split the line at
  separators before reading quotes, so a quoted `;`, `|` or `&` anywhere in an install command
  hid the install, and so did a line continuation, a keyword such as `then` or `do`, or a
  comment. A one-pass lexer now reads quotes and escapes (including `$'...'` and PowerShell's
  doubled and typographic quotes), line continuations, comments, here-documents, here-strings and
  substitutions, and drops redirections by each shell's own rules. Installs inside `if`, loops,
  `case`, functions, and a script piped or fed through a here-document to a shell are read. Each
  difference found by running the same lines through Git Bash and Windows PowerShell 5.1 with
  stub installers is a test.
- **The hook asks when it cannot read what will be installed:** a package name or an install
  command the line builds at run time (`npm i $P`; `eval "$C"` with `C` set on the same line; a
  computed command or subcommand; a glob in a command name), an install inside a `node -e`,
  `python -c` or similar one-liner, and a line it cannot read to the end (an unclosed quote).
- **Every registry or index override asks**, on every install path: an environment variable
  (`npm_config_registry`, scoped registries, `npm_config_userconfig`, `PIP_INDEX_URL`,
  `UV_INDEX_URL` and their kin) and an abbreviated option as well as the full one.
- **More of what installs is checked:** every `-p`/`--package` of `npx`, `bunx`, `npm exec`,
  `pnpm dlx` and `yarn dlx`, and the program the runner starts; scaffolders (`npm create x`
  checks `create-x`; `npm init` alone installs nothing); `python -m pip`, `uv tool install`,
  `uv run --with`, `pipx run` and `pipx inject`, `poetry add`, `pdm add`, `pipenv install`;
  `eval` and `trap` with literal text, aliases defined on the line, `xargs` fed by a literal,
  `find -exec`, and launchers such as `timeout`, `nohup`, `watch` and `systemd-run`; on
  PowerShell, `$r = npm i x` and `&` or `.` with a literal name.
- **A failure of the hook's own asks** ("SkillTotal could not check this command") instead of
  letting the command run with a warning. It never denies because of it.
- **Parsing takes time linear in the length of the line.** A command naming 20,000 packages took
  148 s, and a long run of `>` over two minutes: longer than Claude Code waits for the hook,
  after which the command runs.
- **A hook cache entry lives as long as its key allows** (a week for one exact release, an hour
  otherwise), whatever the cache file says.
- **Windows: no program starts from the current directory.** Windows looks there before PATH, so
  a `git.exe` or `uvx.exe` committed to a scanned repository could run instead of the real one.
  The CLI and the npm wrapper set `NoDefaultCurrentDirectoryInExePath`, and the wrapper looks up
  `uvx`, `pipx` and Python only in PATH's absolute directories (Node before 22 ignores the
  variable).
- `guard --installed` escapes control characters in names read from agent configs: an escape
  sequence in a server name could rewrite what the terminal showed.
- **The MCP server survives malformed requests.** `params` that is not an object, JSON nested too
  deep to decode, or a reply UTF-8 cannot carry gets a JSON-RPC error (-32602, -32700, -32603),
  and the session goes on instead of ending.

### Changed
- **`--fail-on` counts risk, not capabilities.** The severity gate counted every finding: a shell
  call or network access, which many tools exist to do, is high severity, so the GitHub Action's
  default `fail-on: high` failed 21 of 31 popular components that score low. A malicious indicator
  now trips any level (prompt injection is medium severity), a risky construct or a shipped secret
  trips at its severity, and a capability never trips it on its own; a `block` policy still
  forbids a capability rule. What the scan could not read fails it closed (above). Applies to
  `--fail-on`, `--fail-on-high`, `fail_on` in `.skilltotal.toml` and the Action's `fail-on`.
- Verdict headlines: "No malicious indicators - secret-like values found" (was "exposed secrets
  found"); "Name resembles a popular package - check it before installing"; "Low risk - review
  the findings before installing" where one risky construct read "No significant risks found".
- The Action's pull request comment shows 🔴 and the verdict headline when malicious indicators
  fired, finds its earlier comment on any page, and no longer fails a fork's job when the token
  cannot comment.
- Rule descriptions no longer name malware campaigns.
- An `npm:` source fetches the one version document it needs instead of the package's whole
  history (3 KB instead of 30 MB for a large package).
- The hook does not check a program the project already has in `node_modules/.bin`, in the
  working directory or a parent (on Windows also its `.cmd` and `.ps1` shims): `npx tsc` runs it
  and installs nothing. A version or tag, `-p`, `pnpm dlx`, `yarn dlx` and `pnpx` still fetch, and
  are checked.
- The hook's note and questions name the release that was checked (`npm:x@1.2.3`, not
  `@latest`), also when the answer comes from the cache, and a check that ran out of time says how
  to allow more (`SKILLTOTAL_HOOK_BUDGET`, up to 100 seconds).

### Added
- `scan` shows what a long scan is doing, with the elapsed seconds, on one line that is erased
  before the report, and only when stderr is a terminal. `analyze()` and `analyze_directory()`
  take an optional `progress` callback.

### Fixed
- False positives on widely used packages (ruleset 67): a string split at `::`, a loop over literal
  command names, MCP tool shapes quoted in comments, a dict parameter named like a network
  library, example keys and public build variables. See `RULES_CHANGELOG.md`.
- One long line no longer takes minutes to scan.
- The sdist no longer ships the test suite (it could not run without its fixtures).
- GitHub Release notes are the CHANGELOG section with wrapped lines joined.
- Docs: report schema 1.7 documented in full; the registry survey names rulesets 56–59, says what
  a re-run reads and that its rules were tuned on that population; `python -P -m skilltotal`.

## [0.62.0]

Found by pre-launch security reviews of 0.61.1. Ruleset 66.

### Security
- **The Claude Code hook no longer runs code from the project the agent works in.** It started its
  scan with `python -m skilltotal` from the agent's working directory, and `python -m` puts that
  directory first on `sys.path`: a `json.py` planted in an opened repository ran inside the
  scanner before anyone approved anything, and the project's `.skilltotal.toml` tuned the scan of
  someone else's package. The scan now starts in an empty directory of its own, with `-P` on Python
  3.11+. The npm runner's Python fallback passes `-P` too, so it now needs Python 3.11+.
- **A package can no longer silence its own findings.** A `skilltotal:ignore` comment suppressed a
  finding in any scanned component, so one line next to a dropper made it scan clean. Inline
  markers now count only for `skilltotal scan` of a local directory (your own code, as in CI).
  `analyze` and `analyze_directory` take `inline_ignores`, off by default, and an honored marker is
  counted in `metadata.suppressed_count`.
- **The hook asks about every package it did not check.** A scan that failed or ran out of time,
  the sixth and later packages of one command, and an install script that could not be read used
  to let the install through with a note, which made the guard easy to step around: pad a package
  until its scan times out, or name it sixth. They now need the person's approval. The hook still
  never denies an install because of its own failure.
- **The hook checks what will actually be installed.** The version a command names (`npx x@0.1.2`,
  `pip install x==1.0`) instead of the latest release; the git ref (`github:o/r#v1`,
  `git+https://github.com/o/r.git@main`) instead of the default branch; the real package behind an
  npm alias (`x@npm:real`); and `pip install -e git+...`. Other git hosts (`gitlab:`,
  `bitbucket:`, `gist:`) and refs the scan cannot reproduce exactly are asked about.
- **The hook's verdict cache is keyed by the artifact.** An unpinned `npm:x` is first resolved to
  the release the registry serves (`npm:x@1.2.3`), and a PyPI package to the file pip would
  install, because a published PyPI version can gain files. A clean verdict from the morning no
  longer vouches for a release published in the afternoon. An exact release is reused for a week,
  a git repository or an unresolved name for an hour.
- **The GitHub Action** passes its inputs to the shell only through `env` (a `source` copied from
  a pull request comment could run commands in the runner), keeps the checked-out repository off
  `sys.path`, fails on an unknown `fail-on` value instead of silently disabling the gate, and runs
  the engine that ships with the pinned tag unless `version:` is set.
- **Text reports escape control characters**, so a path or snippet from a scanned package cannot
  move the terminal cursor, rewrite earlier lines or set the clipboard.

### Changed
- **The scripts npm runs at install are always analyzed**, whatever their shape. A minified
  one-line `setup.js` run by `postinstall` was set aside as a bundle, so a dropper in it scanned
  clean. An install script that cannot be read at all (larger than 2 MiB, binary) is reported,
  makes `guard` block and makes the hook ask.
- **PyPI packages are scanned as pip installs them**: the pure-Python wheel when it is the
  release's only wheel, else the sdist, else any wheel, named by the registry. The sdist carried tests, docs and build
  tooling that pip never installs, which slowed the hook (fastapi: 1,215 files, now 65) and
  produced findings in code no user runs. A wheel's `*.dist-info/` is packaging metadata, like an
  sdist's `PKG-INFO`.
- **Source maps that carry no code are skipped.** A `.map` holding only positions and names, as
  TypeScript writes it, cannot run and has nothing to analyze. A map with `sourcesContent`, or
  anything else in it, is read like any file.
- **npm dist-tags resolve.** `npm:x@latest` and `npm:x@next`, the usual way MCP servers are
  started, scan the tagged version instead of failing.
- **The text report** leads with the verdict, labels a capability finding as not scored
  (`[HIGH - capability, not scored]`), shows a one-line location as `file:12`, and lists three
  locations per finding (`--json` keeps all of them). Verdict reasons list malicious indicators
  first, then scored risks, then capabilities.
- **The hook's messages** name the release that was checked, the top finding of a high-risk
  package and the command to inspect it (`skilltotal scan npm:x` instead of `<package>`).
- **MITRE ATLAS tactics in the trait crosswalk are real ATLAS tactics.** "Adversarial Perception
  Attacks" and "Model Poisoning" were labels from the CSA paper. An untrusted-instruction surface
  now maps to Execution and Persistence (AML.T0051, AML.T0070, AML.T0099), supply-chain provenance
  to Initial Access (AML.T0010).
- A usage error (an unknown flag value) exits 1, as documented; 2 means a gate tripped. `guard`
  names the malicious finding and its location instead of repeating the headline, and
  `skilltotal scan lodash` suggests `npm:lodash` or `pypi:lodash`.

### Fixed
- **A redirected report no longer crashes on Windows.** Output goes out as UTF-8 and `--output`
  is written before anything is printed, so `scan --json > r.json` on a legacy code page neither
  fails on a snippet nor leaves the file empty.
- **SkillTotal no longer rates its own repository as malicious.** `RULES_CHANGELOG.md` quotes the
  attacks its rules detect, and the word "rules" made it read as an instruction file; a file whose
  name ends in a record word (changelog, history, license) is documentation.
- **False positives on widely used projects** (ruleset 66): an injection phrase quoted by an
  issue-triage skill, a threat model's account of what attackers may do, a CLI's sandbox profile
  that denies its tools the CLI's own login file, a `0.0.0.0` that is not a bind address, JSDoc
  examples, and popular packages whose names sit a letter away from another popular name no longer
  score. Each fix is pinned beside a test that the attack it resembles still fires. See
  `RULES_CHANGELOG.md`.

## [0.61.1]

### Changed
- **The Claude Code plugin says what it found when it blocks an install.** The deny reason now
  names the first malicious-indicator finding and where it is (`Decode-and-execute (obfuscated
  execution) at scripts/setup.js:4`, plus how many more there are) instead of only the verdict, so
  the agent can tell the person exactly why the package was stopped. The path comes from the
  scanned package, so it is quoted as data and shown only when it is a plain path: a file name
  written as an instruction to the agent is left out. `skilltotal scan` still lists every finding.
  Detection is unchanged (ruleset 65).

### Fixed
- **CI tests the npm runner against the engine in the same commit.** The runner prefers
  `uvx`/`pipx`, which fetch the matching release from PyPI, so the end-to-end tests ran the last
  release on ordinary commits and failed on every release commit, whose version is published only
  after its tag. The test step now keeps only Python and Node on `PATH`.

## [0.61.0]

### Fixed
- **The ruleset 64 rules can no longer be sidestepped by rewriting the same code** (ruleset 65).
  A security review of 0.60.0 found ways around each new rule that change nothing about what
  runs. A composite action's `run:` command is now read as the runner's shell receives it, so a
  command written as a quoted or escaped YAML string (`\u007C` for `|`), continued on the next
  line, placed in a flow mapping (`{ run: … }`), behind an alias or under a quoted key is read
  like any other, and a `#` inside shell quotes no longer hides the rest of the line. An action
  under `.github/` is now read too and shown for review instead of being left out. A function
  looked up by name (`getattr(os, "sys" + "tem")`, `__import__("os").system`) resolves to the
  function itself, which also closes a known gap in Python shell detection; `os.exec*`,
  `os.spawn*` and `subprocess.getoutput` now count as process execution. A pickle gadget is
  caught when the callable is aliased first, set with a lambda, or registered with
  `copyreg.pickle`. A `dns` or `https` module bound under any name counts as network egress.
  Each case has an honest look-alike that stays clean: a commented-out command, custom pickling
  that returns the class, an e-mail validator that looks up MX records.

## [0.60.0]

### Added
- **Four gaps found by a blind red-team are closed** (ruleset 64). Ten malicious AI components
  were built without reference to the rules and then scanned; these four went unseen or
  under-read. A composite GitHub Action's `run:` steps are now scanned as shell: they run on the
  runner of whoever uses the action, yet were never read, so `curl … | bash` or `… base64 -d |
  bash` in an `action.yml` produced no finding (the project's own `.github/` CI stays out of
  scope). DNS lookups (`dns.resolve4`, `dns.lookup`) now count as network egress, so reading a
  credential and tunnelling it out over DNS is flagged as exfiltration. A pickle `__reduce__` that
  returns a shell or code-execution callable is flagged as a code-execution gadget
  (`ST-PICKLE-REDUCE`). A Solana CLI keypair read through `os.homedir()` instead of `~` is now
  recognized as a credential path. Each sits beside the honest shape it resembles, which stays
  clean: a DNS health check, custom pickling that returns the class, a security tool that lists
  wallet paths to protect. An ordinary setup action that installs a CLI with its vendor's script
  is reported as a risky construct but not escalated to malicious or high risk.

## [0.59.0]

### Added
- **Four more 2026 attack techniques are detected** (ruleset 63). A wallet private key, seed
  phrase or mnemonic read from an environment variable is now a sensitivity signal
  (`ST-SECRET-ENV`), so reading one and sending it off-host is flagged as credential
  exfiltration. Code that writes a server into another AI client's MCP config
  (`ST-AGENT-CONFIG-INJECT`) or repoints git's global template/hooks path for persistence
  (`ST-GIT-HOOK-PERSIST`) is flagged (SANDWORM_MODE). An Agent Skill that auto-runs a `!`
  dynamic-context command to steal a token or fetch-and-run code is flagged as malicious
  (`ST-SKILL-DYNAMIC-EXEC`, Clawsights). Each sits beside the honest shape it resembles — a local
  husky `core.hooksPath`, a tool that only reads a client config, a benign `!`git status``
  skill command, a plain `API_KEY` from the environment — which stay clean.
- **Detection now sees through split and aliased literals.** An attacker can hide a known string
  from a static matcher by splitting it across concatenated string literals
  (`process.env["WALLET_" + "PRIVATE_KEY"]`, `open("~/." + "ssh/id_rsa")`) or aliasing the object
  that holds it. A new deterministic normalizer folds adjacent string-literal concatenations back
  into one literal (and resolves `process.env` aliasing) before matching, so the credential-path,
  wallet-env and client-config rules catch these without re-leaking evidence — the string-concat
  analogue of the homoglyph/zero-width folding already in place. It only joins runs of plain
  literals, so it adds no false positives. A new per-technique evasion-robustness benchmark guards
  this going forward.

## [0.58.0]

### Added
- **Reports now say when code was not analyzed for behavior.** Shell execution, network access,
  file access and dynamic code are detected only in Python and JavaScript/TypeScript. Before this
  release, a Go server that ran a shell command and posted a credential file could score "low"
  under "No malicious indicators", and nothing in the report showed that its Go code was never
  read. Now a component that ships Go, Rust, Java, Ruby or PHP source (test code excluded) gets a
  `needs_review` note with the file count per language. A low verdict's headline reads "Partially
  analyzed - Go code not checked for shell, network or file access". The verdict carries the counts
  in a new optional `unanalyzed_code` field (report schema 1.7, additive). Score and findings do
  not change.
- **npm package.** `npx -y skilltotal ...` runs this engine through uvx, pipx or an installed
  Python. The npm package contains no scanner code and does not install anything itself. It has
  no install scripts or dependencies. See `npm/README.md`.

## [0.57.0]

### Changed
- **Review notes are grouped.** Five review-only heuristics used to write one `needs_review`
  note for every file or line they matched: unparseable Python files, dynamic imports, large
  base64 blobs, runs of hex escapes, and files with bidi/zero-width characters. One package could
  carry hundreds of identical notes (352 for one linter's deliberately broken test fixtures).
  Each heuristic now writes a single note that says how many places matched, names the first
  five as `file:line`, and says how many of the files are test code. Findings, capabilities and
  the score are unchanged; the report schema is unchanged.

## [0.56.4]

### Changed
- **The plugin lives in `plugin/`.** The marketplace now serves only the plugin's own files (the
  manifest, the hook, the `/skilltotal:scan` command and a listing icon) instead of the whole
  repository. Install commands stay the same. To update an installed copy, run
  `/plugin marketplace update skilltotal`, then `/reload-plugins`.

### Docs
- README: the Claude Code plugin has its own section after Install.

## [0.56.3]

### Fixed
- **The plugin checks commands the agent runs through PowerShell.** On Windows, Claude Code runs
  most commands through its PowerShell tool, but the hook only listened to the Bash tool, so
  installs run through PowerShell went unchecked. The hook now covers both tools. The CLI also
  reads PowerShell quoting (a backtick escapes, a backslash is part of the path), the `&` call
  operator, script blocks, `iex`/`Invoke-Expression`, `Start-Process` and
  `powershell -EncodedCommand`. In Bash, it now also finds commands inside parentheses and
  braces, such as `(npm i x)`.

### Docs
- README: after installing the plugin, run `/reload-plugins` or restart Claude Code. Until then,
  the hook does not check commands in the session that installed it.

## [0.56.2]

### Changed
- **The plugin warns when it can't check an install.** If the `skilltotal` CLI is not on PATH or
  fails to run (a stale virtualenv, or an older version without the `hook` command), install
  commands still run, and Claude Code now shows a warning that names the cause and suggests
  `pip install -U skilltotal`. Before, the hook stayed silent, which looked the same as a clean
  check. Other commands get no warning.

## [0.56.1]

### Fixed
- **The plugin's hook passes every Bash command to the CLI.** The wrapper skipped commands that
  did not contain a package manager's name as typed, so `NPM install x` (which Windows runs) and
  quote-split names such as `n''px x` reached the shell unchecked. The CLI's parser already
  handled both and now sees every command.
- **Hook reasons read as plain sentences.** The risk score appears once, every part ends with a
  full stop, and a package from a custom index no longer suggests running `skilltotal scan`,
  which could not see it either.
- **The plugin manifest carries the engine version**, so an installed plugin updates with each
  release, in step with the CLI that answers its hook. `claude plugin validate --strict` passes.

### Docs
- README: how to check that the plugin works, why a custom registry asks for approval, how GitHub
  sources are scanned, and what the hook does not cover.

## [0.56.0]

### Added
- **Claude Code plugin.** The repository is now also a plugin marketplace
  (`/plugin marketplace add pezhik/skilltotal`). The plugin's hook checks each package the agent
  is about to install through `npx`, `bunx`, `pnpm dlx`, `npm`, `pnpm`, `yarn`, `bun`, `pip`,
  `uv`, `uvx`, `pipx` or `claude mcp add`. Packages with malicious indicators are denied, high-
  and critical-risk ones need approval, and clean ones run with a one-line note showing the
  score. All checks for one command share a 20-second budget (`SKILLTOTAL_HOOK_BUDGET`). A check
  that runs out of time or fails never blocks the install. Verdicts are cached for 24 hours per
  engine version. The plugin also adds `/skilltotal:scan` and registers the SkillTotal MCP
  server. It needs the CLI (`pip install skilltotal`).
- **`skilltotal hook claude-code`**, the CLI entry point behind the plugin's hook. It reads the
  hook event on stdin, prints Claude Code's hook answer and always exits 0.

## [0.55.0]

### Added
- **A component's `.git/config` is checked for `core.fsmonitor`** (GitSpawn, 2026): git runs that
  command on ordinary `status`/`diff` calls, which several AI coding agents make at session
  startup. The file is read for this check only and is not component content for any other rule,
  so a token in the remote URL of a project being scanned locally is never reported as an embedded
  secret. Ruleset 62.
- **A Claude Code plugin's own hook manifest is read** (`hooks/hooks.json`,
  `.claude-plugin/plugin.json`; HookPry, 2026). A hook that fetches or decodes code and runs it is
  a malicious indicator; an ordinary hook is listed for review with its commands and is not
  scored. Ruleset 62.
- **More credential paths and a scanner-evasion variant**: the Vault CLI token, the Hugging Face
  CLI token and SSH key paths built from path segments; a decode function looked up through
  `getattr()`/`__dict__`/`vars()` and executed. Ruleset 62.

### Changed
- **Strings returned by an MCP tool or prompt function are read as text the model sees**, like
  its docstring, so a poisoning phrase built at call time is no longer dismissed as a string
  literal. Ruleset 62.

## [0.54.0]

### Fixed
- **MCP servers written on the SDK's low-level API were not recognised as MCP servers**,
  including the official git, time and fetch reference servers, Python SDK 2.0 servers, proxies
  such as mcp-remote, FastMCP servers that register tools with `add_tool`, and NestJS mcp-nest
  servers. Ruleset 61.
- **Running git through GitPython or simple-git now counts as command execution**; the git
  reference server previously reported no capability at all.
- **`from .sh import x` / `from .git import x`** (a package's own module) no longer reads as a
  process-spawning library.

### Added
- **A note when an MCP package ships no server code the engine can read** (a launcher for a
  native binary or another package, or a server in a language not analyzed yet), so the report
  no longer looks empty and clean. It is a `needs_review` entry and never affects the score.

## [0.53.0]

### Changed
- **Dev-only floor pins on `urllib3` (>=2.8.0) and `virtualenv` (>=21.7.13)**, pulled in
  transitively by `twine`/`detect-secrets` and `pre-commit`. Fixes CVE-2026-97687/88/89 and
  PYSEC-2026-4011/4012/4013/4014 in the dev toolchain; the published package stays
  zero-runtime-dependency and is unaffected.

### Fixed
- **A provider token made of one repeated character is a placeholder, whatever its prefix.**
  `ghp_` followed by 36 copies of one letter was reported as a live credential: the
  "too few distinct characters" test counted the prefix, and `ghp_` alone contributes four of
  the five. Found in a redaction linter's own sample line, reported by its author. The body
  behind a provider prefix (`ghp_`, `github_pat_`, `sk-ant-`, `xoxb-`, ...) is now judged on its
  own as well; a real token's body is random and is unaffected. Ruleset 60.

## [0.52.0]

### Added
- **A second size limit, on the readable text rather than the checkout**
  (`SKILLTOTAL_MAX_READABLE_MB`). The existing limit bounds the clone — disk, bandwidth, the
  time git spends — and the new one bounds the scan, because the two are not the same
  constraint and one number cannot serve both. A repository of video is expensive to clone and
  trivial to scan; one of pure source is the reverse, and scan time tracks only the part an
  index opens.

  It defaults to the clone limit, where it can never fire on its own (readable bytes are a
  subset of the tree), so the offline CLI is unchanged unless it is set. What it is for is a
  deployment that kills a scan at a wall clock: without it such a host accepts a repository it
  has no chance of finishing and times out, which reads as a broken scanner rather than a
  repository that is too big. The gap is real and not hypothetical — `apache/spark` is a 196 MB
  checkout, comfortably inside a 200 MB clone limit, holding 169 MB of text, which at the rate a
  long scan runs is about sixteen minutes.

  The estimate stays conservative in the safe direction: a file whose suffix is not recognised
  counts as readable, so the limit can refuse a scan that would have run but never admits one
  that cannot finish.

## [0.51.0]

### Added
- **`collect()` can report how much work a scan is about to be.** A new optional `on_size`
  callback is handed a `TreeSize` — the bytes of the checkout, and the subset an index will
  actually read — once a GitHub repository has passed the size check and before the clone
  starts. It exists so a caller running scans as jobs can tell someone waiting roughly how long
  is left; the library still neither prints nor blocks. The callback is not invoked for a local
  directory, a registry package, a non-GitHub host, a refused repository, or when the API cannot
  answer, so callers must treat its absence as ordinary.

  Readable bytes are reported because the size of a checkout does not predict how long scanning
  it takes. Measured over five real repositories: 257 MB scanned in 47 seconds while 104 MB took
  326, because the first is video and the second is source. Readable bytes predict the same five
  to within a factor of two. The **size limit is unchanged** and still applies to the whole tree.

## [0.50.2]

### Changed
- **A repository that is too large now says how large.** `SourceTooLargeError` carries
  `measured_mb` and `limit_mb` as data rather than only inside its message, so a caller can tell
  someone they are 2 MB over a 200 MB limit instead of "too large" — which, for the visitor whose
  repository came to 202 MB, was a dead end with a working answer one folder away.

## [0.50.1]

### Fixed
- **Cloning a repository that contains a very long path no longer fails on Windows.** Real
  projects hold file names past Windows' ~260-character limit — one machine-learning repository
  reaches it with a single result file named after five models — and `git clone` refused them with
  "unable to create file". The same scan succeeded on Linux and macOS, so the failure read as a
  broken tool rather than a platform limit. Every git command the collector runs now carries
  `core.longpaths`, passed per command so the machine's own git configuration is left untouched.

## [0.50.0]

### Fixed
- **A repository is measured by what will be scanned, not by its history.** The pre-clone size
  check read GitHub's `size`, which is the whole history: a 24 MB checkout behind a 202 MB history
  was refused as "too large". The check now sums the blobs of the requested branch (GitHub trees
  API) and falls back to the history size only when the tree cannot be listed. The mid-clone
  watchdog no longer counts `.git/` toward the limit either (a shallow clone's pack is a second,
  compressed copy of the tree); the pack itself stays bounded at twice the limit.
- **A subfolder link costs that folder.** `/tree/<ref>/<path>` and `/blob/<ref>/<file>` links
  used to clone the whole repository and measure all of it, so "try a specific subfolder" did not
  help. The size check now measures the folder, and the clone is a sparse checkout of it — on
  GitHub and GitLab a partial clone (`--filter=blob:none`) that downloads only its files.

### Performance
- **Non-ASCII text no longer costs a character at a time.** `normalize_with_map` copies ASCII
  runs in one piece and loops only over the non-ASCII runs; the hidden-Unicode scanner skips files
  and lines that hold none of the code points it acts on (one regex search instead of a Python
  loop per character). Output is identical; on a 24 MB, mostly-CJK repository the two accounted
  for 200 s of a 500 s scan.

## [0.49.0]

### Fixed
- **A method named `exec` is not a shell (ruleset 59).** `ST-SHELL-NODE` matched any `exec(` or
  `spawn(`, so `re.exec(text)` — `RegExp.prototype.exec` — and database calls such as
  better-sqlite3's `db.exec` and mongoose's `query.exec()` were reported as Node.js shell execution.
  A call site now counts only where it can be tied to `child_process`: spelled out, or in a file
  that imports it, as a bare call or through the alias that file bound. `ST-CMDI-NODE` takes the
  same call sites, so `db.exec(\`CREATE TABLE ${t}\`)` is no longer command injection. `Bun.spawn`
  is matched explicitly.
- **Recorded experiment output is data (ruleset 59).** `experiments/` joins the data-corpus
  directories: its non-code files are demoted to needs_review, as under `eval/` or `fixtures/`. An
  ASCII-smuggling study was verdicted malicious on the model outputs it had measured. Code in the
  same tree is still scanned and scored.

### Performance
- **Scans of non-ASCII text use a fraction of the memory.** The de-obfuscation offset map held a
  Python int per character and was cached for every non-ASCII file: a 22 MB repository peaked at
  338 MB and failed the hosted scan's 400 MB cap. The map is now a packed `array('I')`, and ASCII
  characters skip Unicode normalization. The same repository peaks at about 155 MB, and
  normalization itself runs 3–4× faster; results are unchanged, which a test pins against the
  previous implementation.

## [0.48.3]

### Fixed
- **The high tier of the registry survey, read by hand (ruleset 58).** Five shapes still read as
  behaviour: a command printed through several arguments (`printf "%s" "$C" "curl … | bash"`), a
  PowerShell `#` comment, a sentence in Chinese or Japanese around a credential path, a filename
  compared against a literal (`strcmp(lower, "id_rsa")`), and a log redirected into `/tmp`
  (`nohup … > /tmp/x.log &`, where the idiom is running FROM /tmp).

## [0.48.2]

### Fixed
- **A command printed for a person is not a command the line runs (ruleset 57).** An installer that
  prints `curl … | sh` or `powershell -c "irm … | iex"` as a hint (`echo`, `Write-Host`, `print`,
  `console.log`) scored as remote pipe-to-shell and as a defense-evasion idiom. A match inside such
  an argument is demoted for every rule that already treats strings as non-code.
- **Instance metadata is a credential read only when it asks for credentials (ruleset 57).** A
  node's own bootstrap script reads its instance id, region or an IMDSv2 session token from
  169.254.169.254. `ST-SENS-PATH` / `ST-SENS-PATH-PY` now need the request to target the role's
  credentials (`iam/security-credentials`, a service-account token, the Azure identity endpoint).

## [0.48.1]

### Fixed
- **Parsing a URL is not network egress (ruleset 56).** `urllib.parse` and `urllib.error` counted
  as an HTTP client, so a component that only splits URLs read as "can reach the network" and could
  supply the egress half of `ST-COMBO-EXFIL`. Only `urllib.request` (and aliases of it) counts now.
- **Writing a credential file is not reading one (ruleset 56).** A release script putting
  `$NPM_TOKEN` into `~/.npmrc`, or an installer appending to `~/.ssh/authorized_keys`, fed both
  `ST-COMBO-EXFIL` and the `ST-INSTALL-DROPPER` payload. A write is excluded from both;
  `ST-SENS-PATH` still reports the line, because writing `~/.ssh/config` is an injection vector.

## [0.48.0]

### Changed
- **Exposed secrets are their own class and no longer raise the risk score (report schema 1.6,
  ruleset 55).** A hardcoded key, private key or packed `.env` file is the author's leak, not a risk
  the component poses to the machine it runs on. `ST-SECRET-EMBEDDED` and `ST-ENV-SHIPPED` now carry
  `threat_class: "exposure"`: reported with file and line, counted in `verdict.exposed_secrets`,
  still tripping `--fail-on high`, and contributing nothing to `risk_score`. An embedded secret no
  longer feeds `ST-COMBO-EXFIL`, which now means what its name says: a credential location read
  next to network egress. Consumers that switch on `threat_class` must handle the new value.

### Fixed
- **The high and critical tiers of the registry survey, read by hand (ruleset 54).** Nearly every
  high or critical component got there through `ST-COMBO-EXFIL`, and its inputs often named a
  credential without touching one. Credential paths that are installed public keys, a key handed to
  the SSH client, a sentence of help text, a UI label, a denylist or policy glob, or a line in a
  manifest no longer feed the combination. Secret-shaped values that are test placeholders, fixture
  and test-runner values, secret-scanner configuration, variable names, typed words, or client keys
  vendors publish in pages (Firebase web config, Maps JavaScript loader, Paddle.js, Cloudflare Web
  Analytics, OpenAI apps domain challenge) are reported for review instead of scored. Hardcoded
  live keys and shipped private keys still score. Every corpus attack and published-technique probe
  is still caught.
- **Evidence is capped after demotion, not before.** Scanners kept only the first 25 matches of a
  rule, and the engine then moved test, documentation and string matches to review. When those
  filled the 25 slots, a real match later in the component was never considered, and the finding
  disappeared. Scanners now collect up to 500 matches (`MAX_EVIDENCE_SCANNED`) and the engine keeps
  25 after demotion. Reports still show at most 25 per finding.

### Added
- `IndexedFile.string_span_at()`: the span of the Python or C-family string literal around an
  offset.

## [0.47.2]

### Fixed
- **Defensive MCP tools quoting "ignore previous instructions" are not poisoned (ruleset 53).**
  Ruleset 52 widened the poisoning phrase to "ignore previous/prior/system instructions"; four
  registry servers that describe the phrases they block were then flagged. The MCP rule is back to
  the tool's own instructions; "ignore previous instructions" stays with `ST-PROMPT-INJECTION`,
  which tells a cited example from a directive.

## [0.47.1]

### Fixed
- **All seven malicious-indicator hits in the ruleset-51 registry survey were false positives;
  each class is fixed (ruleset 52)**: `re.compile` strings, suffix-less shell scripts, multi-line and
  raw Rust strings, modal "could exfiltrate", and bare "ignore instructions", in addition to the two below.
- **Two false positives found by the ruleset-51 registry survey (ruleset 52).** An agent guide
  saying "pass `authToken` as parameter; use `Authorization: Bearer ${token}` header" matched the
  environment-secret-in-requests phrase case-insensitively; the secret must now be written as an
  environment variable (`$FOO_KEY`, or "environment variable FOO_KEY", upper case). A structured
  tool docstring's `<instructions>` section ("Use this when the user wants...") read as a hidden
  instruction block; "when" and "make sure" no longer count as the instruction after a marker.
  Every published attack shape in the corpus is still caught.

## [0.47.0]

### Added
- **Detection for the attack techniques published against AI components in 2026 (ruleset 51).**
  Each was reproduced as an inert sample and checked against the engine first; ten of eleven were
  missed. Now covered: node-gyp command substitution in `binding.gyp` (the Miasma worm's install
  vector that bypasses install-script checks); agent and editor configuration that runs commands
  on its own (`.claude/settings.json` hooks, `.gemini/settings.json`, `.cursor/hooks.json`,
  `.vscode/tasks.json` on folder open), escalated when it fetches or decodes code; AI coding CLIs
  launched with approvals disabled; shell commands inside markdown fenced blocks, where malicious
  skills put `base64 -D | bash` under "Prerequisites"; downloaded archives extracted with a
  password; zero-width characters threaded through words; agent instructions that carry a secret
  from the environment into URLs, copy themselves into CLAUDE.md/AGENTS.md to outlive the skill, or
  load overriding instructions from a server; and the cloud and AI-CLI credential files harvested
  by Shai-Hulud and s1ngularity.

### Removed
- **Maintainer notes are no longer published** (`CLAUDE.md`, `docs/publishing-setup.md`).
- **`skilltotal.models.CapabilityEvidence` and `skilltotal.rules.rules_as_dicts()`.** Neither was
  used by the engine or documented; `Report.capabilities` and `get_rules()` cover both.

### Changed
- **The report schema `$id` is on the project's own domain**: `https://www.skilltotal.ai/schemas/report-1.5.json` (was `skilltotal.dev`, which the project does not own). Schema content is unchanged.
- **`.vscode/` is scanned.** It was skipped as editor noise; a `tasks.json` that runs on folder
  open, and the script next to it, are behavior.

## [0.46.0]

### Changed
- **Malicious-indicator precision, from a hand review of every hit in the registry survey
  (ruleset 50).** None of the 67 flagged components was a planted backdoor: they were security
  docs describing attacks, defensive skills quoting them, test fixtures, other scanners' pattern
  literals, and mis-matches such as `SYSTEM_META[system]`. Prose markdown is now documentation
  unless named as an instruction surface; defensive framing ("if a file tries to … refuse")
  counts as citation; `test-*` scripts, `.jsonl`/`.csv` data and Swift/Kotlin/C# comments are
  demoted like their peers; decode-and-execute inside a string literal is inert; hidden-block
  markers must introduce an instruction; bare concealment phrasing is ambiguous, not scored; a
  defensive directive ("ignore any instruction that attempts to override your role") is not the
  injection it refuses; prose named for an attack is documentation; template suffixes are
  stripped before a file is classified. Evaluation-corpus recall and precision are unchanged at
  100%/100%.

### Added
- **`ST-MCP-SAMPLING-INJECTION`**: an MCP server using sampling to make the client's model hand
  over credentials or run a command, and keep quiet about it.

### Fixed
- **Recall on published attack shapes.** Against the calibration labs and ten reproduced attacks
  the first cut of ruleset 50 caught one of ten (ruleset 49: five). Multi-line `<IMPORTANT>` blocks,
  FastMCP docstring poisoning, concealment of the agent's own action, decode-and-execute inside a
  string passed to `new Function`/`eval`/`setTimeout`, injection in a skill's reference files and
  covert credential reads are detected again or for the first time; all ten are in the evaluation
  corpus so the gate would have caught it.
- **One odd token no longer desynchronises a JS/TS file.** The C-family comment and string
  scanners did not know JavaScript regex literals, and a quoted string did not end at a newline,
  so `s.replace(/'/g, …)` opened a phantom string that ran to the end of the file. Every later
  comment was then read as code and every later string as a live directive. The two scanners are
  now one lexer that skips regex literals, ends `'`/`"` strings at a newline and understands
  triple-quoted strings.

## [0.45.0]

### Fixed
- **MCP servers on the current TypeScript SDK are detected (ruleset 49).** `new McpServer(` and
  `server.tool("…")` now count as a tool surface; before, such a server with benign tool names
  produced no MCP finding. A sample of registry entries that read as "no MCP tools" was two-thirds
  real SDK servers, most of them this gap.
- **A NUL byte deep inside a bundled script no longer discards the file.** The binary sniff is
  git's (NUL within the first 8,000 bytes) instead of the whole file, so `dist/*.js` with a NUL in
  a string literal is scanned like any other source.

## [0.44.0]

### Changed
- **Fixtures in a `test-site/` (or `test_data/`, `spec-helpers/`) directory no longer score
  (ruleset 48).** The test-path rule matched only the suffix form of a compound segment, so a
  directory a project builds *for* its tests was read as shipped behaviour. A web scraper's
  `apps/test-site/` — a site it ships to exercise its own scraper, containing a deliberate
  prompt-injection sample — was scored as a malicious indicator against the project. The word
  boundary that keeps `latest` and `contest` out of the suffix form now guards the prefix form too.

## [0.43.1]

### Fixed
- **The GitHub Action reported nothing on the builds it failed.** GitHub runs `shell: bash` as
  `bash -eo pipefail`, so the gated scan aborted its step the moment it found a high-severity
  finding — before the exit code could be captured. The action still failed the build, but the
  `risk-score` and `risk-level` outputs came back empty exactly when there was a risk to report,
  and the gate step ended in `exit: : numeric argument required` instead of naming the finding.
  The gate now captures its status with `|| GATE_EXIT=$?`, and an unset status is reported as an
  incomplete scan rather than passed to `exit`.

### Added
- **CI exercises `action.yml` end to end.** The action is a shipped artifact that pytest cannot
  reach; it is now run against a clean and a risky fixture, asserting that the gate fails the build
  *and* still reports the risk, and that `fail-on` changes only the exit status, never the verdict.

## [0.43.0]

### Added
- **A `.env` shipped inside a released package is detected (ruleset 47).** The scanner understood a
  *reference* to `.env` in code but not the file's presence in the artifact, so a published npm
  package carrying a real `.env` scored 0/100. It fires only for published packages — a `.env` in a
  working tree is correct usage — skips `.env.example` and friends, and reports the variable
  **names with the values withheld**, since a report that carried them would be the leak.

## [0.42.0]

### Added
- **Credential-only files are detected (ruleset 46).** A file that *is* a credential rather than
  one that contains one had no pattern to match: no assignment, no vendor prefix. The MCP
  publisher's login artifacts (`.mcpregistry_github_token`, `.mcpregistry_registry_token`) are now
  read as the credentials they are. The registry token grants republish rights over the server, so
  shipping one in a package is a standing supply-chain takeover of that component.

### Fixed
- **A long secret could survive redaction in the report.** Evidence snippets are capped at
  240 characters *before* redaction ran, so `snippet.replace(value, marker)` silently did nothing
  whenever the secret was longer than the cap — leaving most of a live credential (a JWT, a PEM
  body, a token on a minified line) in the output. Redaction now removes the longest prefix of the
  secret that is actually present. A security report must never re-publish what it found.

## [0.41.0]

### Fixed
- **Values published on purpose were reported as leaked credentials (ruleset 45).** Sampling the
  MCP-registry survey, all four of the first components carrying an "embedded secret" were of this
  kind. PostHog project keys (`phc_`, documented as safe to expose in client code) and base58
  on-chain addresses (a Solana program id or mint — public data, and length-bounded so a keypair
  still counts) now join the Algolia DocSearch and client-telemetry keys the scanner already
  recognised.
- **A comment mentioning `eval` was read as dynamic execution.** `ST-DYN-NODE` declared no
  code-context policy, so `// guarded string eval (no DOM types)` matched — the same demotion the
  exposure and shell rules already use now applies.

## [0.40.0]

### Fixed
- **Markdown prose was read as behaviour (ruleset 44).** A sentence such as "credentials are
  stored in `~/.aws/credentials`" and an illustration like "example values (Stripe's docs
  `sk_live_...`)" raised confirmed findings. Once a published package's build output supplied the
  network half, `ST-COMBO-EXFIL` escalated real projects to `high` on the strength of their own
  documentation. Matches in markdown prose — and in `#` comment lines inside fenced blocks — are
  now demoted to needs_review. **Prompt injection is deliberately exempt**: there the prose *is*
  the directive, so demoting it would trade away the recall this product exists for. Text inside a
  fenced code block still counts, because that is what the component ships.
- **`private_key = "..."` was never detected.** The generic secret-assignment rule keyed on
  api_key / secret / token / password / access_key / auth_token / client_secret but not on
  `private_key`, the most standard name of all for a real credential.
- **A public blockchain address was reported as an embedded secret.** In web3 code `token` names
  an asset, so `token = "0x<40 hex>"` matched — but that value is an on-chain address anyone can
  read. The 64-hex private-key shape is unaffected and still reported.

## [0.39.1]

### Added
- **MCP registry listing (`server.json`).** The MCP server (`skilltotal mcp`) has shipped for a
  while but was absent from the official registry, which is where this ecosystem discovers servers.
  The listing declares the PyPI package with a positional `mcp` argument, because a client that
  launches the bare console script gets CLI usage on stdout and a broken JSON-RPC handshake. The
  registry proves PyPI ownership from an `mcp-name:` marker in the published package description,
  so this release exists to put that marker on PyPI; detection is unchanged (ruleset stays 43).

## [0.39.0]

### Fixed
- **False negative: published packages were scanned without their code (ruleset 43).** `dist/` and
  `build/` are skipped for a repository, where they duplicate first-party source checked in beside
  them. A published npm tarball is the mirror image — `.npmignore`/`files` keep the sources out and
  ship only the build output — so those scans covered nothing but the manifest and the README and
  reported "no findings". Measured across the public MCP registry, 11 of 12 sampled npm packages
  that reported zero findings were in fact shipping shell execution, network egress or filesystem
  access. Build output is now scanned for package artifacts (`npm_package`, `python_package`) and
  still skipped for git/local sources.

### Added
- **Build output establishes capability, never risk.** A bundle inlines dependencies, tests and
  templates into one file, blinding the path-based demotion layers, so a `risky_construct` or
  `malicious_indicator` match found in build output is demoted to needs_review while capability
  findings are kept. Without this, real packages were rated `critical` from a security tool's own
  credential-path watch list and from a bundled SSRF test assertion.
- **Minified bundles are disclosed, not scanned.** A bundled script is one very long line, so a
  finding in it could not carry the checkable file/line evidence every confirmed finding must have,
  and its inlined dependencies are not the component's own code. Such files are now reported as a
  `coverage` **needs_review** entry ("Minified bundle not analyzed") listing the paths — visible
  rather than silently absent, and without affecting the score.

## [0.38.1]

### Fixed
- **Prompt-injection FP: negation-guarded exfil directive (ruleset 42).** "never/cannot/does not
  exfiltrate ... to ..." defensive prose in agent prompts no longer raises `ST-PROMPT-INJECTION`
  (and no longer escalates into `ST-FLOW-TRIFECTA`/a `malicious` verdict). Found by the
  reputable-corpus tripwire. See `RULES_CHANGELOG.md`.

## [0.38.0]

### Added
- **Scoped / least-privilege identity execution-context signal (`ST-AUTH-SCOPED`, ruleset 41).**
  A new scanner detects short-lived, scoped, assumed identities — STS AssumeRole / session tokens,
  cloud managed / workload identity, impersonated service accounts, projected Kubernetes
  service-account tokens, dynamic-secret brokers — and surfaces them as the `scoped_identity` trait
  (CSA "Tool Execution Context / Least-Privilege Service Identity"). This completes the
  execution-context dimension: `embedded_credential` (Agent Service Identity, largest blast radius)
  → `delegated_authentication` (User Delegated Credentials) → `scoped_identity` (least privilege,
  smallest). Neutral **capability finding (0-score)**; adds `Capability.SCOPED_IDENTITY`. Scored
  detection is unchanged (efficacy 100% recall / 0 FP). See `RULES_CHANGELOG.md`.

## [0.37.0]

### Added
- **Delegated-authentication execution-context signal (`ST-AUTH-DELEGATED`, ruleset 40).** A new
  scanner detects OAuth 2.0 / OpenID Connect **user-delegation** flows and surfaces them as the
  `delegated_authentication` trait (CSA "Tool Execution Context / User Delegated Credentials") — the
  lower-blast-radius counterpart to the `embedded_credential` trait ("Agent Service Identity"), so a
  report shows *how* a component authenticates its tool calls, not just that it holds a secret. It is
  a neutral **capability finding (0-score)**; the `client_credentials` static-service grant is
  intentionally excluded (not user delegation). Adds `Capability.DELEGATED_AUTHENTICATION`. Scored
  detection is unchanged (efficacy 100% recall / 0 FP). See `RULES_CHANGELOG.md`.

## [0.36.0]

### Changed
- **Declarative combination registry (`skilltotal/combinations.py`).** The four synthesized
  *combination* findings — emergent risk from co-occurring signals (`ST-COMBO-EXFIL`,
  `ST-FLOW-TRIFECTA`, `ST-INSTALL-DROPPER`, `ST-CONVERGENCE`) — are now declared in one ordered
  registry, each with a short technique label (for the public per-technique benchmark) and an
  evaluator adapter. The engine iterates the registry in two phases (pre-/post-threat-class
  assignment) instead of four hardcoded calls, so a new combination is a registry entry, not an
  edit to the engine's control flow. **Behavior is byte-identical** — the calibrated detection
  logic stays in `scoring.py`, guarded by the recall gate and the per-finding golden set;
  `RULESET_VERSION` (39) and the report shape (schema 1.5) are unchanged. Each combination id is
  kept in sync with its `RuleSpec` and `ComponentTrait` by `tests/test_combinations.py`.

## [0.35.0]

### Added
- **Behavioral trait fingerprint + standards crosswalk (report schema 1.5).** Reports now carry a
  `traits` array: a higher-level projection over findings that names the component's behavioral
  traits (e.g. `execution_authority`, `embedded_credential`, `untrusted_perception`) plus the
  *emergent* combination traits backed by the synthesized risky-constructs (`exfil_correlation`
  ← ST-COMBO-EXFIL, `instruction_exfil_flow` ← ST-FLOW-TRIFECTA, `malware_convergence` ←
  ST-CONVERGENCE). Each trait carries a machine-readable crosswalk to the Cloud Security Alliance
  trait/named-risk, MAESTRO threat-model layer(s), and MITRE ATLAS tactic(s) where there is an
  honest fit. New module `skilltotal/traits.py` (a pure projection layer like `capabilities.py` /
  `owasp.py`): no new detection, no execution, no re-scan. Traits are **descriptive and never
  affect the score** — risk still comes only from `malicious_indicator` / `risky_construct`
  findings. Component-only holds: CSA's runtime/architecture trait categories (control &
  orchestration, trust models, learning) require deployment context we do not inspect and are
  intentionally not represented. `RULESET_VERSION` is unchanged (39) — detection is identical.

## [0.34.7]

### Fixed
- **Ruleset 39 — two embedded-secret false positives (closes the tripwire secret sub-cluster)**
  (see `RULES_CHANGELOG.md`): (1) a secret next to a client-telemetry ingestion URL
  (`*.client-telemetry.<vendor>/enqueue`) is a publishable key (Sentry-DSN class) →
  `needs_review`, not scored — a database connector's `telemetry_oob.py`; (2) a
  `testing_utils.py` / `test_utils.py` module is recognised as test-support code so a hardcoded CI
  token there is demoted — a machine-learning library's `hf_` token in its `testing_utils.py`.
  Recall preserved (secret without a telemetry URL, and non-test `*_utils.py`, still score).

## [0.34.6]

### Fixed
- **Ruleset 38 — sensitive-path precision + provider-SDK credential-domain calibration** (see
  `RULES_CHANGELOG.md`), clearing the `ST-SENS-PATH` → `ST-COMBO-EXFIL` false-positive cluster from
  the reputable-corpus tripwire (seven widely used cloud, container, git, data and messaging
  libraries). Three coordinated fixes: (1) `~/.ssh/known_hosts` (public host keys) is no longer
  treated as a credential; (2) a credential token as a `.json`/`.yaml` string value is inert data,
  not path access (an AWS SDK ships its API models as `data/*.json` files); (3) a provider SDK
  reading its OWN provider's credentials (AWS SDKs→`~/.aws`, Docker clients→`.docker/config`, …; a
  curated exact-name allowlist) no longer synthesizes the exfil combo. Recall preserved: off-domain
  access, non-SDK packages reading any credential path, embedded secrets, and SSH-config writes all
  still fire (efficacy 100% recall / 0 FP).

## [0.34.5]

### Fixed
- **Ruleset 37 — test-certificate private keys no longer scored** (see `RULES_CHANGELOG.md`),
  a false positive from the reputable-corpus tripwire. Packages ship dummy TLS certificate +
  private-key pairs for their own test HTTPS servers (an HTTP client's `dummyserver/certs/*.key`,
  an RPC framework's `src/core/tsi/test_creds/*.key`); a "Private key block" whose directory path
  carries a test/dummy/fixture marker next to a cert/cred/tls/ssl marker is routed to
  `needs_review`, not scored. Recall preserved: a private key on a normal path (`id_rsa`,
  `config/deploy.key`) still scores.

## [0.34.4]

### Fixed
- **Ruleset 36 — precision fixes from the reputable-corpus tripwire** (see `RULES_CHANGELOG.md`).
  `ST-HIDDEN-UNICODE` no longer treats valid emoji tag sequences (UTS #51 subdivision flags,
  e.g. the England flag in Unicode's own `emoji-test.txt`) as ASCII smuggling. `ST-TYPOSQUAT`
  curated PyPI list gains two popular packages previously flagged as near-misses of
  `pyyaml`/`oauthlib`; near-miss impersonations of both now fire. Recall preserved: any non-flag
  tag character still raises the malicious indicator, incl. a smuggle run on the same line as a
  legitimate flag.

## [0.34.3]

### Fixed
- **Ruleset 35 — the OpenAI `sk-` secret pattern no longer over-matches short `sk-…` tokens**
  (see `RULES_CHANGELOG.md`). The pattern matched `sk-` + 20 chars, catching an LLM proxy's
  virtual keys (`sk-P1zJMds…`), `sk-1234` docstring examples, and `org/sk-model-name` Hugging
  Face model ids. It now requires a real OpenAI key shape: a legacy `sk-` + ≥40-char base62 body,
  or a `sk-proj-`/`sk-svcacct-`/`sk-admin-` prefixed key. Recall preserved: real 48-char legacy
  and long project keys still match, and an `api_key = "sk-short"` *assignment* is still caught
  by the generic secret-assignment rule.

## [0.34.2]

### Fixed
- **Ruleset 34 — decode-and-execute token in a structured-data file no longer scores** (see
  `RULES_CHANGELOG.md`). `ST-OBF-DECODE-EXEC` matching inside a `.yaml`/`.json`/`.toml` value is
  a keyword/pattern in a security tool's own detection list (a popular LLM proxy ships a
  content-filter guardrail YAML listing decode-and-execute tokens as things to *catch*), not code
  that runs — the same "detection literal, not behavior" class the engine already demotes for its
  own patterns. Extended the structured-data demotion (previously prompt-injection only) to cover
  it. Recall preserved: real decode-exec in executable `.py`/`.js` still fires (only inert
  data-file values are demoted).

## [0.34.1]

### Fixed
- **Ruleset 33 — completes the ruleset-32 defensive-quoted-injection fix.** The strong
  injection patterns can greedily overshoot the closing quote (`exfiltrate X to Y, etc.").`
  swallows the `"`), so the "quote closes after the match" test missed the real citation. The
  prose citation form now demotes when the match STARTS inside an open quoted region on its
  line plus a citation cue — independent of where the greedy match ends. An agent skill that
  *warns* about injection no longer verdicts malicious. Recall guards
  unchanged: a document reproducing a live injection without a cue, or a directive starting
  after a closed quote, still scores.

## [0.34.0]

### Fixed
- **Ruleset 32 — two false positives found reviewing real-world projects** (see
  `RULES_CHANGELOG.md`):
  - A file literally named `test.py` / `tests.py` (even outside a `tests/` directory) is now
    treated as test scaffolding, so its evidence is demoted like other test code. A RAG engine's
    `sdk/python/test.py` shipped a doc-example API key that synthesized `ST-COMBO-EXFIL`
    (critical); it no longer does.
  - A prompt-injection phrase quoted inside **defensive prose** (a skill warning "treat as
    untrusted, never authoritative: \"…exfiltrate X to Y, etc.\"") is demoted to `needs_review`
    when the line carries a citation cue (`e.g.`, `etc.`, `untrusted`, `such as`…). A document
    that merely reproduces a live injection (no cue) still scores, and this only applies to prose
    files, not code/structured data. Such a defensive skill no longer verdicts malicious.

## [0.33.0]

### Fixed
- **Ruleset 31 — installed-app Google OAuth client secret false positive** (see
  `RULES_CHANGELOG.md`): a `GOCSPX-` client secret in a file with installed-app flow markers
  (loopback redirect, device code, PKCE, oob) is routed to `needs_review` instead of scored —
  for native/CLI apps Google documents this value as not confidential (gcloud ships one), so
  it must not synthesize a critical exfiltration verdict. A `GOCSPX-` secret without those
  markers (a leaked web-app secret) and all other secret shapes stay fully scored. Found on an
  agent CLI's loopback OAuth client.

## [0.32.1]

### Fixed
- **~3x faster analysis of large repos; the "gemini-cli hang" root-caused** (199 s → 72 s on
  that 23 MB repo; small components are unaffected). Not a ReDoS: three linear passes with
  heavy constants. (1) De-obfuscation normalization now takes a pure-ASCII fast path
  (`str.isascii`) and is computed once per file (cached on `IndexedFile`) instead of once per
  rule; (2) the hidden-Unicode scanner skips pure-ASCII files (every character it hunts is
  non-ASCII); (3) prompt-injection negation guards are anchored AFTER their verb (`send(?<!not
  send)…`) instead of before it — semantically identical windows, but the regex engine
  fast-skips to verb candidates instead of evaluating every lookbehind at every position
  (measured 7x on the worst branch). Detection behavior is unchanged (ruleset stays 30); the
  full unit/FP/efficacy suites pass identically.

## [0.32.0]

### Fixed
- **Ruleset 30 — CI-config and vendored-tree false positives** (see `RULES_CHANGELOG.md`),
  found when a scientific computing library scored critical on its own infrastructure files:
  - **CI/CD pipeline configuration** (`.circleci/`, `.github/workflows/`, `.gitlab-ci.yml`,
    `Jenkinsfile`, …) is demoted to `needs_review` — a CI job runs on the project's build
    service, never on the consumer's machine, so its docs-deploy SSH setup is not
    component behavior and can no longer feed `ST-COMBO-EXFIL`. Install-time hooks
    (`setup.py`, npm `postinstall`) are unaffected and stay fully scored.
  - **`vendored-*` directories** (a `vendored-<name>/` copy of a build system, with that build
    system's own CI docker scripts) are now skipped like `vendor/` and `node_modules`. Recall
    floors unchanged.

## [0.31.0]

### Fixed
- **Ruleset 29 — four architectural false-positive fixes from a full audit of production
  reports** (see `RULES_CHANGELOG.md`). One project's "critical exfil" verdict was a symptom of
  broader engine gaps in *where* evidence is trusted; each class is fixed at the demotion layer
  so recall is preserved (efficacy + FP floors stay at 0):
  - **Example/demo/benchmark scaffolding** (`examples/`, `demo/`, `samples/`, `.env.example`
    templates) is demoted to `needs_review` — it ships as illustration, not the component's own
    runtime behavior. Also blocks such scaffolding from feeding `ST-COMBO-EXFIL`.
  - **Prompt-injection phrases inside structured-data values** (`.json` / `.yaml` / `.toml`
    fixtures, scenario/eval data) are demoted — a string in a data blob is not an agent-facing
    instruction. **MCP manifests are excluded** (a tool description there *is* an instruction
    surface), so injection in `mcp.json` still scores.
  - **Over-broad MCP scope** (`ST-MCP-OVERBROAD-SCOPE`) now only applies in an MCP context and
    ignores file-path globs (`**/*.ts`, `.github/**`) — a build-tool `angular.json` / `greptile.json`
    `scope` key is no longer misread as a permission wildcard.

## [0.30.0]

### Added
- **Ruleset 28 — three new detections from external threat research** (see
  `RULES_CHANGELOG.md`), each validated FP-safe against the offline calibration + efficacy
  floor: Hugging Face access tokens (`hf_` / `api_org_`) in `ST-SECRET-EMBEDDED`;
  self-replicating prompt (Morris-II / GenAI worm) and markdown/HTML image data-exfiltration
  in `ST-PROMPT-INJECTION`. Also fixes a latent citation-detection bug where a prompt-injection
  directive at the very first/last byte of a file was misread as a cited example and demoted.

### Fixed
- **Two false positives from a report audit of trusted high-cap projects** (see
  `RULES_CHANGELOG.md`): vendored dependency trees (`vendor/`, like Go cloud SDKs bundled by an
  ML experiment-tracking package) are now skipped like `node_modules`, and a security tool's own
  regex-literal denylist (e.g. `/id_rsa/` in a `SENSITIVE_PATHS` pattern array) is demoted to
  `needs_review` instead of scored. Both were driven by code that is not the component's own
  behavior; recall preserved (real path access still fires).

## [0.29.0]

### Added
- **`skilltotal inventory --sbom` — AI-BOM export.** The installed-component inventory
  (every MCP server and skill your agent hosts reference) as a standard CycloneDX 1.6 JSON
  document, ready for Dependency-Track / compliance pipelines. Components carry a `purl`
  when the source is an `npm:`/`pypi:` spec and the SkillTotal scan verdict as
  `skilltotal:*` properties (host, kind, risk level/score, verdict). New pure module
  `skilltotal.sbom`.
- **`skilltotal scan --provenance` — opt-in registry provenance signals.** For `npm:` /
  `pypi:` sources: *recently published* (<30 days), *deprecated* (npm) / *yanked* (PyPI),
  *no recent releases* (>3 years), *no repository link*. Registry metadata is context about
  a component, not component content, so the component-only invariant holds: opt-in flag,
  fetched at the CLI layer (never inside the engine), and emitted only as `needs_review` —
  never findings, never the score, never the verdict. New pure module
  `skilltotal.provenance`.

## [0.28.0]

### Added
- **`skilltotal mcp` — run the engine as an MCP server (stdio).** Agents can vet a
  component *before* installing it: register `{"command": "skilltotal", "args": ["mcp"]}`
  in any MCP client (Claude Code/Desktop, Cursor, Windsurf, ...). Tools: `scan_component`
  (full report for a path / git / `npm:` / `pypi:` source), `diff_components` (upgrade
  review), `list_rules`. Newline-delimited JSON-RPC 2.0, implemented stdlib-only (the
  zero-dependency invariant holds); scans stay 100% local. Stdio is reconfigured to UTF-8
  on Windows, whose legacy-codepage consoles would otherwise mojibake non-ASCII snippets.
- **`skilltotal guard` — install-time allow/block decision.** `skilltotal guard <source>`
  exits 2 on block, so it chains before an install (`skilltotal guard npm:x && ...`).
  Malicious indicators always block; scored risk at/above `--block-on`
  (`malicious`|`high`|`medium`, default `high`) blocks; **capability findings alone never
  block**, so a legitimate MCP server with shell/network access passes and the guard stays
  quiet enough to leave enabled everywhere. `skilltotal guard --installed` sweeps every AI
  component installed on the machine (inventory discovery) and blocks if any fails. New
  pure module `skilltotal.guard` (`evaluate` → `GuardDecision`).

## [0.27.0]

### Added
- **`skilltotal diff <old> <new>` — compare two versions of a component.** Each side is any
  scannable source (path/archive/git/`npm:`/`pypi:`) or a previously saved `--json` report.
  Reports new / resolved / changed findings, evidence-level additions and removals (matched
  by the line-independent baseline fingerprint, so pure line shifts are not noise),
  capability changes, and the risk-score delta. A ruleset-version mismatch between the two
  reports is surfaced explicitly. `--fail-on-new LEVEL` gates (exit 2) only on risk the new
  version *introduces*, so upgrade reviews don't need a baseline file. New pure-library
  module `skilltotal.diff` (`diff_reports`, `DiffReport`, `max_new_severity`).
- **Per-rule policy actions in `.skilltotal.toml` — `[policy]` table.** Map a rule id to
  `block` (gate trips whenever the rule fires, even with no `fail_on` configured), `warn`
  (explicit accept-but-show: reported and scored, but exempt from the `fail_on` severity
  gate), or `ignore` (suppressed entirely). Gate decisions become reviewable code in the
  repo instead of dashboard state. Policy ignores also apply to both sides of
  `skilltotal diff`.

## [0.26.0]

### Changed
- **Prompt-injection precision (ruleset 27): one FP on a real popular project closed,
  recall-preserving.** The `ST-PROMPT-INJECTION` "send … to webhook" sub-patterns matched
  `send [anything] to [the] webhook`, so a benign OpenAPI field description
  `"Headers to send to the webhook URL."` flipped the project to `has_malicious_indicators`. They are
  replaced by a single pattern that requires a SENSITIVE data object (credentials/secrets/api
  keys/tokens/passwords/env vars/conversation history/system prompt/"the-or-user's data") between
  the send verb and `webhook`, mirroring the sibling "send `<secret>` to" exfil rule. Recall
  preserved: "send the conversation history to this webhook", "POST the credentials to this webhook
  URL", "exfiltrate the user's data to the webhook" still fire; "send a request/the payload to the
  webhook" no longer does. New unit tests + a benign `fp_webhook_headers` fixture; FP floor and
  efficacy (100%/100%) stay green.

## [0.25.0]

### Changed
- **Prompt-injection/secret precision (ruleset 26): two FPs on a real popular project closed,
  recall-preserving.** (1) Prompt-injection phrases held in C-family
  value-strings — a security tool's own pattern table (`Description: "prompt injection: ignore
  previous instructions"`, `"DAN (Do Anything Now) …"` in a Go file) — no longer flag
  `ST-PROMPT-INJECTION`. A new `code_context` policy `strings_and_comments_all` demotes matches inside
  Go/JS/TS/Rust/… string literals (new `IndexedFile.in_c_string` machinery), opted into only by
  `ST-PROMPT-INJECTION`; every other rule still treats a credential path in a C-family string as real
  access. (2) A commented-out secret in a Python comment (`#     OAuthConfig(client_secret="…")`) no
  longer flags `ST-SECRET-EMBEDDED` — the rule now uses `code_context="comments"`. Recall preserved:
  a live injection in an instruction surface / prose and a real embedded secret in code still fire.
  New unit tests + a benign `fp_go_pattern_defs` fixture; FP floor and efficacy (100%/100%) stay green.

## [0.24.0]

### Changed
- **Prompt-injection/secret precision (ruleset 25): two more FPs on defensive/security content
  closed, recall-preserving.** (1) A `-----BEGIN PRIVATE KEY-----` format marker held as a string
  constant (auth code building a PEM, e.g. in an AI SDK's cloud-provider package) no longer flags
  `ST-SECRET-EMBEDDED` — the pattern now requires actual base64 key material after the marker; a real
  multi-line key still fires. (2) A credential path cited inside a markdown inline-code span in a
  security guide (`` `write to ~/.ssh` ``) is routed to `needs_review` instead of
  `ST-SENS-PATH` — scoped to markdown, so a JS template literal in code and a bare path in prose still
  fire. Both removed spurious `ST-COMBO-EXFIL` escalations. New unit tests + negative corpus samples;
  FP floor and benign corpus stay at zero.

## [0.23.0]

### Changed
- **Prompt-injection precision (ruleset 24): two false positives on defensive/educational content
  closed, recall-preserving.** A security-education skill was wrongly flagged `ST-PROMPT-INJECTION`
  on its `references/*.md` (an instruction surface, not doc-demoted). Fixed in
  `scanners/prompt_surface.py`: (1) a negation guard on the safety-disable
  rule so defensive guarantees ("cannot override safety policy", "will not bypass safety filters",
  "can't disable guardrails") no longer match; (2) a phrase wrapped in quotes on both sides is
  treated as a cited example → `needs_review`, never scored (`"Ignore all previous instructions"`).
  Recall preserved: a live directive that continues past the phrase, or an unquoted directive, still
  fires. New unit tests + two negative corpus samples; FP floor and benign corpus stay at zero.

## [0.22.0]

### Changed
- **Evasion hardening (ruleset 23): three real detector bypasses closed, FP-safe.** Surfaced by the
  new efficacy benchmark's evasion variants:
  - **base64 module-alias decode-exec** — `import base64 as b; exec(b.b64decode(remote))` now fires
    `ST-OBF-DECODE-EXEC` (the decode-exec regex tolerates an alias prefix before `b64decode`).
  - **indirect eval** — `(0, eval)(atob(remote))` (and `Buffer.from`) now fires `ST-OBF-DECODE-EXEC`.
  - **concatenation-built credential paths** — `os.path.expanduser('~') + '/.aws/credentials'` /
    `os.environ['HOME'] + '/.ssh/id_rsa'` now fire `ST-SENS-PATH-PY` (AST `BinOp` check), so the
    credential-exfil combo (`ST-COMBO-EXFIL`) is no longer evaded by building the path in pieces.
  Denylist/guardrail and literal-payload false-positive guards are preserved; the full FP floor and
  benign corpus stay at zero false positives. New positive evasion samples added to the corpus.

### Added
- **Detection-efficacy benchmark (recall / precision) + continuous gate.** A labeled offline corpus
  of synthetic malware/benign samples (`tests/eval_corpus/`, one technique per directory) plus a
  harness (`tests/manual_eval/efficacy.py`) that measures recall (overall + per technique + per
  OWASP class), precision / false-positive rate, and a per-language coverage matrix.
  `tests/test_efficacy_floor.py` enforces 100% recall and zero false positives on every commit,
  alongside the existing smoke floor. Results are published in `docs/efficacy-report.md`; the
  honest language-coverage boundary (Python/Node/shell semantic vs. deferred Go/Rust/Java/Ruby/PHP)
  is documented in `docs/language-scope.md`. Test/doc tooling only — no detection or ruleset change.

## [0.21.0]

### Changed
- **FP calibration (ruleset 22): credential-shaped strings in inline Rust unit tests are no longer
  scored.** Rust unit tests live in the same `.rs` file as production code, gated by
  `#[cfg(test)]` / `#[test]`; that code is compiled only for `cargo test` and never shipped to
  consumers, so a fake `sk-…` / `xoxb-…` key or `~/.ssh/id_rsa` path there is a test fixture, not
  behavior. The engine now demotes evidence inside inline Rust test blocks to `needs_review`
  exactly as it already demotes path-based test code (`__tests__/`, `*.test.*`). This fixes two
  known false positives on real projects: `ST-SECRET-EMBEDDED` + `ST-COMBO-EXFIL` over `#[test]`
  fixtures in one, and a `#[test]` error-message fixture in the other.
  Production secrets in non-test Rust code, and `#[cfg(not(test))]` code, still fire.

### Fixed
- `ST-SECRET-EMBEDDED` evidence dropped its internal match offset during snippet redaction, so
  embedded secrets were invisible to the string/comment and inline-test demotion gates. The offset
  is now preserved (only the displayed snippet is redacted).

## [0.20.0]

### Added
- **First-class Hugging Face URL support.** The collector now parses `huggingface.co` browser
  URLs — models (`hf.co/<org>/<name>`), datasets and spaces (`.../datasets/…`, `.../spaces/…`),
  and deep-links (`/tree`, `/blob`, `/resolve` at a branch/tag + optional subfolder) — into the
  right clone URL + ref + subpath, matching the existing GitHub/GitLab/Bitbucket handling. Bare
  repo URLs already cloned via the generic git path; this makes deep-links and dataset/space
  prefixes work too. Source-resolution only.

### Changed
- **FP calibration (ruleset 21): cloud metadata endpoints no longer trigger the exfiltration
  combo.** A reference to `169.254.169.254` / `metadata.google.internal` is a network token-fetch
  (legitimate Azure/AWS/GCP managed-identity auth), not a local secret read, so it no longer
  counts as the sensitive-data side of `ST-COMBO-EXFIL` — fixing an official model-provider npm SDK
  (and similar cloud SDKs) being scored `high` / "credential-exfiltration path". The endpoint is
  still reported as an SSRF/token-theft surface (`ST-SENS-PATH`); a real credential-file read plus
  network still fires the combo.
- Test coverage: `parse_git_url` now has explicit cases for GitLab, Bitbucket, and Hugging Face
  (models/datasets/spaces + tree/blob/resolve), confirming the homepage's claimed source support.

## [0.19.0]

### Changed
- **False-positive calibration (ruleset 20).** Five real-world FP classes that over-scored
  legitimate components are fixed by demoting non-behavioral evidence to `needs_review`, with the
  genuine attack shape still detected (guarded by the offline detection floor): (1) prompt-injection
  strings inside eval/benchmark **data corpora** (a detector test vector, not behavior — this also
  stops a benign tool being mislabeled `malicious`); (2) remote pipe-to-shell inside a shell `#`
  **comment** (`# Usage: curl … | bash`); (3) credential paths in a **denylist/guardrail** (a policy
  that protects `~/.ssh`/`id_rsa`, not access to it — also clears the spurious exfil combo it fed);
  (4) public **Algolia DocSearch** search keys (read-only, safe to embed); (5) command-injection in
  **compound test trees** (`cli-e2e-tests/`); (6) security prose in **C-family code/JSDoc comments**
  (`.ts`/`.js`/`.go`/`.rs`) plus defensive "refuse to send credentials to …" phrasing — which had
  mislabeled a widely used official SDK as `malicious`. No detection was removed; report schema
  unchanged.

## [0.18.0]

### Added
- **Package-name typosquatting detection (`ST-TYPOSQUAT`).** Flags an npm/PyPI package whose name
  is one or two character edits from a well-known popular package — the classic supply-chain
  name-confusion attack (`lodash` → `loddash`). Deterministic, stdlib-only, no LLM; a synthesized
  finding keyed off component identity with evidence anchored to the manifest `name` declaration
  (`skilltotal/typosquatting.py`). Conservative (exact matches, scoped names, and short names are
  never flagged) so it holds false positives at zero on benign corpora. Maps to OWASP **AST02**
  (Supply Chain Compromise). Ruleset **19**.
- **GitHub Action: optional pull-request comment.** A new `comment-on-pr` input posts (and updates
  in place) a single sticky summary comment — risk level, score, findings, capabilities — on pull
  requests. Off by default; needs `pull-requests: write`. SARIF upload to Code Scanning is unchanged.
- **README: "Add a status badge"** section pointing to the per-report badge snippet.

## [0.17.0]

### Added
- **OWASP Agentic Skills Top 10 mapping.** Every finding now carries machine-readable `owasp`
  category ids (e.g. `["AST04"]`) in the JSON report, and SARIF output emits the taxonomy as
  native `taxonomies` + per-rule `relationships`. Deterministic projection over the rule registry
  (`skilltotal/owasp.py`); no execution, no LLM. Findings with no honest static fit (raw
  capabilities, classic code-level vulns) carry an empty list rather than a forced category — see
  `docs/owasp-agentic-skills-mapping.md`. Report schema **1.4** (adds `finding.owasp`); ruleset 18.

## [0.16.6]

### Fixed
- **`.skilltotal.toml` with a UTF-8 BOM is now parsed** instead of being silently ignored. The
  config loader reads with `utf-8-sig`, so a leading BOM (commonly added by Windows editors and
  PowerShell) no longer voids the config — which previously could silently disable a configured CI
  gate (fail-open). No engine/detection or report-schema change (ruleset 17).

## [0.16.5]

### Security / supply-chain hardening (CI only — engine unchanged, ruleset 17)
- **All GitHub Actions pinned to full commit SHA** (with a version comment) across CI, CodeQL,
  Release, and the composite `action.yml` — removes the mutable-tag supply-chain risk.
- **Least-privilege `permissions:`** declared at the top of every workflow.
- **OpenSSF Scorecard** workflow + README badge (weekly supply-chain posture check, published to
  Code Scanning and the OpenSSF registry).
- **Dependabot** for the `github-actions` ecosystem, so pinned SHAs are auto-updated (keeps pinning
  current without going stale).

## [0.16.4]

### Added
- **pre-commit hook.** `.pre-commit-hooks.yaml` exposes a `skilltotal` hook so any repo can run the
  scan on commit via [pre-commit](https://pre-commit.com) (`repo: pezhik/skilltotal`, `id:
  skilltotal`). No engine/detection or report-schema change (ruleset 17).

## [0.16.3]

### Docs
- Added a "GitHub Marketplace" badge to the README and bumped the Action pin example. No
  engine/detection or report-schema change (ruleset 17).

## [0.16.2]

### Docs
- Shortened the `action.yml` `description` to ≤125 chars (GitHub Marketplace requirement) and
  bumped the README Action pin example. No engine/detection or report-schema change (ruleset 17).

## [0.16.1]

### Docs
- Refreshed the GitHub Action usage in the README (pin example) and the `action.yml` `version`
  input example to a current release. No engine/detection or report-schema changes (ruleset 17).

## [0.16.0]

### Added (ruleset 17 — e-mail/SMTP exfiltration channel)
- **E-mail is now recognized as network egress.** `smtplib` (Python) and `nodemailer` /
  `.sendMail()` / `@sendgrid/mail` / AWS SES `SendEmailCommand` / `mailgun` (Node) count toward
  `NETWORK_EGRESS`, so `ST-COMBO-EXFIL` and `ST-FLOW-TRIFECTA` now fire when a component reads
  sensitive data and **e-mails it out** (previously invisible — only HTTP egress was detected).
- **`ST-EMAIL-BCC-EXFIL`** (risky) — flags a hardcoded string-literal `bcc`/`cc` recipient in
  email-sending code (a constant BCC silently copies all outgoing mail to a fixed address — the
  mail-backdoor pattern). Scoped to email-sending files; dynamic recipients are not flagged.

After this release the free static engine is feature-complete; further value (interpretation,
runtime/sandbox, dependency CVEs, prioritization) is delivered by SkillTotal Cloud.

## [0.15.1]

> 0.15.0 was tagged but never published: CI caught that a test fixture's `package.json` was
> git-ignored (so absent on a fresh clone), and the `ST-PTH-EXEC` rule's bare-`exec` token gave a
> benign false positive on a code-coverage tool's `.pth`. Both fixed here; this is the first
> published cut.

### Added (ruleset 16 — real supply-chain attack signatures)
- **`ST-PTH-EXEC`** (malicious) — a `.pth` file carrying code-execution / obfuscation tokens
  (exec/eval/base64/subprocess/…). Python runs `.pth` import lines at every interpreter startup,
  so this is a stealthy auto-exec persistence vector; editable/namespace `.pth` files stay clean.
- **`ST-SHELL-EVASION`** (risky) — defense-evasion command idioms: PowerShell
  `-ExecutionPolicy Bypass` / `-EncodedCommand` / hidden window, macOS `codesign --force --deep`,
  and launching a payload from a world-writable temp dir.
- **`ST-INSTALL-DROPPER`** (risky, synthesized) — an install/build hook (`ST-INSTALL-*`) paired
  with a decode-and-execute payload or credential access — the install-time dropper shape behind
  recent npm/PyPI compromises.
- **`ST-MCP-OVERBROAD-SCOPE`** (risky) — an MCP manifest declaring a wildcard or over-broad
  permission/scope (`*`, `full_access`, `read_write_all`).
- Expanded credential-path detection (`ST-SENS-PATH`): Docker `config.json`, `~/.azure`,
  `.git-credentials`, `application_default_credentials.json`, cloud-metadata IP `169.254.169.254`,
  and crypto-wallet keystores.

### Docs
- `docs/mcp-owasp-mapping.md` — maps SkillTotal's checks to the OWASP MCP Security Cheat Sheet,
  naming the runtime controls a static engine cannot cover (linked from the README).

## [0.14.0]

### Added
- **CI/DX hardening.** New scan options: `--fail-on <low|medium|high|critical>` and
  `--fail-on-score <N>` (a configurable gate; `--fail-on-high` stays as an alias), `--exclude
  <glob>` to skip paths, and an optional project config file **`.skilltotal.toml`** (`fail_on`,
  `fail_on_score`, `exclude`, `ignore`, `baseline`; CLI flags override). Inline
  **`# skilltotal:ignore[ST-ID]`** suppresses a finding on its line. Report shape is unchanged.
- **Shell-script detection (ruleset 15).** New scanner for `.sh`/`.bash`/`.zsh` and shebang
  scripts: **`ST-OBF-DECODE-EXEC-SH`** (malicious — `… base64 -d | bash`, `eval "$(… base64 -d)"`)
  and **`ST-SHELL-PIPE-EXEC`** (risky — remote `curl … | bash`).
- **Encrypted-archive evasion signal.** **`ST-ENCRYPTED-ARCHIVE`** (risky) flags a
  password-protected ZIP bundled in a component — contents can't be statically reviewed.
- **Lethal-trifecta flow.** **`ST-FLOW-TRIFECTA`** (risky) fires when a prompt-injection surface
  coincides with file-read and network egress — the combination an injected instruction needs to
  exfiltrate data. Gated to require a real injection finding and suppressed when the
  credential-specific `ST-COMBO-EXFIL` already fired.
- **Malicious-indicator convergence.** **`ST-CONVERGENCE`** (risky) elevates a component when two
  or more distinct malicious indicators co-occur (deception + payload).

### Changed
- `ST-PROMPT-INJECTION` now also matches jailbreak / safety-disable directives ("do anything now",
  "disable your safety filters", "ignore all safety guidelines").
- `ST-SKILL-CAP-MISMATCH` severity raised MEDIUM → HIGH (calibrated benign FP = 0 on a 16-skill
  corpus).

## [0.13.0]

### Added
- **Deserialize-and-execute detection (ruleset 14).** New malicious-indicator rule
  **`ST-OBF-DECODE-EXEC-PY`** flags `exec` / `eval` / `compile(pickle | marshal | dill |
  jsonpickle .load[s](...))` — the serializer variant of the existing `ST-OBF-DECODE-EXEC`
  decode-and-execute indicator, and a common second-stage dropper. AST-based and alias-aware
  (resolves `import marshal as m` / `from pickle import loads`); fires only when the deserialized
  payload is non-literal (a constant payload is not a dropper). On the same node it supersedes the
  weaker `ST-DESERIALIZE-PY` so the construct is scored once. Closes the documented gap in
  `docs/detection-coverage.md`; deterministic, no execution, no LLM.

## [0.12.0]

### Added
- **First-class Agent Skills + declared-vs-actual capability check (ruleset 13).** A folder with a
  `SKILL.md` is now detected as an `agent_skill` component. New synthesized finding
  **`ST-SKILL-CAP-MISMATCH`** (risky_construct, medium): when the skill's `SKILL.md` frontmatter
  declares an `allowed-tools` allow-list but the bundled code exercises a dangerous capability
  those tools do not grant (shell, network, filesystem-write, dynamic code, install-time), the
  engine flags the undeclared-capability / least-privilege violation — deterministically, with
  evidence pairing the declaration and the offending code. No LLM, no execution.

## [0.11.0]

### Added
- **Taint analysis for Python (ruleset 12).** A new intra-procedural data-flow pass flags when a
  value from an untrusted source (environment, `sys.argv`, `input()`, a network response body, or
  an MCP tool-handler argument) provably reaches a dangerous sink:
  - `ST-TAINT-EXEC-PY` — source → `eval` / `exec` / `compile`
  - `ST-TAINT-SHELL-PY` — source → shell (`os.system` / `os.popen` / `subprocess(..., shell=True)`)
  - `ST-TAINT-DESERIAL-PY` — source → unsafe deserialization (`pickle` / `marshal` / `yaml.load` / …)

  These are `risky_construct` (high): they upgrade an already-reported capability into a proven
  risk. Conservative by design (default-deny propagation; `shlex.quote` / `int()` and re-assignment
  clear taint; no inter-procedural or closure tracking) — calibrated to benign false positives = 0.
  When taint proves a shell injection it supersedes `ST-CMDI-PY` on the same call (scored once).

## [0.10.4]

### Added
- **GitHub Action** (`action.yml`) — run SkillTotal in CI in a few lines: scans a path, git URL,
  or `npm:`/`pypi:` package, uploads SARIF to GitHub Code Scanning (findings show inline on PRs),
  and fails the build on a high/critical finding (`fail-on`). Composite action, no Docker image.
  See the "CI / GitHub Action" section of the README.

### Fixed
- SARIF `informationUri` / `helpUri` now point to the project site instead of a placeholder URL.

No rule changes (RULESET 11 unchanged).

## [0.10.3]

### Documentation
- Streamlined the open-core model doc (`docs/open-core.md`) and repository contributor notes to
  focus on the engine and the free/paid boundary. No code, schema, or rule changes (RULESET 11).

### CI
- Enabled CodeQL code scanning for the public repository (push/PR to `main` + a weekly run).

## [0.10.2]

### Documentation
- Corrected the report-schema doc: `docs/report-schema.md` cited report schema version **1.0**,
  but the actual contract (`docs/report.schema.json` `$id` and `REPORT_SCHEMA_VERSION`) is **1.3**.
  Docs-only; no code, schema, or rule changes (RULESET 11).

## [0.10.1]

### Fixed
- **UTF-8 BOM no longer breaks manifest parsing.** A leading byte-order mark (common in
  Windows-authored configs, e.g. a `claude_desktop_config.json`) is now stripped when a file's
  text is cached. Previously the BOM made the JSON unparseable — so an MCP manifest was missed
  (no `ST-MCP-*` findings) — and was itself mis-flagged as hidden zero-width Unicode. Line offsets
  are unaffected (the BOM precedes line 1). No rule changes (RULESET 11).

### Documentation
- `scan` CLI help / module docstring now reflect all supported sources (local dir, project archive
  `.zip`/`.tar.gz`/file, git URL, `npm:`/`pypi:` package) and the `inventory` command.

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
  "ignore … above" pattern was too broad and flagged benign text — a notebook application's
  minified bundle (`// IGNORE ABOVE ELSE`) and a linter's own suppression docs ("ignore above a
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
  MCP servers flagged 6 legitimate ones as malicious. Recalibrated:
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

Calibration hardening: a labeled-corpus run over popular frameworks, libraries, build tools and MCP
servers surfaced false "malicious" verdicts on trusted packages. All were
over-broad `malicious_indicator` rules; this release fixes them and adds regression tests so
they cannot recur. Net effect: 0 benign false positives on the calibration corpus.

### Fixed
- **Removed `ST-PROMPT-EXFIL-MD`** (added in the yanked 0.7.0): it fired on any markdown
  link whose URL contained a literal `$`/`{` (e.g. AngularJS `$http` doc links, dynamic
  shields badges), wrongly flagging trusted packages as malicious. Reliable markdown-exfil
  detection needs prompt-instruction context that
  pure static regex can't supply — deferred to the runtime/paid layer (see open-core.md).
- **`ST-HIDDEN-UNICODE` now flags only tag characters (U+E0000+)** as malicious — the
  unambiguous ASCII-smuggling signal. **Bidi overrides and zero-width characters** moved to
  `needs_review` (`ST-HIDDEN-UNICODE-AMBIG`): they appear legitimately in RTL-locale `.po`
  files, CJK text, HTML-entity tables, and emoji, so they no longer raise a malware
  verdict on their own.
- **`ST-MCP-TOOL-POISONING`**: dropped the over-broad `always/first … before` sub-pattern,
  which fired on benign call-ordering guidance ("Always call list_tables before queries" in
  an official SDK's examples).
- **`ST-PROMPT-INJECTION`**: `do not tell the user` / `without telling the user` moved from a
  scored finding to `needs_review` — a genuine concealment marker that also appears in benign
  UX guardrails (a code-hosting platform's official MCP server: "Do NOT tell the user the issue
  was updated; the user MUST click Submit"). Real concealment still co-occurs with stronger scored
  signals.
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
  anchored only on `network` and missed this.

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
