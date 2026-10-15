# Claude Code plugin: how it works

The [README](../README.md#claude-code-plugin) covers installing the plugin and what it decides.
This page is the reference: which commands the hook reads, what it does when it cannot check an
install, how CI strict mode works, the settings it reads, its cache and its timing.

Coding agents install packages in the middle of a task, and the permission prompt, if there is
one, shows only the command. The plugin checks each package on your machine, with the same engine
as the CLI, before the install command runs.

## Commands the hook recognizes

- npm packages: `npm`/`pnpm`/`yarn`/`bun` add or install, `npx`, `bunx`, `pnpx`, `npm exec`,
  `pnpm dlx`, `yarn dlx`, `bun x`, `npm create`, `volta install` and Deno's `npm:` packages
- Python packages: `pip` (also as `python -m pip`, and `pip download`/`pip wheel`), `uv`, `uvx`,
  `pipx`, `poetry add`, `pdm add`, `pipenv install`, `rye add`, `pixi add --pypi` and
  `easy_install`
- MCP servers: `claude mcp add`, `claude mcp add-json`, `codex mcp add` and `gemini mcp add`
- Skills and extensions from GitHub: `npx skills add owner/repo` and `gemini extensions install`

The hook reads a command the way the shell would, so it finds installs behind `sudo`, `env`,
`timeout`, `nohup`, `bash -c '...'`, `eval '...'`, `cmd /c`, `xargs` and `find -exec`. It also
finds them inside `$(...)`, `if` blocks, loops and functions; in a script piped to a shell or fed
to one through a here-document; and in chains like `cd x && npm i y`. On Windows, Claude Code runs
most commands through its PowerShell tool, and the hook also follows `$r = npm i ...`,
`& { ... }`, `iex '...'`, `Start-Process npm -ArgumentList ...` and `powershell -EncodedCommand`.
Running a program the project already has in `node_modules/.bin` (`npx tsc`) installs nothing, so
the hook does not check it.

## What happens to the install

- **Malicious indicators:** the command is denied, and the agent is told the finding and its
  file:line.
- **High or critical risk:** Claude Code asks you to approve the install and shows the top
  finding.
- **Anything SkillTotal could not check:** Claude Code asks you. This covers:
  - a package from a custom registry or index, set by an option (`--registry`, `--index-url`,
    `--extra-index-url`) or an environment variable (`npm_config_registry`, `PIP_INDEX_URL`)
  - a package name or an install command the shell builds when it runs (`npm i $PKG`)
  - a command hidden from the hook: decoded or assembled when it runs and then run
    (`eval "$(echo ... | base64 -d)"`, `... | base64 -d | sh`, `X=$(printf '\x6e...'); $X i x`,
    `iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(...)))`,
    `$c = "np" + "m"; & $c i x`)
  - an install inside a `node -e` or `python -c` one-liner, or one that decodes something and runs
    it
  - a direct archive URL
  - a git ref the scan cannot reproduce exactly
  - a check that failed
  - a check that did not finish within the 60 seconds that all checks of one command share (it
    goes on in the background, so the same command, run again once it is done, gets its verdict)
  - the sixth and later packages in one command
  - a package name a letter or two away from a popular one
  - a package with an install script SkillTotal could not read, or with nothing it could read
  - an error inside the hook: outside CI, SkillTotal never denies an install because of its own
    failure
- **Clean:** the package installs as usual, and the agent gets a one-line note with the version
  that was checked and its score. If part of the package could not be analyzed (code in a
  language SkillTotal does not analyze, a file too large or impossible to parse), the note says
  "partly analyzed" and lists what was left out.
- **Installs with no package name:** installs from a lockfile, manifest or requirements file
  (`npm ci`, `npm install`, `pip install -r`, `uv sync`, `poetry install`, updates such as
  `npm update`, and `uv run` in a project), from a local path (`pip install -e .`,
  `npm install ./dir`), or a script downloaded and run (`curl ... | bash`,
  `curl -o i.sh ... && bash i.sh`, `iex (irm ...)`). Outside CI they run as usual.

Every install command gets one line in the Claude Code console: what was checked and its score,
the decision and why, or what was not checked (for example "SkillTotal did not check this install:
it installs from package-lock.json, and SkillTotal checks only the packages a command names.").
A `git clone` gets a line too: the repository it fetches is not checked (it is not denied for
that, in CI either).

## CI (strict mode)

In CI nobody is there to answer a question, so everything SkillTotal would ask about is denied.
So is every install it could not check, by kind: an install from a lockfile, manifest or
requirements file (`lockfile`), from a local path (`local`) and a downloaded script (`script`). A
partly analyzed package (a bundle too large to read, code in a language the engine does not
analyze) passes, and its console line names what was not read. What it runs at install is read
either way. `SKILLTOTAL_STRICT_PARTIAL=1` denies it too.

Strict mode is on when `CI` or one of `TF_BUILD`, `JENKINS_URL`, `TEAMCITY_VERSION`,
`CODEBUILD_BUILD_ID`, `BUILDKITE` and `GITLAB_CI` is set to anything but empty, `0`, `false`, `no`
or `off`. `SKILLTOTAL_STRICT=1` (or `true`, `yes`, `on`) turns it on anywhere, and
`SKILLTOTAL_STRICT=0` turns it off. Any other value also turns it on, and the console line says
so. To let some kinds through, list them in `SKILLTOTAL_ALLOW_UNCHECKED`, for example
`SKILLTOTAL_ALLOW_UNCHECKED=lockfile,local`. Allowed kinds still get their console line.
Malicious indicators are denied in and out of CI.

In an unattended run (`claude -p`), Claude Code turns a question nobody can answer into a denial,
so a package that has not been checked yet is not installed there. Once its background check is
done, the same command goes through if the package is clean.

## Git sources, the verdict cache and timing

Packages from GitHub (`github:owner/repo#v1.2.0`, `git+https://github.com/...@ref`) and the
repositories that `npx skills add` and `gemini extensions install` fetch are scanned at the ref that
will be installed; checking them needs `git` on `PATH`.

A verdict is reused for the same artifact (an exact npm release or PyPI file for a week, a git
repository for an hour), so repeated `npx prettier` or `uvx ruff` calls don't trigger a rescan.
When the engine or ruleset version changes, everything is scanned again. The verdicts are kept in
`skilltotal/hook-cache.json` under `XDG_CACHE_HOME` (default `~/.cache`; `%LOCALAPPDATA%` on
Windows); delete it to start over.

A first check takes a second or two for a small package, about 10 seconds for one the size of
`typescript` or `lodash`, half a minute for `openai` and about a minute for `django` (about 2,000
files each), on a 4-core machine. A large package is checked by up to four processes at once;
`SKILLTOTAL_WORKERS` sets how many (1 turns this off). All checks of one command share 60
seconds; to wait longer before asking, set `SKILLTOTAL_HOOK_BUDGET` (in seconds, up to 100). In
CI, where a question becomes a denial, the hook instead waits up to 10 minutes for the full check
(`SKILLTOTAL_HOOK_BUDGET` goes up to 840 there). Once a package is downloaded, the hook uses its
size to estimate how long the check will take. If that does not fit in the time left, Claude Code
asks you right away instead of waiting it out. A check the hook stops waiting for goes on in the
background (two at a time at most, for up to 20 minutes) and saves its verdict, so the same
command, run again once it is done, gets that verdict at once.

## The CLI the plugin calls

The plugin calls the CLI, so install the CLI where Claude Code can find it: `skilltotal --version`
should work in the terminal you start Claude Code from. Outside CI, if the CLI is missing or fails
to start, install commands run unchecked; if it is too old to speak the plugin's hook protocol,
it still checks what it knows. Either way, Claude Code shows a warning on each install command, so
you can tell a broken setup from a clean check. A CLI that speaks the protocol but is older than
the plugin still decides, and each install command gets a line saying so ("SkillTotal CLI 0.66.0
is older than the plugin 0.69.0; update the skilltotal CLI ..."). Update both together
(`pipx upgrade skilltotal` or `pip install -U skilltotal`) to get the newest checks. In CI, every
command is denied until the CLI works, and the console line says how to fix it.

Outside CI, a command that cannot install anything (no installer, interpreter, shell, download or
decoder named in it, and nothing the shell fills in, such as `$`, globs or escapes) skips the CLI,
so `git status` or `ls` costs no Python start. In CI every command goes to the CLI.

The hook loads along with the plugins, so run `/reload-plugins` (or restart Claude Code) after
`/plugin install`. To see it work without touching a real package, ask the agent to run
`npm install --registry https://registry.example.invalid left-pad`. Claude Code should stop and ask
you, with SkillTotal's reason. Nothing is installed unless you approve.

The plugin also adds a `/skilltotal:scan <target>` command and registers the SkillTotal MCP server
(`skilltotal mcp`), so you do not need to add that server yourself.

## What the plugin does not check

- **Dependencies.** It scans the package a command names, not the packages it pulls in.
- **Installs that name no package.** `npm install`, `npm ci`, `pip install -r requirements.txt` and
  `uv sync` install from a lockfile or a requirements file, which the hook does not read. The hook
  says so in the console. In CI it denies them unless `SKILLTOTAL_ALLOW_UNCHECKED` includes
  `lockfile`.
- **Scripts and shell-profile definitions.** The hook reads only the command line. It does not
  read a script on disk (`bash install.sh`, `cat install.sh | bash`) or the aliases, functions and
  variables your shell profile defines, and such a command is not treated as an install: it runs
  without a console line, in CI too. Shell setup lines such as `eval "$(pyenv init -)"` or
  `eval "$(ssh-agent -s)"` run what another program prints and are let through the same way,
  unless the line decodes something or names an installer. A script the agent downloads and runs
  (`curl ... | bash`) is not read either, but that is an install: the hook says so in the console,
  and in CI it denies the command unless `SKILLTOTAL_ALLOW_UNCHECKED` includes `script`.
- **Repositories it clones.** `git clone` gets a console line saying the repository was not
  checked; scan it with `skilltotal scan <url>`.
- **A tampered verdict cache.** Verdicts are reused from `skilltotal/hook-cache.json`, a file any
  program running as you can write. An entry without the engine and ruleset version that produced
  it is ignored, but a program that can write that file can also replace the CLI itself: the hook
  does not defend against code already running on your account.
- **Minified bundles.** They are listed in the report but not analyzed, and a low verdict then
  reads "Partially analyzed". The scripts npm runs at install are the exception: they are analyzed
  even when minified.
- **SkillTotal's own reports.** A SARIF report, JSON report or baseline that SkillTotal wrote into
  the scanned folder is recognised by its content (pure JSON of exactly that shape), listed in the
  report and not scanned: its rule descriptions quote detection patterns.
- **Platform-specific wheels.** For a PyPI release that ships them, SkillTotal scans the source
  distribution; the wheel pip picks for your machine can differ from it. A release whose only
  wheel is pure Python is scanned as that wheel.
- **Behavior in languages other than Python, JavaScript/TypeScript and shell.** Secrets, sensitive
  paths and hidden Unicode are still checked there. The console line says the package was partly
  analyzed.

It is a static guardrail, not a sandbox. For code you don't trust, run the agent in a container.
