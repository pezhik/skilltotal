# Claude Code plugin: how it works

The [README](../README.md#claude-code-plugin) covers installing the plugin and what it decides.
This page is the reference: which commands the hook reads, what it does when it cannot check an
install, how CI strict mode works, the settings it reads, its cache and its timing, how to roll
it out to a team, and what to do when it does not work.

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
It follows tools that run a command for you: `corepack pnpm@9 ...`, `volta run`, `nvm exec`,
`fnm exec`, `cross-env`, `aws-vault exec`, `mise exec`/`mise use npm:x`, and `wsl`. When the tool
loads variables from a place the hook does not read (`dotenv --`, `direnv exec`, `op run --`,
`doppler run --`, `devbox run`, `nix-shell --run`, `mise exec`, `wsl`), a registry could be set
there, so the package counts as coming from a custom registry. A program the hook does not know
that is given an install command (`some-tool npm i x`) is asked about, and its package is still
checked.
Running a program the project already has in `node_modules/.bin` (`npx tsc`) installs nothing, so
the hook does not check it. It looks where npx looks: in npm's project folder (in a workspace
member, the workspace root) and the folders above it, for the program file itself (a `tsc.cmd`
alone does not count).

## What happens to the install

- **Malicious indicators:** the command is denied, and the agent is told the finding and its
  file:line.
- **High or critical risk:** Claude Code asks you to approve the install and shows the top
  finding.
- **Anything SkillTotal could not check:** Claude Code asks you. This covers:
  - a package from a custom registry, index or mirror (see
    [Custom registries](#custom-registries-and-mirrors))
  - a package name or an install command the shell builds when it runs (`npm i $PKG`)
  - a command hidden from the hook: decoded or assembled when it runs and then run
    (`eval "$(echo ... | base64 -d)"`, `... | base64 -d | sh`, `X=$(printf '\x6e...'); $X i x`,
    `iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(...)))`,
    `$c = "np" + "m"; & $c i x`, `& (gcm npm) i x`, `& ('n'+'pm') i x`)
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
- **MCP servers with no package:** a server reached at a URL (`claude mcp add --transport http`
  or `--transport sse`, `codex mcp add --url`, `claude mcp add-json` with a `url`) or run from a
  container image (`claude mcp add x -- docker run ... image`, `podman run`). Nothing is
  downloaded where SkillTotal could read it. Outside CI they are added as usual, with a console
  line.

### Custom registries and mirrors

SkillTotal scans the package from the public npm registry or PyPI, or from your mirror when you
set one (see "Checking through your mirror" below). When the installer is set to fetch from
somewhere else, that copy may not be what gets installed, so the package
counts as not checked: Claude Code asks you, and CI denies it unless `registry` is allowed. The
hook looks for another registry in:

- options on the command line: `--registry`, `--index-url`, `--extra-index-url` and similar
  (pnpm's `--config.registry`, `--userconfig`)
- the environment: `npm_config_registry` and any other `npm_config_*registry` (any letter case),
  `YARN_REGISTRY`, `YARN_NPM_REGISTRY_SERVER`, `BUN_CONFIG_REGISTRY`, `PIP_INDEX_URL`,
  `PIP_EXTRA_INDEX_URL`, `PIP_FIND_LINKS`, `UV_INDEX_URL`, `UV_DEFAULT_INDEX`,
  `UV_EXTRA_INDEX_URL`, `UV_INDEX` and `UV_FIND_LINKS`, whether set for the agent or in the
  command itself (`PIP_INDEX_URL=... pip install x`)
- npm's config files, read the way npm reads them (the last setting of a key wins, quotes and
  comments as npm takes them, keys under a `[section]` ignored): the `.npmrc` of the project (the
  nearest folder up from where the command runs that holds `package.json` or `node_modules`; in a
  workspace member, the workspace root), of the user (`NPM_CONFIG_USERCONFIG`, else `~/.npmrc`),
  and the global one when the user's file sets `prefix` or `globalconfig`
- pip's config files: `PIP_CONFIG_FILE`, the virtual environment's, the user's and the machine's
  `pip.conf` or `pip.ini`
- when the command runs yarn, bun, pnpm or uv, that tool's own files in the folder it runs in and
  the folders above it: `.yarnrc`, `.yarnrc.yml` (`npmRegistryServer`), `bunfig.toml`,
  `pnpm-workspace.yaml`, `uv.toml` and the `[tool.uv]` index settings of `pyproject.toml`

When the hook cannot tell which registry applies, it asks (CI denies): a config file larger than
it reads (64 KB, 256 KB for `pyproject.toml`), a project `.npmrc` that points npm at another config file (`userconfig`,
`globalconfig`, `prefix`), a key npm fills in from a variable, or a tool's registry setting that is
not one plain URL. npm's `tag` setting (`.npmrc` or `npm_config_tag`) picks the dist-tag a package
named without a version comes from; the hook checks that release (`npm:x@next`), and asks when the
tag is not one it can name.

A scoped registry (`@corp:registry=...`) counts only for packages of that scope. An extra index
or find-links location counts wherever it is set, since it can serve a newer version than the
public one. The console line and the reason show only the registry's scheme and host, never a
token or a path. A command that changes the installer's config before it installs
(`npm config set registry ...`, `echo registry=... > .npmrc`, `pip config set ...`) counts too.

**Checking through your mirror.** Set `SKILLTOTAL_NPM_REGISTRY` and/or `SKILLTOTAL_PYPI_INDEX`
(and `SKILLTOTAL_REGISTRY_TOKEN` if the mirror needs one) in the environment Claude Code runs in;
see the README's
[registry mirror section](https://github.com/pezhik/skilltotal#scanning-through-a-registry-mirror).
When the registry an install resolves to through the environment or the config files above is
that mirror, the hook checks the package there instead of calling it unchecked, and the console
line says "(from the registry mirror)". The URLs must match in scheme, host, port and path after
normalization (a trailing slash and letter case in the scheme and host do not matter; a user name
and password in the installer's URL are ignored). For pip and uv, the index may be the mirror's
base, `<base>/simple` or devpi's `<base>/+simple`.

For Python, the hook uses the index of the installer that runs. pip and pipx read
`PIP_INDEX_URL` and `pip.conf`. uv and uvx (including `uv pip`) read `UV_DEFAULT_INDEX`,
`UV_INDEX_URL`, `uv.toml` and `[tool.uv]`. Neither reads the other's settings, so `uv add x` with
only `PIP_INDEX_URL` on the mirror is checked on PyPI, where uv fetches it. When the hook cannot
tell which installer runs or what it reads, the package is not checked through the mirror and
stays unchecked. That covers poetry, pdm, pipenv, rye, pixi and similar tools, and a command
where pip and uv both appear and read different indexes.

The mirror counts only when no other registry or index is configured alongside it. These stay
unchecked (asked about, denied in CI unless `registry` is allowed):

- any other registry or index, including another path on the same host
- a mirror set only as an extra index (`PIP_EXTRA_INDEX_URL`, `extra-index-url`), or a main index
  on the mirror with an extra index elsewhere
- npm on the mirror while `YARN_REGISTRY` (or another tool's setting) names another registry
- a registry named on the command line (`--registry`, `--index-url`) or set in the command's own
  environment (`PIP_INDEX_URL=... pip install x`)
- a mirror setting that is not a usable URL (the console line says so)

A package whose installer reads the public registry is checked on the public registry, even when a
mirror is set. Only checks of mirror packages get the mirror settings and the token. A verdict for a
mirror package is cached separately from the public one, for an hour.

### The console line

Every install command gets one line in the Claude Code console: what was checked and its score,
the decision and why, or what was not checked (for example "SkillTotal did not check this install:
it installs from package-lock.json, and SkillTotal checks only the packages a command names.").
A `git clone` gets a line too: the repository it fetches is not checked (it is not denied for
that, in CI either).

## CI (strict mode)

In CI nobody is there to answer a question, so everything SkillTotal would ask about is denied.
So is every install it could not check, unless `SKILLTOTAL_ALLOW_UNCHECKED` lists its kind:

| Kind | What it covers |
|---|---|
| `lockfile` | An install from a lockfile, manifest or requirements file (`npm ci`, `pip install -r`, `uv sync`) |
| `local` | An install from a local path (`pip install -e .`, `npm install ./dir`) |
| `script` | A script downloaded and run (`curl ... \| bash`, `iex (irm ...)`) |
| `partial` | A package that was checked but not all of it (see below) |
| `remote` | An MCP server reached at a URL (`claude mcp add --transport http\|sse`, `codex mcp add --url`, `claude mcp add-json` with a `url`) |
| `container` | An MCP server run from a container image (`claude mcp add x -- docker run ... image`, `podman run`) |
| `registry` | A named package from a configured registry or mirror (see [Custom registries](#custom-registries-and-mirrors)) |

`registry` lets a CI job behind a company mirror install named packages without turning strict
mode off (`SKILLTOTAL_STRICT=0`), which would also let through everything else it asks about.
Outside CI, a package from such a registry is still asked about. Better still, set
`SKILLTOTAL_NPM_REGISTRY` / `SKILLTOTAL_PYPI_INDEX` to the mirror: its packages are then checked
there and need no `registry` allowance (see
[Custom registries](#custom-registries-and-mirrors)).

A partly analyzed package (a bundle too large to read, code in a language the engine does not
analyze) passes, and its console line names what was not read. What it runs at install is read
either way. `SKILLTOTAL_STRICT_PARTIAL=1` denies it unless `partial` is allowed.

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
`hook-cache.json` in `SKILLTOTAL_CACHE_DIR` when it is set, else in `skilltotal/` under
`XDG_CACHE_HOME`, `%LOCALAPPDATA%` or `~/.cache`, the first that is set; delete the file to start
over.

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
to start, install commands run unchecked, and Claude Code shows a warning on each one, so you can
tell a broken setup from a clean check. Commands that decode something and run it
(`base64 -d | sh`, `powershell -EncodedCommand`, `FromBase64String`, `certutil -decode`) get
that warning too.

A CLI older than the plugin still answers, with a warning, but it misses what newer releases
read. Each install command gets a line such as "SkillTotal CLI 0.66.0 is older than the plugin
0.69.0; update the skilltotal CLI ...". When such a CLI cannot judge a command the plugin could
not rule out, the line says it "could not judge this command", and CI denies the command. Update
both together (`pipx upgrade skilltotal` or `pip install -U skilltotal`) to get the newest
checks. In CI, every command is denied until the CLI works, and the console line says how to fix
it.

Outside CI, a command that cannot install anything (no installer, interpreter, shell, download or
decoder named in it, and nothing the shell fills in, such as `$`, globs or escapes) skips the CLI,
so `git status` or `ls` costs no Python start. In CI every command goes to the CLI.

The hook loads along with the plugins, so run `/reload-plugins` (or restart Claude Code) after
`/plugin install`. To see it work without touching a real package, ask the agent to run
`npm install --registry https://registry.example.invalid left-pad`. Claude Code should stop and ask
you, with SkillTotal's reason. Nothing is installed unless you approve.

The plugin also adds a `/skilltotal:scan <target>` command and registers the SkillTotal MCP server
(`skilltotal mcp`), so you do not need to add that server yourself.

`skilltotal hook claude-code --help` describes what the hook reads and answers: the event format,
`--protocol`, the settings and the exit codes.

## Settings

The hook reads these environment variables from the environment Claude Code runs in.

| Variable | Default | What it sets |
|---|---|---|
| `SKILLTOTAL_STRICT` | unset | `1` (or `true`, `yes`, `on`) turns CI strict mode on anywhere, `0` (or `false`, `no`, `off`) turns it off. Unset, strict mode follows the CI variables (see [CI](#ci-strict-mode)) |
| `SKILLTOTAL_ALLOW_UNCHECKED` | empty | Comma-separated kinds of unchecked install that strict mode lets through: `lockfile`, `local`, `script`, `partial`, `remote`, `container`, `registry` |
| `SKILLTOTAL_STRICT_PARTIAL` | off | `1`: strict mode also denies a partly analyzed package |
| `SKILLTOTAL_HOOK_BUDGET` | 60 (600 in strict mode) | Seconds all checks of one command share; at most 100 (840 in strict mode) |
| `SKILLTOTAL_WORKERS` | up to 4 | Processes one large check may use; `1` turns this off |
| `SKILLTOTAL_CACHE_DIR` | see [the verdict cache](#git-sources-the-verdict-cache-and-timing) | Folder for the verdict cache |
| `SKILLTOTAL_NPM_REGISTRY`, `SKILLTOTAL_PYPI_INDEX`, `SKILLTOTAL_REGISTRY_TOKEN` | unset | The registry mirror to check mirror packages through (see [Custom registries](#custom-registries-and-mirrors)) |

The scan limits in the README's
[settings table](https://github.com/pezhik/skilltotal#environment-variables)
(`SKILLTOTAL_MAX_ARCHIVE_MB` and the others) apply to the hook's checks too. If one of the
variables above has a value the hook cannot use, the console line says so. An unknown
`SKILLTOTAL_STRICT` or `SKILLTOTAL_STRICT_PARTIAL` value is read as on, so a typo cannot loosen
CI.

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
- **Platform-specific wheels.** A PyPI release is scanned as one of its files, chosen the same way
  on every machine: a pure-Python wheel when it has one, else a platform wheel in a fixed order
  (Linux x86-64, then Windows x64, then macOS, then the rest; the newest CPython first); the source
  distribution only when it has no wheel. The other files are not read, and the report says which
  file was scanned and how many were not; a wheel for another platform can carry different code.
- **Behavior in languages other than Python, JavaScript/TypeScript and shell.** Secrets, sensitive
  paths and hidden Unicode are still checked there. The console line says the package was partly
  analyzed.

It is a static guardrail, not a sandbox. For code you don't trust, run the agent in a container.

## Rolling out to a team

1. **Install the CLI at a pinned version** on each machine, for example
   `pipx install skilltotal==0.74.0`, with the same version as the plugin.
2. **Enable the plugin for everyone** with Claude Code's managed settings file,
   `managed-settings.json` in `/Library/Application Support/ClaudeCode/` (macOS),
   `/etc/claude-code/` (Linux and WSL) or `C:\Program Files\ClaudeCode\` (Windows). Register the
   marketplace under `extraKnownMarketplaces` and turn the plugin on under `enabledPlugins`:

   ```json
   {
     "extraKnownMarketplaces": {
       "skilltotal": {
         "source": { "source": "github", "repo": "pezhik/skilltotal", "ref": "v0.74.0" }
       }
     },
     "enabledPlugins": { "skilltotal@skilltotal": true }
   }
   ```

3. **Pin the plugin to a release.** Without `ref`, the marketplace follows the repository's
   default branch, so the plugin can change before you update the CLI. With `ref` set to a
   release tag, the plugin and the CLI move together when you change both. To control every
   change, fork or mirror the marketplace and point `repo` at your copy. See Claude Code's
   [plugin marketplace reference](https://code.claude.com/docs/en/plugins/marketplace-reference)
   and [managed settings](https://code.claude.com/docs/en/managed-settings) for the details.
4. **Allow internal packages.** Set `SKILLTOTAL_NPM_REGISTRY` / `SKILLTOTAL_PYPI_INDEX` (and
   `SKILLTOTAL_REGISTRY_TOKEN`) to your mirror so its packages are checked there. Packages from any
   other company registry are asked about on a workstation. In CI, allow them with
   `SKILLTOTAL_ALLOW_UNCHECKED=registry`, together with the other kinds your jobs need (`lockfile`
   for `npm ci`, for example).
5. **Know where decisions show.** Every install command gets a console line in Claude Code. The
   verdicts are kept in the cache file (see
   [the verdict cache](#git-sources-the-verdict-cache-and-timing)); `SKILLTOTAL_CACHE_DIR` moves it.

## Troubleshooting

- **"the skilltotal CLI is not on PATH".** The plugin could not find the CLI. Install it
  (`pipx install skilltotal`), run `pipx ensurepath`, and start Claude Code from a new terminal.
  `skilltotal --version` must work in that terminal.
- **"SkillTotal CLI X is older than the plugin Y".** The CLI still checks, but misses what newer
  releases read. Run `pipx upgrade skilltotal` or `pip install -U skilltotal`.
- **"not checked within SkillTotal's 60-second time limit".** A first check of a large package
  can take longer than the 60 seconds all checks of one command share. The check goes on in the
  background; run the same command again once it is done, or raise `SKILLTOTAL_HOOK_BUDGET`
  (up to 100 seconds, 840 in CI).
- **No console lines at all on Windows.** The hook command is
  `sh ".../hooks/pretooluse.sh"`, so it needs the `sh` that comes with
  [Git for Windows](https://gitforwindows.org). Run `/reload-plugins` or restart Claude Code
  after installing it.
- **Nothing happens after `/plugin install`.** Run `/reload-plugins` or restart Claude Code. To
  test it without touching a real package, see [The CLI the plugin calls](#the-cli-the-plugin-calls).
