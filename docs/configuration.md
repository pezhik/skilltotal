# Configuration

How to configure a scan: the project config file, inline suppression, environment variables and
scanning through a registry mirror. The [README](../README.md) has the short version.

## Project config

Commit a `.skilltotal.toml` instead of repeating flags (CLI flags override it):

```toml
fail_on = "high"           # low | medium | high | critical
fail_on_score = 50         # or gate on the 0-100 risk score
fail_on_unanalyzed = true  # or when part of the component could not be analyzed (true/false)
exclude = ["vendor/*", "*.min.js"]
ignore = ["ST-NET-PY"]     # rule ids to drop
baseline = ".skilltotal-baseline.json"   # relative to this file

# Per-rule policy: reviewable gate decisions that live in the repo, not in a dashboard.
[policy]
"ST-SHELL-PIPE-EXEC" = "block"   # gate trips (exit 2) whenever this rule fires,
                                 # even with no fail_on configured
"ST-DESERIALIZE-PY" = "warn"     # explicit accept-but-show: reported, still counts toward
                                 # the risk score, but exempt from the fail_on severity gate
"ST-SENS-WORD" = "ignore"        # suppressed entirely (same effect as `ignore`)
```

The config is read from the directory you run `skilltotal` in (not from the scanned folder), or
from the file `--config` names; `--no-config` ignores it. A config it cannot honor stops the scan
with exit code 1, so a typo can't turn a gate off: invalid TOML, an unknown key, a value of the
wrong kind, an unknown policy action, a rule id in `ignore` or `[policy]` that no rule has (the
error suggests the closest id), or a `--config` path that does not exist. A relative `baseline`
path is resolved against the config file's folder.

An applied config is always named: on a `Config    :` line in the text report, as a
`config applied: ...` line on stderr with `--json` or `--sarif`, and in the report's
`metadata.config_applied`. A `baseline` set in the config is named there too.

> **Protect the config in CI.** The GitHub Action and the pre-commit hook run from the root of the
> repository they scan, so that repository's own `.skilltotal.toml` is applied, and a pull request
> can change it: lower `fail_on`, `ignore` a rule, point `baseline` at a file that suppresses
> everything. Inline `skilltotal:ignore` markers come with the code too. Put `.skilltotal.toml` and
> the baseline file under CODEOWNERS with branch protection, and review new ignore markers like any
> other code. When you scan code you don't control from its own root, pass `--no-config` (Action:
> `config: none`).

## Inline suppression

To accept a single finding, add a `skilltotal:ignore[ST-ID]` comment (any comment syntax: `#`,
`//`, `<!-- -->`) on the finding's line or on the line just above it. Several ids are separated by
commas; a bare `skilltotal:ignore` accepts every rule on that line. Inline markers count only when
you scan a local directory (your own code, as in CI). In a package, repository, archive or file
that SkillTotal fetches or unpacks they are ignored, so a component cannot silence its own
findings. Suppressed occurrences are counted in the report (`metadata.suppressed_count`).

A marker never hides a malicious indicator, in any source. The finding stays, and a
`needs_review` note says so. To accept one after review, record it in a baseline or set its rule
to `warn` under `[policy]`. A marker that names a rule id no rule has suppresses nothing and gets
a `needs_review` note suggesting the closest id.

## Environment variables

**Settings** (environment variables, for the CLI, the plugin and the action):

| Variable | Default | What it sets |
|---|---|---|
| `SKILLTOTAL_MAX_ARCHIVE_MB` | 150 | Largest archive downloaded or read |
| `SKILLTOTAL_MAX_EXTRACT_MB` | 400 | Largest total size an archive may extract to |
| `SKILLTOTAL_MAX_ARCHIVE_MEMBERS` | 30000 | Most entries an archive may hold |
| `SKILLTOTAL_MAX_CLONE_MB` | 200 | Largest git working tree cloned |
| `SKILLTOTAL_MAX_READABLE_MB` | same as clone | Most text a scan reads |
| `SKILLTOTAL_CLONE_TIMEOUT` | 300 | Seconds a git clone may take |
| `SKILLTOTAL_WORKERS` | up to 4 | Processes a large scan uses (1 for one) |

A source over a limit is refused with its size and the variable to raise. A value that is not a
positive whole number is an error. The registry mirror settings are described below.

## Scanning through a registry mirror

If your installers fetch from a company mirror (Artifactory, Nexus, Verdaccio, devpi), point
SkillTotal at it to scan the copy they get:

| Variable | Default | What it sets |
|---|---|---|
| `SKILLTOTAL_NPM_REGISTRY` | unset | npm registry mirror that `npm:` sources are fetched from |
| `SKILLTOTAL_PYPI_INDEX` | unset | PyPI mirror that `pypi:` sources are fetched from |
| `SKILLTOTAL_REGISTRY_TOKEN` | unset | Token sent to the mirror as `Authorization: Bearer` |

```bash
export SKILLTOTAL_NPM_REGISTRY=https://artifactory.example.com/artifactory/api/npm/npm-remote
export SKILLTOTAL_PYPI_INDEX=https://artifactory.example.com/artifactory/api/pypi/pypi-remote
export SKILLTOTAL_REGISTRY_TOKEN=...   # optional; from your CI secret store
skilltotal scan npm:left-pad
skilltotal scan pypi:requests==2.32.3
```

- `SKILLTOTAL_NPM_REGISTRY` is the base URL of an npm-protocol registry: SkillTotal reads
  `<base>/<name>/<version or tag>` (or `<base>/<name>`) and downloads `dist.tarball`.
- `SKILLTOTAL_PYPI_INDEX` is the base of a PyPI-style JSON API: SkillTotal reads
  `<base>/pypi/<name>/json` (or `<base>/pypi/<name>/<version>/json`), the way pypi.org,
  Artifactory and devpi serve it. It is not the `/simple` URL pip uses.
- The URL must be https (plain http only for `localhost`, `127.0.0.1` or `::1`) and must not hold
  a user name, password, query or fragment. Anything else stops the scan with an error naming the
  variable.
- The token is sent only to the mirror's own scheme and host. It is never sent to the public
  registries, never follows a redirect to another host, and never appears in a report or an
  error.
- Download URLs the mirror returns must be on the mirror's host or the public registry's file
  host (`registry.npmjs.org`, `files.pythonhosted.org`); anything else is refused. Redirects to
  plain http are refused.
- The report says where the package came from: `component.download_url` is the mirror's file
  URL, and a `needs_review` note ("Fetched through a registry mirror") names the mirror.
  `--provenance` reads the mirror too.

The settings come only from the environment of the process that runs the scan, never from the
scanned component. Unset, `npm:` and `pypi:` sources are fetched from the public registries as
before. The Claude Code plugin uses the mirror for installs whose configured registry is that
mirror (see
[docs/plugin.md](https://github.com/pezhik/skilltotal/blob/main/docs/plugin.md#custom-registries-and-mirrors)).
The plugin's own settings are listed in
[docs/plugin.md](https://github.com/pezhik/skilltotal/blob/main/docs/plugin.md).
