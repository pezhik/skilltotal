# CI / GitHub Action

Run SkillTotal in CI and surface findings in your repository's **Security → Code scanning** tab.

```yaml
# .github/workflows/skilltotal.yml
name: SkillTotal
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # required to upload SARIF to Code Scanning
  actions: read            # required for the SARIF upload in a private repository
  pull-requests: write     # required only for comment-on-pr (optional)
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: pezhik/skilltotal@v0.84.0
        id: skilltotal
        with:
          source: .             # a path, a git URL, or an npm:/pypi:<name> spec
          fail-on: high         # fail on a high/critical risk finding (or 'none')
          fail-on-unanalyzed: 'false' # 'true': also fail when part of it could not be analyzed
          comment-on-pr: 'true' # post a sticky summary comment on pull requests (optional)
          # upload-sarif: 'false'     # a private repository without GitHub Advanced Security
      # Runners are discarded after the job: keep the report as an artifact, also after a tripped gate
      - if: always()
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: skilltotal-report
          path: skilltotal.sarif
      - if: always()
        run: echo "verdict=$VERDICT score=$SCORE"
        env:
          VERDICT: ${{ steps.skilltotal.outputs.verdict }}
          SCORE: ${{ steps.skilltotal.outputs.risk-score }}
```

`on: [push, pull_request]` runs the scan twice for a branch with an open pull request, once for
each event. To scan once, limit `push` to your default branch (`push: { branches: [main] }`).

The action runs the engine that ships with the tag you pin, so nothing is downloaded from PyPI and
the tag pins the scanner too. Pin it to a released tag (see
[Releases](https://github.com/pezhik/skilltotal/releases)), or to that release's commit SHA
(`pezhik/skilltotal@<commit> # vX.Y.Z`), which, unlike a tag, cannot be moved. Without the action,
the same scan is `skilltotal scan . --sarif --output skilltotal.sarif --fail-on-high`.

| Input | Default | What it does |
|---|---|---|
| `source` | `.` | A path in the repository, a git URL, or an `npm:`/`pypi:<name>` spec |
| `fail-on` | empty | `low`, `medium`, `high`, `critical` or `none`. Empty uses the gate of the applied `.skilltotal.toml` (`fail_on` / `fail_on_score`) when it sets one, else `high`. A level overrides the config's `fail_on`; `none` turns off every gate the config sets |
| `fail-on-score` | empty | Also fail at or above this risk score (0-100); overrides the config's `fail_on_score` |
| `fail-on-unanalyzed` | `false` | `true`: also fail when part of the component could not be analyzed |
| `exclude` | empty | Path globs to skip, relative to `source`, one per line or comma-separated (added to the config's `exclude`) |
| `config` | empty | Path to a `.skilltotal.toml`. Empty reads one from the working directory if present; `none` ignores any config |
| `baseline` | empty | Baseline file of accepted findings |
| `upload-sarif` | `true` | Upload SARIF to Code Scanning (needs `security-events: write`) |
| `sarif-file` | `skilltotal.sarif` | Where the SARIF report is written. A missing folder is created |
| `sarif-category` | empty | Code Scanning category. Empty: none for `source: .`, else `skilltotal/<source>`, so two scans in one job keep their alerts apart |
| `comment-on-pr` | `false` | Post a summary comment on pull requests (needs `pull-requests: write`) |
| `version` | empty | Install this `skilltotal` release from PyPI instead of running the engine that ships with the tag. It must be at least as new as the action; an older one gives a warning |

Outputs: `risk-level`, `risk-score`, `sarif-file` and `verdict`, which is `malicious` whenever a
malicious indicator was found, whatever the score. Read them as
`steps.<id>.outputs.<name>` after giving the step an `id`. A tripped gate fails the step, so a
later step that should still run needs `if: always()`.

How it behaves:

- **The gate decides the job.** The [gate semantics](cli.md#exit-codes) apply: a malicious indicator fails the job at
  any severity, and a capability on its own, such as a shell call or network access, never does.
  The Scan step's log says which gate tripped, and each gate line is also an error annotation.
  With `fail-on` empty and no gate in `.skilltotal.toml`, the log names the gate
  `fail-on high (action default)`.
- **Errors are not verdicts.** A usage, config or fetch error fails the job as "SkillTotal could
  not run the scan (exit 1): ...", not as a tripped gate.
- **Job summary.** Each run writes one: the applied `.skilltotal.toml` and what it sets, the
  verdict, the risk score and the gate result, the gate lines that tripped, a table of risk findings
  (severity, rule, file:line and title; up to 20, then a count), the capabilities, and how many
  findings a baseline or inline marker suppressed. The pull request comment says the same in
  short. A pull request that changes the applied config gets a warning when the base branch is
  fetched (`fetch-depth: 0`).
- **The log lists the findings.** It prints a count of risk findings and, separately, capability
  findings (not scored, never gated), then every location of each risk finding: up to 10 per rule,
  then "and N more" (the SARIF and JSON reports have them all). When Code Scanning is off, this is
  where you read why the gate failed. Text from the scanned files cannot issue workflow commands
  in the log.
- **SARIF paths.** For a `source` in a subfolder, SARIF locations are made relative to the
  repository root, so alerts point at real files. SARIF for an `npm:`, `pypi:` or git-URL source is
  written to `sarif-file` but not uploaded: its alerts would point at files the repository does not
  have. For an `npm:` or `pypi:` source it describes the same release the gate scanned. If the
  SARIF report cannot be written, the action warns and skips the upload; the gate still decides
  the job.
- **Without Code Scanning.** A private repository has Code Scanning only with GitHub Advanced
  Security. Without it, GitHub's upload action shows an error annotation of its own, the next step
  prints a warning explaining why, and the job result is still decided by the gate. Set
  `upload-sarif: 'false'` to skip the upload, and keep the report with `actions/upload-artifact`
  as in the example above: the runner and its files are gone after the job.
- **PR comment.** With `comment-on-pr: 'true'`, the action keeps one comment on the pull request
  up to date: the verdict, the risk and the gate result, the gate lines, the top five risk
  findings with file:line, the capabilities, the suppressed count and a link to the workflow run.
  On a pull request from a fork the token is read-only: the comment is skipped with a warning,
  and the job is not failed for it.
- **The repository's config is applied.** See [Protect the config in CI](configuration.md#project-config).

To re-check a third-party package you depend on, on a schedule:

```yaml
on:
  schedule: [{ cron: '0 6 * * 1' }]   # runs only from the default branch
jobs:
  mcp-server:
    runs-on: ubuntu-latest
    permissions: { contents: read }
    steps:
      - uses: pezhik/skilltotal@v0.84.0
        with:
          source: npm:some-mcp-server@1.4.2
          config: none         # this repository's .skilltotal.toml is not about that package
```

## Use as a pre-commit hook

Run SkillTotal on every commit via [pre-commit](https://pre-commit.com):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pezhik/skilltotal
    rev: v0.84.0
    hooks:
      - id: skilltotal
        args: [".", "--fail-on-high"]   # scan the repo; block the commit on a high/critical finding
```

Then `pre-commit install`. The hook installs the CLI in its own environment and scans the repo
on commit; tune the scan with the same flags as the CLI (e.g. `--exclude`, `--fail-on`). It scans
what the commit will contain (`skilltotal scan --staged`): every file in git's index across the
whole repository, not only the changed files, so the verdict matches what CI sees. Untracked
and ignored files are left out. The repository's `.skilltotal.toml` applies here too.

## Other CI systems

Anywhere Python 3.10+ runs, install a pinned release and gate on the exit code: 0 passed, 2 a gate
tripped, 1 the scan could not run. SkillTotal writes SARIF 2.1.0 (`--sarif`) and its own JSON
report; it does not write GitLab's security report format, so publish the files as job artifacts.
Write reports outside the scanned folder, or into a folder you `--exclude` (SkillTotal also
recognises its own SARIF, JSON and baseline files by content and skips them). `--output` does not
create folders, so create the report folder first.

A shell step (a virtual environment outside the checkout, so it is not scanned):

```bash
python3 -m venv "$HOME/.skilltotal-venv"
"$HOME/.skilltotal-venv/bin/pip" install skilltotal==0.84.0
OUT="$(mktemp -d)"
"$HOME/.skilltotal-venv/bin/skilltotal" scan . --sarif --output "$OUT/skilltotal.sarif" --fail-on high
```

Where pipx is on `PATH`, `pipx run --spec skilltotal==0.84.0 skilltotal` followed by the same
arguments runs the pinned CLI without a virtual environment. The `python:*-slim` images do not
include pipx.

GitLab CI (`allow_failure: exit_codes: [2]` would turn the gate into a warning):

```yaml
skilltotal:
  image: python:3.12-slim
  script:
    - pip install skilltotal==0.84.0
    - mkdir -p skilltotal-reports
    - skilltotal scan . --exclude "skilltotal-reports/*" --sarif --output skilltotal-reports/skilltotal.sarif --fail-on high
  artifacts:
    when: always
    paths: [skilltotal-reports/]
```

Jenkins (declarative pipeline, Docker agent):

```groovy
stage('SkillTotal') {
  agent { docker { image 'python:3.12-slim' } }
  steps {
    sh '''
      python -m venv .skilltotal-venv    # a virtual environment is not scanned
      .skilltotal-venv/bin/pip install skilltotal==0.84.0
      mkdir -p skilltotal-reports
      .skilltotal-venv/bin/skilltotal scan . --exclude "skilltotal-reports/*" --sarif --output skilltotal-reports/skilltotal.sarif --fail-on high
    '''
  }
  post { always { archiveArtifacts artifacts: 'skilltotal-reports/*', allowEmptyArchive: true } }
}
```

For a JSON report, drop `--sarif` (`--output` then writes JSON). To publish both, run the scan
twice: once with `--fail-on none` for the report, once with the gate.

## Rolling out on an existing repository

1. **Record what is there today.** `skilltotal scan . --write-baseline .skilltotal-baseline.json`
   writes a baseline of the current findings and exits 0. Read the report first: a baseline
   accepts everything in it, malicious indicators included.
2. **Gate only new findings.** Commit the baseline and a `.skilltotal.toml` with
   `baseline = ".skilltotal-baseline.json"` and `fail_on = "high"` (or pass the action's `baseline`
   input). Findings already in the baseline no longer trip the gate; new ones do.
3. **Protect the gate.** Put `.skilltotal.toml` and the baseline under CODEOWNERS with branch
   protection, so loosening them needs a review.
4. **Accept a false positive.** For one occurrence, prefer an inline
   `# skilltotal:ignore[ST-ID]` on its line or the line above: it sits next to the code and is
   reviewed with it. A malicious indicator needs the baseline or a `[policy]` `warn` instead.
   Re-writing the baseline accepts every current finding at once, which is convenient after a
   review but easy to misuse. A `[policy]` `warn` or `ignore` applies to a rule
   everywhere. [Report false positives](https://github.com/pezhik/skilltotal/issues) too: they are
   fixed in the open.
5. **Decide on `--fail-on-unanalyzed`.** It is off by default, so the gate passes code the scan
   could not read: files over 2 MiB, minified bundles, code in languages whose behavior is not
   analyzed, and compiled code shipped without its source. The log still reports that code on every
   run (`Not everything was analyzed: ...`; the action adds a warning annotation). Turned on, the flag
   fails closed on that code, which also fails a repository that commits bundles or Go code, so
   turn it on for the third-party components you scan rather than for your own repository. Do not
   `exclude` an install script to get past it: an install script the scan cannot read fails every
   gate closed, whatever the flag.
