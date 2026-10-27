# Releasing the engine

`skilltotal` is published to PyPI with [semantic versioning](https://semver.org). Downstream
consumers (the web app) pin a version (`skilltotal==X.Y.Z`), so version discipline is the
contract.

## Version bump rules

| Change | Bump | Also |
|--------|------|------|
| New detection rule / scanner; better detection | **MINOR** | `RULESET_VERSION` += 1, `RULES_CHANGELOG.md` |
| New optional report field (backward compatible) | **MINOR** | `REPORT_SCHEMA_VERSION` minor (1.9 → 1.10), `docs/report.schema.json` `$id` + "Added in", `docs/report-schema.md`, `CHANGELOG.md` |
| Bugfix that doesn't change the report shape or public API | **PATCH** | `CHANGELOG.md` |
| **Breaking** change to `report.schema.json` or the public API (`analyze`, `analyze_directory`, models) | **MAJOR** | `REPORT_SCHEMA_VERSION`, `docs/report.schema.json`, `CHANGELOG.md` |

The three version fields (in `skilltotal/__init__.py`) are independent on purpose:
`ENGINE_VERSION` (code/API), `REPORT_SCHEMA_VERSION` (report shape), `RULESET_VERSION`
(detection set). A consumer re-scans old inputs when `RULESET_VERSION` advances; it only
needs to migrate code when `REPORT_SCHEMA_VERSION` (major) advances.

## Steps

1. Update `__version__` in `skilltotal/__init__.py` (pyproject reads it dynamically —
   never edit a version there) and bump the relevant contract version.
2. Update `CHANGELOG.md` / `RULES_CHANGELOG.md`.
3. Regenerate the detection-efficacy report with
   `python tests/manual_eval/efficacy.py --out docs/efficacy-report` and update the sample
   counts `README.md` quotes from it. Bump the documented version pins to the new version:
   `uses: pezhik/skilltotal@vX.Y.Z`, `rev:`, `skilltotal==X.Y.Z` and `skilltotal@X.Y.Z` in
   `README.md`, `docs/ci.md`, `docs/cli.md`, `docs/mcp-server.md`, `docs/plugin.md`, `examples/`,
   `server.json`,
   `plugin/.claude-plugin/plugin.json` and `npm/package.json`. `tests/test_release_hygiene.py`
   fails the release on a stale report or `uses:` pin.
4. **Review docs that SHIP with the release**: `README.md` is the PyPI long description —
   it is frozen into the artifact at tag time (a stale Install/Usage section stays on the
   PyPI page until the next release). Check `docs/*` touched by the change too.
5. `ruff check . && pytest && bandit -r skilltotal` — all green (the release gate runs all
   three; ruff failures have blocked a tag before).
6. Commit and push. When CI is green on that commit, create a signed annotated tag
   (`git tag -s -m vX.Y.Z vX.Y.Z`) and push it. `release.yml` builds the release and publishes
   it through OIDC from the `pypi` and `npm` environments, which accept only `v*` tags. Before
   it publishes, it waits for a finished `ci.yml` run on the tagged commit with every required
   job green, and installs the built wheel and sdist into fresh environments on Linux, Windows
   and macOS (Python 3.10 and 3.14) to run the user journeys against them.

## Release cadence and guarantees

- Security fixes ship as a patch or minor release as soon as they pass the release gate. They
  are listed under Security in `CHANGELOG.md`.
- Detection changes (a new or changed rule, or a change in which files the rules read) ship in a
  minor release that bumps `RULESET_VERSION`, at most about once a week. Before the tag, each
  change is checked against a set of benign components for new false positives.
- Bug fixes ship in a patch release when ready.
- A breaking change to the report shape or the public API ships only with a major
  `REPORT_SCHEMA_VERSION` bump and is described in `CHANGELOG.md`.
- Every tag points at a commit that passed CI on Python 3.10 to 3.14 and on Windows; the release
  workflow checks this before it publishes. That run includes the end-to-end user journeys on
  Linux, Windows and macOS and the GitHub Action's own job.
- Release tags (`v*`) are signed, only a maintainer can create them, and they are never moved
  or deleted. A broken release is fixed by the next version. Pin an exact version
  (`skilltotal==X.Y.Z`, `pezhik/skilltotal@vX.Y.Z`) or, for the Action, the release's commit
  SHA.

## Pre-release checklist

- [ ] Tests green, ruff clean, bandit clean
- [ ] Schema test passes (contract intact) — if it failed, the schema/version was bumped on purpose
- [ ] `CHANGELOG.md` / `RULES_CHANGELOG.md` updated (enforced by `tests/test_release_hygiene.py`)
- [ ] `docs/efficacy-report.{json,md}` regenerated for this version and ruleset, and README quotes
      its sample counts (enforced by `tests/test_release_hygiene.py`)
- [ ] `README.md` Install/Quick start accurate: it becomes the PyPI page (partially enforced by
      `tests/test_release_hygiene.py`); `docs/cli.md` and `docs/ci.md` match the release
- [ ] Correct version bump per the table above
