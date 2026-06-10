# Releasing the engine

`skilltotal` is published to PyPI with [semantic versioning](https://semver.org). Downstream
consumers (the web app) pin a version (`skilltotal==X.Y.Z`), so version discipline is the
contract.

## Version bump rules

| Change | Bump | Also |
|--------|------|------|
| New detection rule / scanner; better detection | **MINOR** | `RULESET_VERSION` += 1, `RULES_CHANGELOG.md` |
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
3. **Review docs that SHIP with the release**: `README.md` is the PyPI long description —
   it is frozen into the artifact at tag time (a stale Install/Usage section stays on the
   PyPI page until the next release). Check `docs/*` touched by the change too.
4. `ruff check . && pytest && bandit -r skilltotal` — all green (the release gate runs all
   three; ruff failures have blocked a tag before).
5. Commit, push, tag `vX.Y.Z`, push the tag — `release.yml` publishes via OIDC.

## Pre-release checklist

- [ ] Tests green, ruff clean, bandit clean
- [ ] Schema test passes (contract intact) — if it failed, the schema/version was bumped on purpose
- [ ] `CHANGELOG.md` / `RULES_CHANGELOG.md` updated (enforced by `tests/test_release_hygiene.py`)
- [ ] `README.md` Install/Usage accurate — it becomes the PyPI page (partially enforced by
      `tests/test_release_hygiene.py`)
- [ ] Correct version bump per the table above
