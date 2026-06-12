## What this changes

<!-- A short description. Link any related issue (e.g. Fixes #123). -->

## Type

- [ ] Bug fix
- [ ] New detection rule
- [ ] Feature / improvement
- [ ] Docs / packaging
- [ ] Refactor

## Checklist

- [ ] `ruff check .`, `pytest`, and `bandit -r skilltotal` are green
- [ ] Tests added/updated for the change
- [ ] For a **new/changed rule**: fixture + unit test added, calibrated against the trusted
      corpus (no new false positives), `RULESET_VERSION` bumped, `RULES_CHANGELOG.md` updated
      (see `docs/contributing-rules.md`)
- [ ] For user-facing changes: `CHANGELOG.md` updated
- [ ] No new runtime dependencies (the engine is zero-dependency by design)
