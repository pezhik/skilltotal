# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
("Report a vulnerability" on the repo's Security tab) or by email to
**contact@skilltotal.ai** — not in public issues. We aim to acknowledge within a few
business days.

## Preventing secret/key leakage (defense in depth)

SkillTotal is a security product; its own repo must not leak secrets. Four independent layers
guard against committing secrets or keys — no single layer is relied on alone:

1. **Local pre-commit hook** (`.pre-commit-config.yaml`): `gitleaks` + `detect-secrets` run on
   every `git commit` (install once with `pre-commit install`). Blocks the secret before it is
   committed.
2. **CI secret scan** (`.github/workflows/ci.yml` → `secrets` job): `gitleaks` runs on every
   push/PR with full history (`fetch-depth: 0`). Fails the build if a secret is found anywhere
   in the commit range.
3. **GitHub Push Protection** (server-side): on this **public** repo GitHub's platform push
   protection blocks a `git push` containing a recognized **partner** secret format (an AWS
   `AKIA…`, a Hugging Face `hf_…`, a GitHub `ghp_…` token, …) — a stop even if layers 1–2 are
   bypassed. This layer is **not disable-able by repo config** for partner patterns.
4. **No long-lived tokens** (OIDC): PyPI publishing uses **Trusted Publishing** (OpenID
   Connect) from GitHub Actions, so there are no PyPI API tokens stored in the repo, in CI
   secrets, or on any developer machine. There is no static publishing key to leak.

Supporting measures: `.gitignore` excludes common secret files (`.env`, `*.pem`, `*.key`,
`id_rsa`, `.pypirc`, `.npmrc`, …); a `detect-secrets` baseline (`.secrets.baseline`) tracks
reviewed non-secrets to keep scans signal-rich.

**This repo is a secret scanner — its `tests/` tree deliberately contains fake tokens as
detection inputs.** That would otherwise trip the very layers above, so the fixtures are handled,
not weakened:

- **gitleaks & GitHub secret-scanning alerts** allowlist the whole `tests/` tree
  (`.gitleaks.toml`, `.github/secret_scanning.yml`) — production code (`skilltotal/`) stays fully
  scanned, so a real leak there is still caught.
- **GitHub push protection** enforces partner patterns even inside `tests/` and can't be
  configured off, so a fixture must never commit a *contiguous* provider-pattern literal. Build it
  at runtime instead — `fake_token("hf_", "<body>")` (see `tests/test_secrets.py`) — so the scanned
  temp file gets the full value while the source has no matchable literal. **Never** resolve a
  blocked push via GitHub's per-secret allow URL: that keeps a real-looking token in public history
  forever.

## Code security of the engine itself

- `bandit` static analysis runs in CI (`security` job) and locally via pre-commit.
- CodeQL (`security-extended`) runs on push/PR and weekly.
- The runtime engine has **zero third-party dependencies** (minimal supply-chain surface) and
  never executes analyzed code.

## If a secret is ever exposed

Treat it as compromised: rotate/revoke it immediately at the provider, then purge it from
history (e.g. `git filter-repo`) and force-push. Because publishing uses OIDC, a leaked repo
contains no usable publishing credential.
