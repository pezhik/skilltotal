# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
("Report a vulnerability" on the repo's Security tab) or by email to
**contact@skilltotal.ai** — not in public issues. We aim to acknowledge within a few
business days.

### What to report privately, and what in public

- **Privately:** anything that lets a component make SkillTotal itself misbehave. For example,
  code from a scanned package, repository or archive that runs on the user's machine; an install
  command the Claude Code plugin should have read but missed, or an install it let through against
  its own verdict; a path escape during extraction; or a way to tamper with a report or a cached
  verdict.
- **In a public issue, or a pull request with a sanitized fixture:** a package that was scanned
  but that no rule flagged (a detection gap), or a false positive. Detection gaps are expected in
  a static scanner. They are fixed in the open, and the sample is added to the test corpus.

## Supported versions

Only the latest release receives fixes. The engine, the CLI, the Claude Code plugin, the GitHub
Action and the npm runner are released together under one version number. Upgrade the CLI with
`pipx upgrade skilltotal`; the plugin updates through its marketplace, and the GitHub Action and
the pre-commit hook move when you change the tag they are pinned to.

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
4. **No long-lived tokens** (OIDC): PyPI and npm publishing use **Trusted Publishing** (OpenID
   Connect) from GitHub Actions. No PyPI or npm API token is stored in the repo or in CI secrets,
   so there is no static publishing key to leak. What the release workflow publishes carries a
   PEP 740 attestation (PyPI) or npm provenance that points back to the workflow run that built
   it.

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

Treat it as compromised and rotate or revoke it at the provider immediately. Rotation is the fix.
A secret that reached a public repository has already been copied, and rewriting history does not
take it back (the default branch is protected against force-pushes). Because publishing uses OIDC,
the repository holds no publishing credential that could leak.
