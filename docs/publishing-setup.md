# Publishing setup (one-time)

Goal: you do **only** the things that require your own accounts/credentials. After that, the
assistant can create the repo, push commits, and publish releases to PyPI on its own — with
**no API tokens stored on disk** (releases go through GitHub Actions + PyPI Trusted Publishing
via OIDC).

---

## Part A — what only YOU can do (one-time)

### A1. Authenticate GitHub in this environment

This grants push access via the system credential store (no token written into the repo).

In the chat prompt, run the interactive login (the `!` prefix runs it in this session):

```
! gh auth login
```

Choose: GitHub.com → HTTPS → "Login with a web browser" (or paste a token). When done, also
run once:

```
! gh auth setup-git
```

That's it — the assistant can now create the repo, push, and tag from here.

> If you prefer not to use `gh`: create an empty public repo named **`skilltotal`** on GitHub
> yourself, then run `! git config --global credential.helper manager` and do the first
> `! git push` (a browser auth popup stores your credentials in Windows Credential Manager).
> After that the assistant can push.

### A2. PyPI account + Trusted Publisher (no tokens needed)

1. Create/sign in to a **PyPI** account (https://pypi.org), with 2FA. (And optionally
   **TestPyPI** https://test.pypi.org for a dry run.)
2. Go to **PyPI → Your account → Publishing → "Add a pending publisher"** and fill **exactly**:
   - **PyPI Project Name:** `skilltotal`
   - **Owner:** `<your-github-username>` (or org)
   - **Repository name:** `skilltotal`
   - **Workflow name:** `release.yml`
   - **Environment name:** `pypi`
3. Save. (This "pending publisher" lets the very first automated release create the project;
   after that it becomes a normal trusted publisher.)

That is the entire manual part. Everything below is done by the assistant.

---

## Part B — what the ASSISTANT does (after A1/A2)

1. Create the public repo and push:
   ```
   gh repo create skilltotal --public --source . --remote origin --push
   ```
   → triggers CI (lint, tests, bandit) and CodeQL on GitHub.
2. (Once) create the `pypi` GitHub Environment used by `release.yml`:
   ```
   gh api -X PUT repos/<owner>/skilltotal/environments/pypi
   ```
3. (Once) enable GitHub Secret Scanning + Push Protection (free for public repos) — the
   server-side secret-leak guard:
   ```
   gh api -X PATCH repos/<owner>/skilltotal \
     -f 'security_and_analysis[secret_scanning][status]=enabled' \
     -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
   ```
4. Routine commits: normal `git commit` + `git push` (already how we work locally). Local
   secret/lint/security hooks run via `pre-commit install`; CI re-checks on the server.

---

## Releasing a new version (assistant-run, repeatable)

No PyPI tokens involved — pushing the tag makes GitHub Actions build and publish via OIDC.

1. Bump `__version__` in `skilltotal/__init__.py` (and the relevant contract version; see
   [releasing.md](releasing.md)).
2. Update `CHANGELOG.md` / `RULES_CHANGELOG.md`.
3. Verify locally: `ruff check . && pytest && bandit -r skilltotal && python -m build && twine check dist/*`.
4. Commit, then tag and push the tag:
   ```
   git commit -am "Release vX.Y.Z"
   git tag vX.Y.Z
   git push && git push origin vX.Y.Z
   ```
5. `release.yml` checks `tag == __version__`, re-runs ruff/pytest/bandit, builds, `twine check`,
   and publishes to PyPI. Watch it: `gh run watch`.

> Optional fallback (manual local upload, needs a token and is less safe): create a PyPI API
> token, then `python -m build && twine upload dist/*`. Prefer the tag-based CI flow above.
