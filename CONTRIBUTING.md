# Contributing to SkillTotal

Thanks for helping improve SkillTotal — the open-source engine that statically analyzes AI
components (MCP servers, agent skills/plugins, npm/PyPI packages, repos) for supply-chain
risk, dangerous capabilities, prompt-injection, and exfiltration.

## Ground rules (the product's invariants)

These are enforced in code and reviews — keep them in any change:

1. **Never execute analyzed code, never call an LLM.** Detection is deterministic regex +
   AST/JSON/markdown parsing only.
2. **Component-only analysis.** Derive everything from files inside the component — never from
   user/company/environment/runtime context.
3. **Every confirmed `Finding` carries evidence** (file/line/snippet). Signals that can't be
   anchored are emitted as `NeedsReview` and never affect the score.
4. **Interpret evidence, don't assert intent.** Describe what a matched API does, not unproven
   motive.
5. **Zero runtime dependencies** (Python stdlib only). Dev/test deps live in `.[dev]`.

## Dev setup

```bash
pip install -e ".[dev]"
pytest                       # full suite
ruff check .                 # lint
bandit -r skilltotal -q      # security scan (must be clean)
```

Requires Python 3.10+. `git` is needed only to scan remote URLs.

## Adding a detection rule

Corpus-driven and low-false-positive by design. The full process is in
[`docs/contributing-rules.md`](docs/contributing-rules.md): sanitized fixture → confirm the
gap → add the rule (a `RuleSpec` on a scanner under `skilltotal/scanners/`, registered in
`scanners/__init__.py`) → unit test → **calibrate against the trusted corpus**
(`tests/manual_eval/`) so it doesn't false-positive on legitimate packages → bump
`RULESET_VERSION` and update `RULES_CHANGELOG.md`.

A rule that flags a popular, legitimate package as malicious is a release blocker — false
positives erode trust faster than a missed edge case. New `malicious_indicator` rules in
particular must be validated on the calibration corpus before they ship.

## Pull requests

- Keep changes focused and traceable to the stated goal; follow existing conventions.
- Include tests; `ruff`, `pytest`, and `bandit` must be green.
- For docs that ship with a release, update them in the same commit as the change.

## Security

Please report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md). Do not open a
public issue for a security report.
