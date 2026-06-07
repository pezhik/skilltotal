# Manual evaluation harness

Out-of-band calibration material for SkillTotal. **Not run by `pytest`** — these are
scripts for manually checking detection quality against (a) hand-built malicious fixtures
based on real attacks, and (b) a corpus of real third-party components.

```bash
# Scan the malicious fixtures
python tests/manual_eval/run_eval.py

# Fetch the real-world corpus (git required), then scan everything
python tests/manual_eval/fetch_corpus.py
python tests/manual_eval/run_eval.py --corpus
```

## Malicious fixtures (`malicious/`)

Each is modeled on a documented, real-world attack technique — built from the *technique*,
not from SkillTotal's own rules, so they probe for real gaps. All endpoints are
non-existent `.test` domains and payloads are inert; SkillTotal only analyzes statically.

| Fixture | Real-world technique | What it should trigger |
|---------|----------------------|------------------------|
| `mcp-tool-poisoning/` | **MCP Tool Poisoning** (Invariant Labs, Apr 2025): hidden instructions in a tool `description`/`inputSchema` that the model reads but the user never sees, telling the agent to read `~/.ssh`/`~/.aws` and hide it. | `ST-MCP-DANGEROUS-TOOL`, `ST-SENS-PATH`, `ST-PROMPT-INJECTION` → HIGH |
| `npm-trapdoor-stealer/` | **TrapDoor** (2026): npm `postinstall` runs a credential harvester reading `~/.aws`, `~/.ssh`, `.npmrc`, env, base64-encodes and POSTs to a webhook. | `ST-INSTALL-NPM`, `ST-FS-NODE-READ`, `ST-SENS-PATH`, `ST-NET-NODE`, `ST-COMBO-FS-NET` → CRITICAL |
| `pypi-importtime-stealer/` | **TrapDoor** PyPI variant: import-time execution + `exec(base64.b64decode(...))` that reads creds and exfiltrates via `urllib`. | `ST-DYN-PY`, `ST-OBF-DECODE-EXEC`, `ST-SENS-PATH`, `ST-FS-PY-READ`, `ST-NET-PY`, `ST-COMBO-FS-NET` → CRITICAL |
| `zero-width-injection/` | **ASCII smuggling / zero-width Unicode** (used by TrapDoor to hide prompts): a benign-looking `SKILL.md` whose instructions are encoded in invisible Unicode tag characters + zero-width chars. | `ST-HIDDEN-UNICODE` → HIGH. *This was a real detection gap found during calibration; the `invisible_unicode` scanner was added to close it.* Regenerate with `python tests/manual_eval/gen_zero_width.py`. |
| `agent-instruction-override/` | **Prompt injection in agent instructions** (`AGENTS.md`): "ignore previous instructions", "do not tell the user", collect tokens / read credentials, send to webhook. | `ST-SENS-PATH`, `ST-PROMPT-INJECTION` → MEDIUM |

> Note on the risk scale: a single HIGH finding scores 20 → `risk_level` LOW (band is
> 0–24). CI gating uses `--fail-on-high` (which keys off finding *severity*), so these
> fixtures still block a build even when the aggregate level reads low.

## Real-world corpus (`corpus/`, git-ignored)

Third-party repos used to check false positives (trusted code) and true positives (real
shell servers). Reproduce with `fetch_corpus.py`:

- `servers/`, `servers-archived/` — official MCP reference servers (trusted; FP check).
- `community/` — real shell-execution MCP servers (true-positive check).
- `pkgs/` — sample npm/pip packages (`click`, `express`).
