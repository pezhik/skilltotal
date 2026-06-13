# Detection coverage — malware archetypes → engine rules

This maps the common real-world malicious-package archetypes (as catalogued by the
[OSSF malicious-packages](https://github.com/ossf/malicious-packages) dataset and supply-chain
incident reports) to the SkillTotal rules that detect them. It documents *what the engine
already covers* and is exercised by the in-repo fixtures under `tests/manual_eval/malicious/`
(see `tests/test_offline_calibration.py`, the offline detection floor).

> **Why fixtures, not the OSSF packages directly:** OSSF stores OSV *metadata only* (hashes,
> IOCs, advisories) — **no code** — and the packages themselves are pulled from npm/PyPI after
> detection. So they cannot be fetched and scanned (`CollectionError → skipped`). The reliable,
> deterministic way to prove coverage is sanitized in-repo fixtures modelled on each archetype.
> See `../../skilltotal-ops/calibration/README.md`.

## Archetype → rules

| Archetype | Engine rules | Fixture |
|---|---|---|
| **Install-time execution** (npm pre/post/install, `setup.py`/cmdclass) | `ST-INSTALL-NPM`, `ST-INSTALL-NPM-PREPARE`, `ST-INSTALL-PY` | `npm-postinstall-exfil`, `pypi-typosquat-dropper` |
| **Import-time / second-stage download-and-execute** | `ST-OBF-DECODE-EXEC` (malicious), `ST-DYN-PY`/`ST-DYN-NODE`, `ST-NET-PY`/`ST-NET-NODE` | `pypi-typosquat-dropper`, `pypi-importtime-stealer` |
| **Credential / secret exfiltration** (read `~/.aws`, `~/.ssh`, `.env` → POST) | `ST-COMBO-EXFIL` (critical), `ST-SENS-PATH`/`ST-SENS-PATH-PY`, `ST-SECRET-EMBEDDED`, `ST-FS-*-READ` + `ST-NET-*` | `npm-postinstall-exfil`, `npm-trapdoor-stealer` |
| **Obfuscation** (base64/hex/codecs decode → exec) | `ST-OBF-DECODE-EXEC` (malicious); heuristics `ST-OBF-BASE64-BLOB`/`ST-OBF-HEX`/`ST-OBF-MINIFIED` (needs_review) | `pypi-importtime-stealer` |
| **Unsafe deserialization** (pickle/marshal/dill loader) | `ST-DESERIALIZE-PY` | *(gap — see below)* |
| **Shell / command execution & injection** | `ST-SHELL-PY`/`ST-SHELL-NODE`, `ST-CMDI-PY`/`ST-CMDI-NODE` | `pypi-typosquat-dropper` |
| **Hidden-Unicode / Trojan-Source instruction smuggling** | `ST-HIDDEN-UNICODE` (malicious); `ST-HIDDEN-UNICODE-AMBIG` (needs_review) | `zero-width-injection` |
| **Prompt injection / instruction override** | `ST-PROMPT-INJECTION` (malicious); `ST-PROMPT-WEAK` (needs_review) | `agent-instruction-override` |
| **MCP tool poisoning** (agent-directed instructions in tool metadata) | `ST-MCP-TOOL-POISONING` (malicious); `ST-MCP-DANGEROUS-TOOL`, `ST-MCP-SERVER-EXEC`, `ST-MCP-AUTO-APPROVE`, `ST-MCP-TOOL-SHADOWING` | `mcp-tool-poisoning` |
| **Network/debug exposure** | `ST-EXPOSE-BIND`, `ST-EXPOSE-DEBUG` | — |

Only `malicious_indicator` rules drive the "malicious" verdict; `risky_construct` rules raise
risk; `capability` rules are informational (they never push the score up — capability ≠ risk).

## Known gaps (candidate rule improvements)

- **`exec(marshal.loads(<remote>))` / `exec(pickle.loads(...))`** — a remote-deserialize-then-exec
  dropper currently scores **low**: `ST-DESERIALIZE-PY` (risky_construct) + `ST-DYN-PY`
  (capability) fire, but neither is a `malicious_indicator` and the pair doesn't reach the
  high band. `ST-OBF-DECODE-EXEC` only matches base64/hex/codecs decode chains, not marshal/
  pickle. Extending the decode-and-execute indicator to cover `exec(marshal.loads(...))` /
  `exec(pickle.loads(...))` would close this (a deliberate ruleset change — bump
  `RULESET_VERSION`, add fixture `py-marshal-loader`, calibrate FP=0).
- **Obfuscated natural-language injection** — CLOSED (ruleset 11): instruction-override and
  tool-poisoning phrases hidden behind homoglyphs, full-width, diacritics, or zero-width-in-word
  are now de-obfuscated before matching (`skilltotal.text_normalize`). Still out of scope for the
  free static engine (and deferred to paid Deep Analysis): semantic paraphrase and arbitrary
  *non-English* natural-language understanding — those need an LLM, not a keyword list.
