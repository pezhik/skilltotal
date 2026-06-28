# Detection-efficacy corpus (synthetic, inert)

This directory is an **offline detection-efficacy corpus**: a set of small, synthetic,
sanitized component samples used to measure the engine's recall (do we flag real malware
shapes?) and precision (do we leave benign-but-tricky look-alikes clean?). A recall/precision
gate can be built directly on top of it.

Every sample is **synthetic and inert**:

- No real payloads. Decoded blobs resolve to harmless `print(...)` / `console.log(...)`.
- Network destinations use only `.test` / `.invalid` domains.
- Secret-shaped strings are obviously fake (e.g. `AKIAFIXTUREFAKE000000`, `sk-FIXTUREfake...`).
- Every file begins with the banner
  `FIXTURE ONLY — synthetic detection test sample, not real malware`.

These files live under `tests/` (gitleaks-allowlisted) and are never executed by the engine —
detection is static.

## Label-by-path convention (no manifest)

The label of a sample is encoded in its path; there is **no** separate manifest file.

```
positive/<AST-class>/<technique>/<variant>/   # malware shape — MUST be flagged
negative/<AST-class>/<technique>/<variant>/   # benign look-alike — MUST stay clean
```

- `<AST-class>` is the OWASP-Agentic-style class the technique maps to (e.g. `AST01`, `AST02`,
  `AST04`, `AST05`).
- `<technique>` is one detection technique (e.g. `decode-exec`, `credential-exfil`).
- The **leaf `<variant>/` directory is the component root** — the sample's 1–3 files live
  directly in it. Each variant is analyzed on its own (`analyze_directory(variant_dir, ...)`),
  so the surrounding `tests/eval_corpus/...` path never affects analysis (relpaths are computed
  relative to the variant root, so the `tests/` segment does not trigger test-code demotion).

File suffixes are real (`.py` / `.js` / `.ts` / `.sh` / `.json` / `.md` / `.pth`) so the
language axis of detection is exercised correctly.

## The detection bar (how a sample is judged)

For a variant directory `DIR`, the engine is run as:

```python
from pathlib import Path
from skilltotal import engine
from skilltotal.collector import detect_component

r = engine.analyze_directory(Path(DIR), detect_component(Path(DIR), source=DIR))
risk = r.risk_level.value
malicious = (r.verdict or {}).get("has_malicious_indicators")
ids = sorted({f.id for f in r.findings})
```

- A **positive** sample is correct iff `malicious is True` **OR** `risk` is `high`/`critical`.
  (A lone risky construct that only reaches `low`/`medium` does **not** count — a realistic
  positive must stack signals the way real malware does.)
- A **negative** sample is correct iff `malicious is False` **AND** `risk` is not
  `high`/`critical` **AND** neither `ST-COMBO-EXFIL` nor `ST-FLOW-TRIFECTA` is present.

## Maintenance

- Keep samples minimal (1–3 small files) and inert. Never weaken a sample just to pass.
- If a realistic positive cannot reach the bar on the current engine, leave the negative,
  keep the positive, and record it as a detection gap for a hardening phase — do not fake it.
- Adding a new technique: create both a `positive/` (ideally a base case plus an evasion
  variant) and a `negative/` look-alike, then verify each against the bar above.
