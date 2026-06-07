# Contributing detection rules

SkillTotal's value grows as new code-hiding / malware techniques are covered. This is the
repeatable process for turning a new malicious sample into a shipped detection rule. It is
**corpus-driven**: every rule is backed by a fixture and guarded against false positives.

> Guiding principle ([CI-first](../CLAUDE.md)): a detection must be *actionable* (a real
> reason to fail a CI build) and *low false-positive*. Ambiguous signals go to
> `needs_review`, never to `findings`.

## Steps

1. **Sanitize the sample.** Never commit a working weapon. Replace real endpoints with
   non-existent `.test` domains, make payloads inert (e.g. `print`/`echo`), and add a
   `FIXTURE ONLY` header. Place it under `tests/manual_eval/malicious/<technique>/` and add
   a row to `tests/manual_eval/README.md` describing the technique and its source.

2. **Confirm the gap.** Run the manual harness and verify the current engine misses (or
   under-rates) it:
   ```
   python tests/manual_eval/run_eval.py
   ```

3. **Add the detection.** Either a new `RuleSpec` on an existing scanner, or a new
   `Scanner` subclass:
   - Declarative regex → extend a `PatternScanner` (`skilltotal/scanners/*.py`).
   - Custom logic (parsing, codepoint analysis) → subclass `Scanner`, implement `scan()`,
     and still declare `RuleSpec` metadata.
   - Register new scanners in `skilltotal/scanners/__init__.py` (`SCANNERS`).
   - Set each rule's `capability` so it wires into capability extraction and `rules list`.
   - Rule ids follow `ST-<AREA>-<...>`. Prefer one finding per rule (clustered evidence).

4. **Unit-test the technique.** Add `tests/test_<area>.py` (see `test_invisible_unicode.py`
   for a model). Assert the rule fires and that every finding carries valid evidence.

5. **Calibrate false positives.** Run against the trusted corpus and confirm no legitimate
   component regresses:
   ```
   python tests/manual_eval/fetch_corpus.py      # once
   python tests/manual_eval/run_eval.py --corpus
   ```
   If a benign component now lights up, tighten the rule or move the ambiguous part to
   `needs_review`.

6. **Bump the ruleset + record it.** Increment `RULESET_VERSION` in `skilltotal/__init__.py`
   and add an entry to `RULES_CHANGELOG.md`. Then release a **minor** version (see
   [releasing.md](releasing.md)).

## Checklist (PR)

- [ ] Sanitized fixture + README row
- [ ] New rule/scanner with `capability` set, registered
- [ ] Unit test (fires + evidence valid)
- [ ] Corpus calibration clean (no new FP)
- [ ] `pytest` + `ruff check .` green
- [ ] `RULESET_VERSION` bumped + `RULES_CHANGELOG.md` updated
