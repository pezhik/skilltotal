# Contributing detection rules

SkillTotal's value grows as new code-hiding / malware techniques are covered. This is the
repeatable process for turning a new malicious sample into a shipped detection rule. It is
**corpus-driven**: every rule is backed by a fixture and guarded against false positives.

> Guiding principle (CI-first): a detection must be *actionable* (a real
> reason to fail a CI build) and *low false-positive*. Ambiguous signals go to
> `needs_review`, never to `findings`.

## Steps

0. **Check the scope.** SkillTotal finds malicious or deceptive behavior inside a component that
   someone installs or runs: a package, an MCP server, an agent skill or plugin, a GitHub Action
   other projects use, an agent or editor config a component ships, or a malicious hook or
   workflow injected into a repository. Before writing a rule, state which of these the threat
   is. Misconfiguration of a project's own CI or cloud (untrusted input in a workflow `run:`,
   `pull_request_target`, unpinned actions, IAM policies), ordinary vulnerabilities in honest code
   and model jailbreaks with no component file are out of scope; dedicated linters and scanners
   cover them. When a threat has both in-scope and out-of-scope parts, build only the in-scope
   part.

1. **Sanitize the sample.** Never commit a working weapon. Replace real endpoints with
   non-existent `.test` / `.invalid` domains, make payloads inert (e.g. `print`/`echo`), assemble
   fake credentials at run time so no complete token appears in a file, and start every file
   with the `FIXTURE ONLY` banner. Add it to the detection corpus as
   `tests/eval_corpus/positive/<AST-class>/<technique>/<variant>/` (the leaf folder is the
   component root, 1-3 files), with an honest look-alike under `negative/` next to it. A rule
   that cannot flag a sample on its own gets `tests/eval_corpus/rules/<RULE-ID>/fires/<variant>/`
   and `.../silent/<variant>/` instead. `tests/eval_corpus/README.md` has the layout and the bar
   each sample must meet.

2. **Confirm the gap.** Scan the sample with the current engine and check that it misses or
   under-rates it (a positive must be malicious or rated high/critical):
   ```
   skilltotal scan tests/eval_corpus/positive/<AST-class>/<technique>/<variant> --json
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

5. **Calibrate false positives.** Regenerate the corpus expectations and read the diff: only
   your new samples may change, and no negative sample may gain a finding:
   ```
   python tests/manual_eval/efficacy.py --write-expected
   git diff tests/eval_corpus/expected_findings.json
   ```
   Before each release the maintainers also scan a labeled calibration set
   (`tests/manual_eval/calibrate.py`) and about a thousand popular packages; a new malicious
   verdict or high finding on a popular package blocks the release. If a benign component gains
   a finding, tighten the rule or move the ambiguous part to `needs_review`.

6. **Bump the ruleset + record it.** Increment `RULESET_VERSION` in `skilltotal/__init__.py`
   and add an entry to `RULES_CHANGELOG.md`. Then release a **minor** version (see
   [releasing.md](releasing.md)).

## Checklist (PR)

- [ ] The threat, or the part the rule covers, is in scope (step 0)
- [ ] Sanitized fixture + README row
- [ ] New rule/scanner with `capability` set, registered
- [ ] Unit test (fires + evidence valid)
- [ ] Corpus calibration clean (no new FP)
- [ ] `pytest` + `ruff check .` green
- [ ] `RULESET_VERSION` bumped + `RULES_CHANGELOG.md` updated
