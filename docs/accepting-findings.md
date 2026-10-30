# Accepting findings

How to accept a finding you have reviewed: a false positive, or a construct you decided to live
with. SkillTotal has five ways to do it. Each works in a different place and covers a different
amount, so pick by where the finding blocks you.

## Which one to use

| You want to | Use | Works with | Covers | Accepts a malicious indicator |
|---|---|---|---|---|
| Accept one occurrence in your own code | An [inline marker](#inline-marker): `# skilltotal:ignore[ST-ID]` | `scan` of a local folder | One line | No |
| Adopt the scanner on a repository that already has findings | A [baseline](#baseline): `--write-baseline`, then `--baseline` or `baseline =` in the config | `scan` | Every finding that exists today, by fingerprint | Yes, with a warning on every run |
| Show a rule's findings but never fail the gate on them | [`[policy]`](#policy-and-ignore) `"ST-ID" = "warn"` | `scan` | One rule, everywhere | Yes (it stays in the report and the score) |
| Drop a rule entirely | [`ignore`](#policy-and-ignore), or `[policy]` `"ST-ID" = "ignore"` | `scan`, `diff` | One rule, everywhere | Yes, silently: avoid it for these |
| Stop a scheduled check of installed components, or a `guard`, from blocking on a reviewed component | An [accept file](#accept-file): `--accept FILE` | `guard`, `guard --installed`, `inventory` | One component at one exact version, by fingerprint | Yes, with a warning on every run |
| Let an install through the Claude Code plugin | [Not possible](#the-claude-code-plugin) | | | |

Every mechanism keeps the accepted finding visible: the report counts suppressed occurrences
(`metadata.suppressed_count`), names the baseline and the config it applied, and marks what an
accept file accepted. An accepted malicious indicator is named on stderr on every run, so a CI
log or a SIEM shows it even with `--json` or `--sarif`.

[Report false positives](https://github.com/pezhik/skilltotal/issues) as issues too: they are
fixed in the open, and a fixed rule needs no acceptance at all.

## Inline marker

Add a `skilltotal:ignore[ST-ID]` comment on the finding's line or on the line just above it. Any
comment syntax works (`#`, `//`, `<!-- -->`). Separate several ids with commas; a bare
`skilltotal:ignore` accepts every rule on that line.

```python
subprocess.run(cmd, shell=True)  # skilltotal:ignore[ST-CMDI-PY] cmd is built from constants
```

- Markers count only when `scan` reads a local folder: your own code, as in CI. In a package,
  repository, archive or file that SkillTotal fetches or unpacks they are ignored, so a component
  cannot silence its own findings. `diff`, `guard`, `inventory` and the MCP server ignore them.
- A marker never hides a malicious indicator, in any source. The finding stays, and a
  `needs_review` note says so. Use a baseline or a `warn` policy for one after review.
- A marker that names a rule id no rule has suppresses nothing and gets a `needs_review` note
  suggesting the closest id.
- Suppressed occurrences are counted in `metadata.suppressed_count`.

A marker sits next to the code it accepts, so it is reviewed with that code. Prefer it for a single
occurrence.

## Baseline

A baseline records the fingerprints of the current findings, and later scans drop those findings
before scoring. A fingerprint is the rule id, the file and the code snippet, without the line
number, so it survives edits that move the code.

```bash
skilltotal scan . --write-baseline .skilltotal-baseline.json
skilltotal scan . --baseline .skilltotal-baseline.json --fail-on-high
```

- `--write-baseline` writes the file and exits 0 whatever it found: writing a baseline is how you
  adopt the tool on existing code. It warns on stderr when the baseline accepts a malicious
  indicator, so read the report before you commit the file.
- Commit the file and name it in `.skilltotal.toml` (`baseline = ".skilltotal-baseline.json"`, a
  path relative to the config file) or pass `--baseline`. Findings in the baseline no longer trip
  the gate; new ones do.
- A scan with a baseline says how many occurrences it suppressed on a `Baseline  :` line. When the
  baseline hides a malicious indicator, that line names the rule, the CLI warns on stderr, and the
  report's `metadata.baseline_suppressed_malicious` lists it. The verdict and the gates do not see
  a hidden finding.
- A fingerprint also suppresses a finding synthesized from the component's name or declared tools
  (`ST-TYPOSQUAT`, `ST-SKILL-CAP-MISMATCH`). A combination finding (`ST-COMBO-EXFIL`,
  `ST-FLOW-TRIFECTA`, `ST-INSTALL-DROPPER`, `ST-POSTEX-CHAIN`, `ST-CONVERGENCE`) follows its
  inputs: it disappears when the findings it combines are suppressed, and keeps firing while they
  are present, even if its own fingerprints are listed.
- Re-writing the baseline accepts every current finding at once. That is convenient after a
  review and easy to misuse.

`diff`, `guard`, `inventory` and the MCP server do not read a baseline. The steps for an existing
repository are in [Rolling out on an existing repository](ci.md#rolling-out-on-an-existing-repository).

## Policy and ignore

Both live in `.skilltotal.toml` ([Project config](configuration.md#project-config)):

```toml
ignore = ["ST-NET-PY"]            # drop the rule's findings

[policy]
"ST-DESERIALIZE-PY" = "warn"      # report it and score it, never fail the severity gate on it
"ST-SENS-WORD" = "ignore"         # same as listing it under ignore
"ST-SHELL-PIPE-EXEC" = "block"    # the opposite: fail the gate whenever the rule fires
```

- `warn` keeps the finding in the report and in the risk score, so `--fail-on-score` still counts
  it; only the `--fail-on` severity gate skips it.
- `ignore` removes the rule from the report. It applies to every file and every future
  occurrence, so it is the widest acceptance there is.
- `scan` reads both. `diff` reads `ignore` and `[policy]` `ignore` entries, not `warn` or `block`.
  `guard`, `inventory` and the MCP server read neither.

## Accept file

`guard <source>`, `guard --installed` and `inventory` take an accept file, `--accept FILE`. Each
entry accepts the findings it lists for one component at one exact version:

```json
{
  "format": "skilltotal-accept",
  "version": 1,
  "accepted": [
    {
      "component": "VS Code|editor_extension|acme.quillwidget",
      "version": "1.4.2",
      "findings": ["3f9c2a7e1b6d4c08"],
      "rules": ["ST-OBF-DECODE-EXEC"],
      "reason": "Decodes a bundled test fixture; reviewed in SEC-123, nothing runs it",
      "accepted_by": "security team",
      "expires": "2027-03-31"
    }
  ]
}
```

| Key | Required | Meaning |
|---|---|---|
| `component` | yes | For an installed component, `host|kind|name` as the inventory prints them, without an editor extension's `@version`. For `guard <source>`, the source: `npm:<name>` or `pypi:<name>` without its version and in lower case (for PyPI, runs of `-`, `_` and `.` read as one `-`), anything else as written |
| `version` | yes | The exact version scanned; `""` for a component that has none, such as a skill folder |
| `findings` | yes | Fingerprints (16 lowercase hex characters) of the accepted evidence, the same fingerprints a baseline uses |
| `reason` | yes | Why the findings are safe. An empty reason makes the whole file invalid |
| `rules` | no | Rule ids, for the reader. Matching uses `findings` only |
| `accepted_by` | no | Who accepted it |
| `expires` | no | `YYYY-MM-DD`; the entry applies through that day |

How it applies:

- Accepted evidence is removed before scoring, so the score, the verdict and the guard decision
  are those of the rest.
- An update is judged afresh: an entry for 1.4.2 does not cover 1.4.3, so a trojanized update of
  an accepted component still blocks. A new finding in the same version is judged as usual.
- `guard --installed` marks the component `[ACCEPTED]` and prints the rules, the count and the
  reason; `guard <source>` adds an `Accepted  :` line; the JSON gets an `accepted` object and the
  AI-BOM a `skilltotal:accepted` property ([Output formats](report-schema.md#accepted)).
- Every run warns on stderr when an accepted finding is a malicious indicator, names expired
  entries (which no longer apply), and lists stale entries, which matched no component scanned
  at their version.
- Combination findings follow their inputs, as with a baseline. A finding lists at most 25
  locations, so more of them can appear once the listed ones are accepted; accept those the same
  way.
- A block that is not a finding cannot be accepted: an install script that could not be read, or
  a component with nothing readable.
- A file that is not valid (not JSON, a wrong `format` or `version`, an unknown key, an empty
  `reason`, a malformed fingerprint or date) stops the command with exit 1 before anything is
  scanned. An unknown key is refused so that a misspelt `expires` cannot make an entry permanent.
- With `--state`, an accepted finding is not drift, and the state file still records it, so the
  file is the same as without `--accept`.

### Writing the entries

`--write-accept FILE` adds one entry for each component the run blocks (`guard`) or flags as high
risk, malicious or blocked (`inventory`). Each entry holds the fingerprints of the component's risk
findings and an empty `reason`. The command exits 0. The file is refused until a reviewer fills in
every reason. `--write-accept` adds to an existing accept file, skips entries it already covers,
and never overwrites a file that is not an accept file.

```bash
skilltotal guard --installed --write-accept accept.json
skilltotal guard --installed --accept accept.json
```

To share one accept file across a team or a fleet, see
[Installed components](installed-components.md#sharing-an-accept-file).

## The Claude Code plugin

The plugin's hook has no accept file and reads no baseline, config or inline marker: the package
it checks is someone else's code. An install denied for a malicious indicator stays denied. After
you have reviewed the package, run the install yourself in a terminal outside the agent. An
install the plugin asks about (high risk, a look-alike name, anything it could not check) needs
only your approval in Claude Code.

## Protect what accepts findings

Every mechanism above can hide a real finding, and in CI the scanned repository's own files decide
what is accepted. Put `.skilltotal.toml`, the baseline and the accept file under CODEOWNERS with
branch protection, so loosening them needs a review:

```text
# .github/CODEOWNERS
/.skilltotal.toml             @your-org/security
/.skilltotal-baseline.json    @your-org/security
/skilltotal-accept.json       @your-org/security
```

Review new `skilltotal:ignore` markers like any other code. When you scan code you do not control
from its own root, pass `--no-config` (Action: `config: none`).
