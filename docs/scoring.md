# SkillTotal Scoring

Scoring is deterministic and derived **only** from the component's findings.

## Severity weights

| Severity | Weight |
|----------|--------|
| critical | +30 |
| high | +20 |
| medium | +10 |
| low | +3 |

## Score

```
risk_score = min(100, Σ weight(finding.severity) for findings that are risk, not capability)
```

The sum is over **distinct findings** (one finding per rule), so repeated matches of the
same rule do not inflate the score — only a new *kind* of risk does. The score is capped at
100.

**A malicious indicator scores at least 50 (high).** A component with any `malicious_indicator`
finding has `risk_score >= 50`, so the score, the level and a `fail_on_score` gate agree with the
"Malicious indicators found" verdict even when the indicator's own weight is small.

**Capability is not risk.** Only findings whose `threat_class` is `malicious_indicator` or
`risky_construct` contribute to the score. Neutral `capability` findings (shell execution,
filesystem read/write, network egress, MCP tool surface) are still reported — as findings and
as capability chips — but contribute **0**.

**An exposed secret is not risk to the user either.** `exposure` findings — a hardcoded key or
private key (`ST-SECRET-EMBEDDED`), a `.env` packed into a release (`ST-ENV-SHIPPED`) — are the
author's leak: anyone holding the package can use the credential. They are reported with full
evidence, counted in `verdict.exposed_secrets`, keep their severity for `--fail-on`, and contribute
**0** to the score. A legitimate-but-powerful component is therefore
not pushed into the red by what it *can* do; the score and verdict reflect actual risk
(deliberate malice and dangerous constructs), not raw capability.

## Risk levels

| Score range | Level |
|-------------|-------|
| 0–24 | low |
| 25–49 | medium |
| 50–74 | high |
| 75–100 | critical |

## Default severities by category

Severity says how serious a finding is; the threat class decides whether it is scored. Capability
findings keep their severity (it is shown, and SARIF reports them as notes) but add **0** to the
score. `skilltotal rules list --json` gives every rule's severity and class.

| Category | Example rules | Severity | Threat class | Score weight |
|----------|---------------|----------|--------------|--------------|
| Shell execution | `ST-SHELL-PY`, `ST-SHELL-NODE` | high | capability | 0 |
| Download piped into a shell | `ST-SHELL-PIPE-EXEC`, `-PY`, `-NODE` | high | risky_construct | 20 |
| Sensitive path access | `ST-SENS-PATH`, `ST-SENS-PATH-PY` | high | risky_construct | 20 |
| Filesystem access (read/write) | `ST-FS-PY-READ`, `ST-FS-NODE-WRITE` | medium | capability | 0 |
| Network egress | `ST-NET-PY`, `ST-NET-NODE` | medium | capability | 0 |
| Install-time execution (a lifecycle hook) | `ST-INSTALL-NPM`, `ST-INSTALL-PY` | high | capability | 0 |
| Install script that downloads or decodes code and runs it | `ST-INSTALL-NPM-REMOTE-EXEC` | high | malicious_indicator | 20, score at least 50 |
| Dynamic code execution | `ST-DYN-PY`, `ST-DYN-NODE` | high | capability | 0 |
| Unsafe deserialization | `ST-DESERIALIZE-PY` | high | risky_construct | 20 |
| Obfuscation (decode-and-execute) | `ST-OBF-DECODE-EXEC` | high | malicious_indicator | 20, score at least 50 |
| Prompt injection indicators | `ST-PROMPT-INJECTION` | medium | malicious_indicator | 10, score at least 50 |
| Broad MCP tools (shell/fs/network/credential) | `ST-MCP-DANGEROUS-TOOL` | high | capability | 0 |
| MCP server launches a command | `ST-MCP-SERVER-EXEC` | high | capability | 0 |
| MCP surface detected | `ST-MCP-DETECTED` | low | capability | 0 |
| Embedded secret | `ST-SECRET-EMBEDDED` | high | exposure | 0 |

## Combination rule (sensitive data + network ⇒ critical)

If a component **both** reads a credential location (`ST-SENS-PATH`, `ST-SENS-PATH-PY`: `~/.ssh`,
`~/.aws/credentials`, an AI assistant's login file, written out or built by joining segments onto
the home directory, as in `path.join(os.homedir(), ".aws", "credentials")` or
`Path.home() / ".aws" / "credentials"`), or reads a wallet private key or seed phrase from an
environment variable (`ST-SECRET-ENV`), **and** has `network_egress`,
the engine adds one synthesized **critical** `risky_construct` finding, `ST-COMBO-EXFIL`
("Sensitive-data access combined with network egress"). Its evidence is drawn (de-duplicated)
from the contributing finding/capabilities, so the evidence invariant still holds. This makes
the credential-exfiltration path explicit and scored.

Note this is **sensitivity-gated**: plain filesystem access plus network is a neutral capability
combination (legitimate tools read files and use the network) and is *not* flagged — only access
to *secret* data combined with an egress channel is. An embedded secret is not an input: a key the
component ships plus a network call describes no theft, and it is reported as an exposure.

The two halves must also be able to belong to one program. A credential reference in code of one
language runtime (Python, JavaScript/TypeScript, Go, Rust, ...) pairs only with network egress in
code of the same runtime. A shell script, markdown an agent reads, or a JSON/YAML configuration file
starts or steers other programs, so a credential reference or a network call there pairs with any
runtime: `cp ~/.ssh/id_rsa /tmp/k && node send.js` still forms the path. A Go file that names its
own host key and a Python script that posts to localhost do not.

Programs in two runtimes also pair when the code links them. One link is a staging file: the file
with the credential reference writes a path that the file with the network call reads
(`open("/tmp/.k", "w")` in Python, `fs.readFileSync("/tmp/.k")` in Node.js). The other is a launch:
one of the two files starts the other by its file name (`subprocess.run(["node", "send.js"])`,
`execFileSync("python3", ["collect.py"])`). The linking line is added to the finding's evidence.
A path both programs only read, such as a shared settings file, is not a link, and neither is a
launch of some other program.

## Other synthesized combinations

`ST-COMBO-EXFIL` is one of four findings the engine synthesizes from combinations of base findings,
in the order `combinations.py` declares. Each carries the merged evidence of what it combines and
is a scored `risky_construct`:

| Rule | Severity | Fires when |
|------|----------|------------|
| `ST-COMBO-EXFIL` | critical | credential access + network egress (above) |
| `ST-FLOW-TRIFECTA` | high | a real `ST-PROMPT-INJECTION` + filesystem read + network egress (the "lethal trifecta"); not added when `ST-COMBO-EXFIL` already fired |
| `ST-INSTALL-DROPPER` | high | an install/build hook + a decode-and-execute payload or credential access |
| `ST-CONVERGENCE` | high | two or more distinct malicious-indicator findings in one component |

## Taint: untrusted input → dangerous sink (Python)

Beyond raw capability, the Python AST scanner reports a **proven data flow** from an untrusted
source (environment, `sys.argv`, `input()`, a network response body, or an MCP tool-handler
argument) to a dangerous sink, as `risky_construct` (high):

- `ST-TAINT-EXEC-PY` — reaches `eval` / `exec` / `compile`
- `ST-TAINT-SHELL-PY` — reaches a shell (`os.system` / `os.popen` / `subprocess(..., shell=True)`)
- `ST-TAINT-DESERIAL-PY` — reaches unsafe deserialization

These turn an already-reported capability (`ST-DYN-PY` / `ST-SHELL-PY`, weight 0) into a scored
risk; the capability finding still appears. `ST-DESERIALIZE-PY` is already a scored
`risky_construct` (high) on its own, so `ST-TAINT-DESERIAL-PY` adds a second, distinct finding when
the loaded data provably comes from an untrusted source. This is stronger than `ST-CMDI-PY` (which flags any non-constant shell command): when taint proves an
untrusted source reaches the shell, `ST-TAINT-SHELL-PY` supersedes `ST-CMDI-PY` on that node so the
injection is scored once. The analysis is conservative (default-deny propagation, sanitizers clear
taint, no inter-procedural tracking) to keep benign false positives at zero.

## Agent Skill: declared vs actual (undeclared capability)

For an `agent_skill` component (a folder with a `SKILL.md`), the engine compares the skill's
declared `allowed-tools` against what its bundled code does. The `allowed-tools` field
pre-approves tools for the agent and does not limit the skill's own code, so a narrow list can
make a skill look safer than it is. If the skill declares a non-empty, non-wildcard list but the
code exercises a dangerous capability those tools do not cover (shell, network, filesystem write,
dynamic code execution, or install-time execution), the engine synthesizes
`ST-SKILL-CAP-MISMATCH` (`risky_construct`, high). Reading files (`filesystem_read`) is treated
as benign and not checked. This is a deterministic, evidence-anchored check for "the skill does
more than it claims": it uses no LLM and fires only when there is an explicit declaration to
contradict.

## Evidence-context demotion (what does NOT score)

Matches that are not executed, agent-facing behavior are moved to `needs_review` before scoring,
so the engine does not flag descriptions of attacks or its own detection patterns:

- **Test code** — `tests/`, `*.test.*`, `conftest.py`, compound test trees (`cli-e2e-tests/`,
  `integration-tests/`), … (not run by consumers).
- **Documentation / prose** — `README`, `CHANGELOG`, `LICENSE`, `docs/`, `*.egg-info/PKG-INFO`,
  RSS/Atom release feeds (`feed.xml`, `*.rss`, `*.atom`), ignore-files. AI-instruction surfaces
  (`SKILL.md`, `AGENTS.md`, MCP manifests, `.cursorrules`, `.windsurfrules`, `.clinerules`,
  `.github/copilot-instructions.md`, `.mdc` rules, and the markdown in a skill folder or in a
  `.clinerules/`, `.cursor/rules/` or `.windsurf/rules/` folder unless it is named for an attack or
  a record) are **kept in scope** — a real injection lives there.
- **Data / eval / benchmark corpora** — inert reference *data* files under `eval_datasets/`,
  `fixtures/`, `benchmarks/`, `datasets/`, `snapshots/`, … A
  prompt-injection string in an eval dataset is a detector test vector, not behavior. Restricted to
  non-code suffixes, so a real payload shipped as code in such a directory is still scanned/scored.
- **Python string literals / comments, shell `#` and PowerShell `<# … #>` comments, and C-family
  `//` `/* */` comments** (`.ts`/`.js`/`.go`/`.rs`/…) — a behavior/text detector matching
  its own regex literal or a docstring example is not behavior; a `# Usage: curl … | bash` line is a
  doc comment, not a runnable pipe-to-shell. Which contexts count depends on the rule: the
  decode-exec, tool-poisoning, prompt-injection and sensitive-path rules set aside matches in
  strings and comments; shell pipe-to-shell and the Node.js filesystem / network / shell rules set
  aside comments only, since their real positives are code and value strings (a JSDoc
  `* fs.writeFileSync(...)` example is not a write); the network-exposure rules and the AI-CLI
  permission-bypass rule also set aside Python docstrings (a docstring that shows
  `host="0.0.0.0"` is an example, not a bind).
- **A provider SDK reading its own provider's credentials** — botocore, boto3, awscli and the
  AWS JavaScript SDK (`@aws-sdk/*`, `@smithy/*`) reading `~/.aws`, the Kubernetes client reading
  `~/.kube/config`, package-index tooling (pip, twine, distlib, pipenv, setuptools, flit, pdm)
  reading the PyPI upload configuration `~/.pypirc`, and other packages on a curated list,
  matched by exact registry name (an `npm:` or `pypi:` source): a
  `ST-SENS-PATH`/`ST-SENS-PATH-PY` match in the package's own credential domain is what the package
  is for, so it goes to `needs_review` and cannot feed `ST-COMBO-EXFIL`. Another domain (an AWS SDK
  reading `~/.ssh`), and the same read in any other package, still score.
- **Denylist / guardrail credential paths and public DocSearch keys** — set aside by the scanners
  themselves: a policy that *protects* `~/.ssh`/`id_rsa` is not access to
  it — including a macOS sandbox profile's `(deny file-read* …)` rule that keeps an agent CLI's
  tools away from its own login file — a key or kubeconfig handed to its own client (`ssh -i`,
  `--kubeconfig`) is read locally to authenticate, and an Algolia DocSearch search key sitting next
  to an app id / index name is public/read-only.
- **PowerShell `-EncodedCommand` of the file's own script** — a JS/TS file that base64-encodes a
  script it spells out (`Buffer.from(SCRIPT, "utf16le").toString("base64")`) to pass it to
  PowerShell hides nothing from a reader; `ST-SHELL-EVASION` sets it aside for review. A literal
  blob, or a value encoded from a download, a file read or a parameter, still scores.
- **Cited or described attacks** — a prompt-injection phrase wrapped in quotes (also when elided:
  `'Ignore previous instructions...'`), framed by a defensive line, or a data-theft phrase whose
  subject is a third-party attacker with a modal verb ("attackers may steal credentials", a threat
  model) is demoted to `needs_review` by the prompt-surface scanner; the same words addressed to the
  agent still score.

How each layer is implemented is in [architecture.md](architecture.md#evidence-context-demotion).

## `needs_review` and the score

Items in `needs_review` (e.g. lone base64 blobs, ambiguous prompt phrasing, minified files,
unparseable manifests) are **never** scored. They are surfaced for a human to decide,
preserving the rule that the score reflects only evidence-confirmed risk.

## Worked example (malicious npm fixture)

| Finding | Severity | Threat class | Weight |
|---------|----------|--------------|--------|
| ST-SENS-PATH (reads `~/.ssh`, `.aws/credentials`) | high | risky_construct | 20 |
| ST-COMBO-EXFIL (sensitive data + network) | critical | risky_construct | 30 |
| ST-INSTALL-DROPPER (install hook + credential access) | high | risky_construct | 20 |
| ST-INSTALL-NPM | high | capability | 0 |
| ST-SHELL-NODE | high | capability | 0 |
| ST-FS-NODE-READ | medium | capability | 0 |
| ST-NET-NODE | medium | capability | 0 |
| **Sum** | | | **70** |

Result: `risk_score = 70`, `risk_level = high`. The credential-exfiltration pattern (read
secrets + reach the network, run from an install hook) drives the score; the raw capabilities are
reported but add nothing.
A *benign* tool with the same capabilities but no sensitive-data access scores **0 / low**.
