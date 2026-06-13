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

**Capability is not risk.** Only findings whose `threat_class` is `malicious_indicator` or
`risky_construct` contribute to the score. Neutral `capability` findings (shell execution,
filesystem read/write, network egress, MCP tool surface) are still reported — as findings and
as capability chips — but contribute **0**. A legitimate-but-powerful component is therefore
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

| Category | Severity |
|----------|----------|
| Shell execution | high |
| Sensitive path access | high |
| Filesystem access (read/write) | medium |
| Network egress | medium |
| Install-time execution | high |
| Dynamic code execution | high |
| Obfuscation (decode-and-execute) | high |
| Prompt injection indicators | medium |
| Broad MCP tools (shell/fs/network/credential) | high |
| MCP server launches a command | high |
| MCP surface detected | low |

## Combination rule (sensitive data + network ⇒ critical)

If a component **both** accesses sensitive data — a credential-location reference
(`ST-SENS-PATH`) or an embedded secret (`ST-SECRET-EMBEDDED`) — **and** has `network_egress`,
the engine adds one synthesized **critical** `risky_construct` finding, `ST-COMBO-EXFIL`
("Sensitive-data access combined with network egress"). Its evidence is drawn (de-duplicated)
from the contributing finding/capabilities, so the evidence invariant still holds. This makes
the credential-exfiltration path explicit and scored.

Note this is **sensitivity-gated**: plain filesystem access plus network is a neutral capability
combination (legitimate tools read files and use the network) and is *not* flagged — only access
to *secret* data combined with an egress channel is.

## Evidence-context demotion (what does NOT score)

Matches that are not executed, agent-facing behavior are moved to `needs_review` before scoring,
so the engine does not flag descriptions of attacks or its own detection patterns:

- **Test code** — `tests/`, `*.test.*`, `conftest.py`, … (not run by consumers).
- **Documentation / prose** — `README`, `CHANGELOG`, `LICENSE`, `docs/`, `*.egg-info/PKG-INFO`,
  ignore-files. AI-instruction surfaces (`SKILL.md`, `AGENTS.md`, MCP manifests, `.cursorrules`)
  are **kept in scope** — a real injection lives there.
- **Python string literals / comments** — a behavior/text detector matching its own regex
  literal or a docstring example is not behavior. Governed per-rule by `code_context`
  (`strings_and_comments` for decode-exec / tool-poisoning / prompt-injection / sensitive-path;
  `comments` for the network-exposure rules, whose real positives are value-strings).

## `needs_review` and the score

Items in `needs_review` (e.g. lone base64 blobs, ambiguous prompt phrasing, minified files,
unparseable manifests) are **never** scored. They are surfaced for a human to decide,
preserving the rule that the score reflects only evidence-confirmed risk.

## Worked example (malicious npm fixture)

| Finding | Severity | Threat class | Weight |
|---------|----------|--------------|--------|
| ST-SENS-PATH (reads `~/.ssh`, `.aws/credentials`) | high | risky_construct | 20 |
| ST-COMBO-EXFIL (sensitive data + network) | critical | risky_construct | 30 |
| ST-INSTALL-NPM | high | capability | 0 |
| ST-SHELL-NODE | high | capability | 0 |
| ST-FS-NODE-READ | medium | capability | 0 |
| ST-NET-NODE | medium | capability | 0 |
| **Sum** | | | **50** |

Result: `risk_score = 50`, `risk_level = high`. The credential-exfiltration pattern (read
secrets + reach the network) drives the score; the raw capabilities are reported but do not.
A *benign* tool with the same capabilities but no sensitive-data access scores **0 / low**.
