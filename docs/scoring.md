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
risk_score = min(100, Σ weight(finding.severity))
```

The sum is over **distinct findings** (one finding per rule), so repeated matches of the
same rule do not inflate the score — only a new *kind* of risk does. The score is capped at
100.

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

## Combination rule (filesystem + network ⇒ critical)

If a component has **both** a filesystem capability (`filesystem_read` or
`filesystem_write`) **and** `network_egress`, the engine adds one synthesized **critical**
finding, `ST-COMBO-FS-NET` ("Combined filesystem access and network egress"). Its evidence
is drawn (de-duplicated) from the contributing capabilities, so the evidence invariant
still holds. This both raises the score and makes the potential data-exfiltration path
explicit in the report rather than hiding it inside the number.

## `needs_review` and the score

Items in `needs_review` (e.g. lone base64 blobs, ambiguous prompt phrasing, minified files,
unparseable manifests) are **never** scored. They are surfaced for a human to decide,
preserving the rule that the score reflects only evidence-confirmed risk.

## Worked example (malicious npm fixture)

| Finding | Severity | Weight |
|---------|----------|--------|
| ST-INSTALL-NPM | high | 20 |
| ST-SHELL-NODE | high | 20 |
| ST-SENS-PATH | high | 20 |
| ST-FS-NODE-READ | medium | 10 |
| ST-NET-NODE | medium | 10 |
| ST-COMBO-FS-NET | critical | 30 |
| **Sum** | | **110 → capped 100** |

Result: `risk_score = 100`, `risk_level = critical`.
