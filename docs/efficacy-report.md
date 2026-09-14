# SkillTotal detection-efficacy report

Engine 0.47.0 · ruleset 51 · offline corpus.

- **recall: 100.0%** (45/45 malicious samples flagged)
- **precision: 100.0%** · false-positive rate 0.0% (0/28 benign samples wrongly flagged)

## Recall by OWASP class

| class | recall |
|---|---|
| AST01 | 100% |
| AST02 | 100% |
| AST04 | 100% |
| AST05 | 100% |

## Recall by technique

| technique | recall |
|---|---|
| agent-config-autorun | 100% |
| credential-exfil | 100% |
| decode-exec | 100% |
| deserialize-exec | 100% |
| email-exfil | 100% |
| gyp-command-substitution | 100% |
| hidden-unicode | 100% |
| install-dropper | 100% |
| lethal-trifecta | 100% |
| mcp-sampling-injection | 100% |
| mcp-tool-poisoning | 100% |
| password-archive | 100% |
| prompt-injection | 100% |
| pth-persistence | 100% |
| shell-decode-exec | 100% |
| typosquat-dropper | 100% |

## Coverage matrix (positive samples: class x language)

| class | manifest/text | node | python | shell |
|---|---|---|---|---|
| AST01 | 6 | 7 | 7 | 2 |
| AST02 | 0 | 4 | 2 | 0 |
| AST04 | 10 | 1 | 4 | 0 |
| AST05 | 0 | 0 | 2 | 0 |

> Languages with no semantic exec/network/deserialization detection (Go, Rust, Java, Ruby, PHP) are a documented gap — see `docs/language-scope.md`.

