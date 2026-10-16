# SkillTotal detection-efficacy report

Engine 0.74.0 · ruleset 76 · Python 3.14 · offline corpus.

- **recall: 100.0%** (125/125 malicious samples flagged)
- **precision: 100.0%** · false-positive rate 0.0% (0/89 benign samples wrongly flagged)

## Recall by OWASP class

| class | recall |
|---|---|
| AST01 | 100% |
| AST02 | 100% |
| AST03 | 100% |
| AST04 | 100% |
| AST05 | 100% |

## Recall by technique

| technique | recall |
|---|---|
| action-run-exec | 100% |
| agent-config-autorun | 100% |
| agent-config-persist | 100% |
| cli-relay | 100% |
| clipboard-swap | 100% |
| credential-exfil | 100% |
| decode-exec | 100% |
| decrypt-and-execute | 100% |
| dep-redirect | 100% |
| deserialize-exec | 100% |
| dns-exfil | 100% |
| dynamic-call-resolution | 100% |
| email-exfil | 100% |
| env-dump-exfil | 100% |
| git-hook-persistence | 100% |
| github-action-secret-exfil | 100% |
| gyp-command-substitution | 100% |
| hidden-unicode | 100% |
| install-dropper | 100% |
| lethal-trifecta | 100% |
| mcp-config-inject | 100% |
| mcp-hidden-dotpath-launcher | 100% |
| mcp-launch-command | 100% |
| mcp-sampling-injection | 100% |
| mcp-tool-poisoning | 100% |
| npm-lifecycle-remote-exec | 100% |
| npm-worm | 100% |
| password-archive | 100% |
| pickle-reduce-gadget | 100% |
| plugin-hook-trojan | 100% |
| powershell-download-exec | 100% |
| prompt-injection | 100% |
| pth-persistence | 100% |
| shell-decode-exec | 100% |
| skill-dynamic-exec | 100% |
| skill-fetch-exec | 100% |
| typosquat-dropper | 100% |
| wallet-key-exfil | 100% |

## Coverage matrix (positive samples: class x language)

| class | manifest/text | node | python | shell |
|---|---|---|---|---|
| AST01 | 17 | 24 | 15 | 2 |
| AST02 | 20 | 11 | 2 | 1 |
| AST03 | 0 | 1 | 0 | 0 |
| AST04 | 17 | 3 | 8 | 0 |
| AST05 | 0 | 0 | 4 | 0 |

> Languages with no semantic exec/network/deserialization detection (Go, Rust, Java, Ruby, PHP) are a documented gap — see `docs/language-scope.md`.

