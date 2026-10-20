# SkillTotal detection-efficacy report

Engine 0.79.0 · ruleset 79 · Python 3.14 · offline corpus.

- **recall: 100.0%** (130/130 malicious samples flagged)
- **precision: 100.0%** · false-positive rate 0.0% (0/94 benign samples wrongly flagged)

## Recall by OWASP class

| class | recall |
|---|---|
| AST01 | 100% |
| AST02 | 100% |
| AST03 | 100% |
| AST04 | 100% |
| AST05 | 100% |

> A class row counts the malicious samples filed under that class and flagged by any rule. It does not show which rules did the work; the rule coverage table below does.

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
| AST01 | 17 | 26 | 18 | 2 |
| AST02 | 20 | 11 | 2 | 1 |
| AST03 | 0 | 1 | 0 | 0 |
| AST04 | 17 | 3 | 8 | 0 |
| AST05 | 0 | 0 | 4 | 0 |

> Languages with no semantic exec/network/deserialization detection (Go, Rust, Java, Ruby, PHP) are a documented gap — see `docs/language-scope.md`.

## Rule coverage (rules mapped to an OWASP class)

Each rule mapped to an OWASP class, with the corpus samples it fired on. Rule samples under `tests/eval_corpus/rules/<rule>/` test the rule itself: a `fires/` sample must trigger it and a `silent/` look-alike must not. Rule samples are not part of recall or precision: a capability rule adds nothing to the score, and one risky construct alone usually stays below high risk, so most rule samples are not flagged, by design. A rule firing on a benign sample is not a false positive by itself, because precision is judged on the verdict. Rule samples show that a rule matches what it describes. They do not estimate how often it fires on benign code in the wild.

| rule | class | fired on malicious samples | fired on benign samples | rule samples: fired | rule samples: stayed silent |
|---|---|---|---|---|---|
| `ST-ACTION-SECRET-EXFIL` | AST01 | 1 | 0 | - | - |
| `ST-ARCHIVE-PASSWORD-EXTRACT` | AST01 | 1 | 0 | - | - |
| `ST-CLIPPER` | AST01 | 3 | 0 | - | - |
| `ST-COMBO-EXFIL` | AST01 | 24 | 0 | 1/1 | 1/1 |
| `ST-CONVERGENCE` | AST01 | 4 | 0 | - | - |
| `ST-EMAIL-BCC-EXFIL` | AST01 | 1 | 0 | 1/1 | 1/1 |
| `ST-ENCRYPTED-ARCHIVE` | AST01 | 0 | 0 | - | - |
| `ST-FLOW-TRIFECTA` | AST01 | 1 | 0 | - | - |
| `ST-MCP-SERVER-HIDDEN-EXEC` | AST01 | 1 | 0 | - | - |
| `ST-OBF-DECODE-EXEC` | AST01 | 15 | 0 | - | - |
| `ST-OBF-DECODE-EXEC-PY` | AST01 | 2 | 0 | - | - |
| `ST-OBF-DECODE-EXEC-SH` | AST01 | 8 | 0 | - | - |
| `ST-OBF-DECRYPT-EXEC` | AST01 | 1 | 0 | - | - |
| `ST-OBF-DYNAMIC-DECODE-EXEC` | AST01 | 1 | 0 | - | - |
| `ST-PS-DOWNLOAD-EXEC` | AST01 | 2 | 0 | - | - |
| `ST-PTH-EXEC` | AST01 | 2 | 0 | - | - |
| `ST-PTH-IMPORT-EXEC` | AST01 | 1 | 0 | - | - |
| `ST-SECRET-EXFIL` | AST01 | 9 | 0 | - | - |
| `ST-SHELL-EVASION` | AST01 | 0 | 0 | 2/2 | 1/1 |
| `ST-SKILL-DYNAMIC-EXEC` | AST01 | 1 | 0 | - | - |
| `ST-INSTALL-NPM-REMOTE-EXEC` | AST01, AST02 | 4 | 0 | - | - |
| `ST-SKILL-FETCH-EXEC-HIDDEN` | AST01, AST02 | 2 | 0 | - | - |
| `ST-AGENT-CONFIG-PERSIST` | AST01, AST04 | 6 | 0 | - | - |
| `ST-PICKLE-REDUCE` | AST01, AST05 | 2 | 0 | - | - |
| `ST-AGENT-AUTORUN` | AST02 | 3 | 3 | 2/2 | 1/1 |
| `ST-AGENT-AUTORUN-REMOTE` | AST02 | 5 | 0 | - | - |
| `ST-AGENT-GITCONFIG-EXEC-REMOTE` | AST02 | 0 | 0 | - | - |
| `ST-GIT-HOOK-PERSIST` | AST02 | 1 | 0 | - | - |
| `ST-INSTALL-DROPPER` | AST02 | 8 | 0 | 1/1 | 1/1 |
| `ST-INSTALL-GYP` | AST02 | 1 | 0 | - | - |
| `ST-INSTALL-NPM` | AST02 | 17 | 5 | 1/1 | 1/1 |
| `ST-INSTALL-NPM-PREPARE` | AST02 | 0 | 3 | 1/1 | 1/1 |
| `ST-INSTALL-PY` | AST02 | 2 | 0 | 1/1 | 1/1 |
| `ST-NPM-GIT-DEP` | AST02 | 0 | 0 | - | - |
| `ST-NPM-INSTALL-PUBLISH` | AST02 | 2 | 0 | - | - |
| `ST-NPM-URL-DEP` | AST02 | 0 | 0 | - | - |
| `ST-SHELL-PIPE-EXEC` | AST02 | 2 | 2 | 1/1 | 1/1 |
| `ST-SHELL-PIPE-EXEC-NODE` | AST02 | 3 | 0 | - | - |
| `ST-SHELL-PIPE-EXEC-PY` | AST02 | 0 | 0 | - | - |
| `ST-SKILL-FETCH-EXEC` | AST02 | 0 | 3 | - | - |
| `ST-TYPOSQUAT` | AST02 | 1 | 0 | 2/2 | 1/1 |
| `ST-SKILL-DEP-REDIRECT` | AST02, AST04 | 1 | 0 | - | - |
| `ST-AGENT-AUTO-APPROVE` | AST03 | 0 | 0 | 2/2 | 2/2 |
| `ST-AGENT-CLI-BYPASS` | AST03 | 0 | 2 | 1/1 | 1/1 |
| `ST-AGENT-CLI-RELAY` | AST03 | 1 | 0 | - | - |
| `ST-MCP-AUTO-APPROVE` | AST03 | 0 | 0 | 1/1 | 1/1 |
| `ST-MCP-DANGEROUS-TOOL` | AST03 | 0 | 0 | 3/3 | 2/2 |
| `ST-MCP-OVERBROAD-SCOPE` | AST03 | 0 | 0 | 1/1 | 1/1 |
| `ST-MCP-SERVER-EXEC` | AST03 | 5 | 3 | 3/3 | 2/2 |
| `ST-SKILL-CAP-MISMATCH` | AST03, AST04 | 1 | 2 | - | - |
| `ST-AGENT-API-REDIRECT` | AST04 | 0 | 0 | - | - |
| `ST-AGENT-CONFIG-INJECT` | AST04 | 1 | 1 | - | - |
| `ST-HIDDEN-ANSI` | AST04 | 2 | 0 | - | - |
| `ST-HIDDEN-UNICODE` | AST04 | 6 | 0 | - | - |
| `ST-HIDDEN-UNICODE-AMBIG` | AST04 | 0 | 0 | - | - |
| `ST-MCP-ELICIT-SECRET` | AST04 | 0 | 0 | - | - |
| `ST-MCP-SAMPLING-INJECTION` | AST04 | 1 | 0 | - | - |
| `ST-MCP-TOOL-POISONING` | AST04 | 12 | 0 | - | - |
| `ST-MCP-TOOL-SHADOWING` | AST04 | 0 | 0 | - | - |
| `ST-PROMPT-INJECTION` | AST04 | 17 | 0 | - | - |
| `ST-PROMPT-WEAK` | AST04 | 0 | 0 | - | - |
| `ST-DESERIALIZE-PY` | AST05 | 0 | 0 | 1/1 | 1/1 |
| `ST-TAINT-DESERIAL-PY` | AST05 | 1 | 0 | - | - |

53 of 63 rules fire on at least one sample.
Fired on no sample: `ST-ENCRYPTED-ARCHIVE`, `ST-AGENT-GITCONFIG-EXEC-REMOTE`, `ST-NPM-GIT-DEP`, `ST-NPM-URL-DEP`, `ST-SHELL-PIPE-EXEC-PY`, `ST-AGENT-API-REDIRECT`, `ST-HIDDEN-UNICODE-AMBIG`, `ST-MCP-ELICIT-SECRET`, `ST-MCP-TOOL-SHADOWING`, `ST-PROMPT-WEAK`.

