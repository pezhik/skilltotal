# SkillTotal detection-efficacy report

Engine 1.11.0 · ruleset 110 · Python 3.11 · offline corpus.

- **recall: 100.0%** (391/391 malicious samples flagged)
- **precision: 100.0%** · false-positive rate 0.0% (0/302 benign samples wrongly flagged)

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
| agent-cred-helper-exec | 100% |
| agent-dotenv-exec | 100% |
| agent-launcher-hijack | 100% |
| builtin-name-lookup | 100% |
| cli-relay | 100% |
| clipboard-swap | 100% |
| compiled-node-output | 100% |
| credential-exfil | 100% |
| decode-exec | 100% |
| decode-spawn | 100% |
| decrypt-and-execute | 100% |
| dep-redirect | 100% |
| dependency-confusion-beacon | 100% |
| deserialize-exec | 100% |
| dns-exfil | 100% |
| dynamic-call-resolution | 100% |
| email-exfil | 100% |
| encrypted-instructions-decoy-key-env-read | 100% |
| entry-point-path-demotion | 100% |
| env-dump-exfil | 100% |
| fake-http-dependency-download-beacon | 100% |
| foreign-image | 100% |
| git-hook-persistence | 100% |
| github-action-secret-exfil | 100% |
| gyp-command-substitution | 100% |
| hidden-unicode | 100% |
| init-remote-archive-loader | 100% |
| install-dropper | 100% |
| js-shell-polyglot-preinstall | 100% |
| known-trojanized-image | 100% |
| lethal-trifecta | 100% |
| main-file-harvest | 100% |
| mcp-config-inject | 100% |
| mcp-hidden-dotpath-launcher | 100% |
| mcp-launch-command | 100% |
| mcp-oauth-endpoint-injection | 100% |
| mcp-sampling-injection | 100% |
| mcp-sampling-sysprompt | 100% |
| mcp-schema-default-command | 100% |
| mcp-static-auth-exec | 100% |
| mcp-tool-poisoning | 100% |
| module-run-embedded-infostealer-exe | 100% |
| native-addon-dropper-sandbox-gate | 100% |
| npm-lifecycle-remote-exec | 100% |
| npm-postinstall-miner | 100% |
| npm-preinstall-id-output-curl-beacon | 100% |
| npm-worm | 100% |
| password-archive | 100% |
| pickle-reduce-gadget | 100% |
| platform-binary-dropper | 100% |
| plugin-hook-trojan | 100% |
| post-exploitation | 100% |
| powershell-download-exec | 100% |
| preview-pane-oversized-html-file-url-csp-bypass | 100% |
| prompt-injection | 100% |
| prompt-split-exfil | 100% |
| pth-persistence | 100% |
| scriptlet-host | 100% |
| setup-detached-fetch | 100% |
| setup-host-beacon | 100% |
| setup-py-install-cmd-override-embedded-exe | 100% |
| shell-decode-exec | 100% |
| shell-hidden-command | 100% |
| skill-dynamic-exec | 100% |
| skill-fetch-exec | 100% |
| skill-scanner-directed-audit-override-text | 100% |
| skill-writes-agent-memory-files-persistence | 100% |
| socket-shell | 100% |
| ssh-tunnel-backdoor | 100% |
| startup-hook-exec | 100% |
| stdlib-shadow | 100% |
| token-revocation-wiper | 100% |
| typosquat-dropper | 100% |
| url-exec-loader | 100% |
| wallet-key-exfil | 100% |
| workflow-history-exfil | 100% |

## Coverage matrix (positive samples: class x language)

| class | manifest/text | node | python | shell |
|---|---|---|---|---|
| AST01 | 52 | 61 | 57 | 28 |
| AST02 | 49 | 35 | 15 | 7 |
| AST03 | 0 | 2 | 0 | 0 |
| AST04 | 59 | 6 | 14 | 0 |
| AST05 | 0 | 0 | 6 | 0 |

> Languages with no semantic exec/network/deserialization detection (Go, Rust, Java, Ruby, PHP) are a documented gap — see `docs/language-scope.md`.

## Rule coverage (rules mapped to an OWASP class, and rules with their own samples)

Each rule mapped to an OWASP class or with samples of its own, with the corpus samples it fired on. Rule samples under `tests/eval_corpus/rules/<rule>/` test the rule itself: a `fires/` sample must trigger it and a `silent/` look-alike must not. Rule samples are not part of recall or precision: a capability rule adds nothing to the score, and one risky construct alone usually stays below high risk, so most rule samples are not flagged, by design. A rule firing on a benign sample is not a false positive by itself, because precision is judged on the verdict. Rule samples show that a rule matches what it describes. They do not estimate how often it fires on benign code in the wild.

| rule | class | fired on malicious samples | fired on benign samples | rule samples: fired | rule samples: stayed silent |
|---|---|---|---|---|---|
| `ST-FS-NODE-WRITE` | - | 14 | 10 | 2/2 | 1/1 |
| `ST-ACTION-SECRET-EXFIL` | AST01 | 1 | 0 | - | - |
| `ST-ARCHIVE-PASSWORD-EXTRACT` | AST01 | 1 | 0 | - | - |
| `ST-BYTECODE-NO-SOURCE` | AST01 | 0 | 0 | 2/2 | 2/2 |
| `ST-CLIPPER` | AST01 | 4 | 0 | - | - |
| `ST-COMBO-EXFIL` | AST01 | 59 | 0 | 1/1 | 1/1 |
| `ST-CONVERGENCE` | AST01 | 14 | 0 | - | - |
| `ST-EMAIL-BCC-EXFIL` | AST01 | 1 | 0 | 1/1 | 1/1 |
| `ST-ENCRYPTED-ARCHIVE` | AST01 | 0 | 0 | - | - |
| `ST-FLOW-TRIFECTA` | AST01 | 1 | 0 | - | - |
| `ST-HTML-FILE-URL-EXFIL` | AST01 | 1 | 0 | - | - |
| `ST-LOOKALIKE-IDENTIFIER` | AST01 | 0 | 0 | 3/3 | 3/3 |
| `ST-MCP-SERVER-HIDDEN-EXEC` | AST01 | 1 | 0 | - | - |
| `ST-MCP-STATIC-AUTH-EXEC` | AST01 | 3 | 0 | - | - |
| `ST-OBF-DECODE-EXEC` | AST01 | 32 | 0 | - | - |
| `ST-OBF-DECODE-EXEC-PY` | AST01 | 2 | 0 | - | - |
| `ST-OBF-DECODE-EXEC-SH` | AST01 | 15 | 0 | - | - |
| `ST-OBF-DECRYPT-EXEC` | AST01 | 1 | 0 | - | - |
| `ST-OBF-DYNAMIC-DECODE-EXEC` | AST01 | 1 | 0 | - | - |
| `ST-POSTEX-BEACON` | AST01 | 2 | 0 | - | - |
| `ST-POSTEX-CHAIN` | AST01 | 11 | 0 | - | - |
| `ST-POSTEX-EVASION` | AST01 | 4 | 0 | - | - |
| `ST-POSTEX-MASQUERADE` | AST01 | 3 | 0 | - | - |
| `ST-POSTEX-PERSIST` | AST01 | 13 | 8 | 3/3 | 2/2 |
| `ST-POSTEX-REMOTE-ACCESS` | AST01 | 8 | 2 | - | - |
| `ST-POSTEX-REVERSE-SHELL` | AST01 | 2 | 0 | - | - |
| `ST-POSTEX-STAGER` | AST01 | 4 | 0 | - | - |
| `ST-PS-DOWNLOAD-EXEC` | AST01 | 2 | 0 | - | - |
| `ST-PTH-EXEC` | AST01 | 3 | 0 | - | - |
| `ST-PTH-IMPORT-EXEC` | AST01 | 1 | 0 | - | - |
| `ST-PY-BUILTIN-NAME-LOOKUP` | AST01 | 3 | 0 | - | - |
| `ST-PY-MAIN-BUNDLED-EXE-HIDDEN` | AST01 | 1 | 0 | - | - |
| `ST-PY-MAIN-FILE-HARVEST` | AST01 | 1 | 0 | - | - |
| `ST-PY-SOCKET-SHELL` | AST01 | 1 | 0 | - | - |
| `ST-PY-STDLIB-SHADOW` | AST01 | 1 | 0 | - | - |
| `ST-SECRET-EXFIL` | AST01 | 47 | 0 | - | - |
| `ST-SHELL-EVASION` | AST01 | 2 | 1 | 2/2 | 1/1 |
| `ST-SHELL-HIDDEN-COMMAND` | AST01 | 3 | 0 | - | - |
| `ST-SKILL-DYNAMIC-EXEC` | AST01 | 4 | 0 | - | - |
| `ST-SKILL-ENCRYPTED-INSTRUCTIONS` | AST01 | 1 | 0 | - | - |
| `ST-SKILL-MEMORY-WRITE-HIDDEN` | AST01 | 2 | 0 | - | - |
| `ST-SSH-TUNNEL-BACKDOOR` | AST01 | 1 | 0 | - | - |
| `ST-WORKFLOW-HISTORY-EXFIL` | AST01 | 1 | 0 | - | - |
| `ST-WORKFLOW-SECRETS-DUMP-EXFIL` | AST01 | 2 | 0 | - | - |
| `ST-ARTIFACT-KNOWN-BAD` | AST01, AST02 | 1 | 0 | - | - |
| `ST-INSTALL-MINER` | AST01, AST02 | 1 | 0 | - | - |
| `ST-INSTALL-NPM-REMOTE-EXEC` | AST01, AST02 | 20 | 0 | - | - |
| `ST-NODE-FETCH-EXEC` | AST01, AST02 | 5 | 0 | - | - |
| `ST-NPM-SANDBOX-GATED-LOADER` | AST01, AST02 | 1 | 0 | - | - |
| `ST-OBF-DECODE-SPAWN` | AST01, AST02 | 9 | 0 | - | - |
| `ST-PY-FETCH-EXEC` | AST01, AST02 | 6 | 0 | - | - |
| `ST-PY-INIT-REMOTE-ARCHIVE-LOADER` | AST01, AST02 | 1 | 0 | - | - |
| `ST-PY-SCRIPTLET-HOST` | AST01, AST02 | 1 | 0 | - | - |
| `ST-PY-SETUP-DETACHED-FETCH` | AST01, AST02 | 1 | 0 | - | - |
| `ST-PY-SETUP-EXE-LAUNCH` | AST01, AST02 | 1 | 0 | - | - |
| `ST-PY-SETUP-HOST-BEACON` | AST01, AST02 | 1 | 0 | - | - |
| `ST-SKILL-FETCH-EXEC-HIDDEN` | AST01, AST02 | 9 | 0 | 3/3 | 2/2 |
| `ST-STARTUP-HOOK-EXEC` | AST01, AST02 | 1 | 0 | - | - |
| `ST-AGENT-CONFIG-PERSIST` | AST01, AST04 | 7 | 0 | - | - |
| `ST-AGENT-CRED-HELPER-EXEC` | AST01, AST04 | 2 | 0 | - | - |
| `ST-AGENT-DOTENV-EXEC` | AST01, AST04 | 1 | 0 | - | - |
| `ST-AGENT-LAUNCHER-HIJACK` | AST01, AST04 | 1 | 0 | - | - |
| `ST-MCP-DEFAULT-COMMAND` | AST01, AST04 | 2 | 0 | - | - |
| `ST-MCP-OAUTH-ENDPOINT-INJECTION` | AST01, AST04 | 2 | 0 | - | - |
| `ST-MCP-SAMPLING-SYSPROMPT` | AST01, AST04 | 1 | 0 | - | - |
| `ST-PROMPT-SPLIT-EXFIL` | AST01, AST04 | 1 | 0 | - | - |
| `ST-PICKLE-REDUCE` | AST01, AST05 | 3 | 0 | - | - |
| `ST-AGENT-AUTORUN` | AST02 | 4 | 5 | 5/5 | 3/3 |
| `ST-AGENT-AUTORUN-REMOTE` | AST02 | 10 | 0 | - | - |
| `ST-AGENT-ENV-INJECT` | AST02 | 3 | 0 | 3/3 | 3/3 |
| `ST-AGENT-GITCONFIG-EXEC-REMOTE` | AST02 | 0 | 0 | - | - |
| `ST-ARTIFACT-DIRTY-BUILD` | AST02 | 1 | 0 | - | - |
| `ST-ARTIFACT-FOREIGN-IMAGE` | AST02 | 1 | 0 | - | - |
| `ST-ARTIFACT-HTTP-BINARY` | AST02 | 1 | 0 | - | - |
| `ST-DEP-FOREIGN-SOURCE` | AST02 | 0 | 0 | 4/4 | 4/4 |
| `ST-DEP-REGISTRY-LOOKALIKE` | AST02 | 2 | 0 | 2/2 | 1/1 |
| `ST-DEP-TYPOSQUAT` | AST02 | 0 | 0 | 7/7 | 3/3 |
| `ST-DISGUISED-SCRIPT` | AST02 | 3 | 0 | 2/2 | 2/2 |
| `ST-GIT-HOOK-PERSIST` | AST02 | 2 | 0 | 1/1 | 2/2 |
| `ST-INSTALL-DROPPER` | AST02 | 20 | 0 | 1/1 | 1/1 |
| `ST-INSTALL-GYP` | AST02 | 2 | 0 | - | - |
| `ST-INSTALL-NPM` | AST02 | 52 | 31 | 1/1 | 1/1 |
| `ST-INSTALL-NPM-DNS-BEACON` | AST02 | 1 | 0 | - | - |
| `ST-INSTALL-NPM-MASKED-REGISTRY` | AST02 | 1 | 0 | - | - |
| `ST-INSTALL-NPM-PREPARE` | AST02 | 3 | 6 | 1/1 | 1/1 |
| `ST-INSTALL-NPM-SERVICE-TOKEN-WATCH` | AST02 | 1 | 0 | - | - |
| `ST-INSTALL-NPM-SHELL-RUNS-JS` | AST02 | 1 | 0 | - | - |
| `ST-INSTALL-PY` | AST02 | 10 | 8 | 1/1 | 1/1 |
| `ST-INSTALL-PY-DOWNLOAD-EXEC` | AST02 | 3 | 0 | - | - |
| `ST-LOOKALIKE-HOST` | AST02 | 5 | 0 | 3/3 | 2/2 |
| `ST-NPM-BIN-SHADOW` | AST02 | 0 | 0 | 1/1 | 1/1 |
| `ST-NPM-DEPCONF-BEACON` | AST02 | 1 | 0 | - | - |
| `ST-NPM-GIT-DEP` | AST02 | 0 | 0 | 1/1 | 1/1 |
| `ST-NPM-INSTALL-PUBLISH` | AST02 | 4 | 0 | - | - |
| `ST-NPM-INSTALL-RECON-BEACON` | AST02 | 1 | 0 | - | - |
| `ST-NPM-URL-DEP` | AST02 | 1 | 0 | 1/1 | 1/1 |
| `ST-PY-DEP-PLAIN-HTTP-URL` | AST02 | 1 | 0 | - | - |
| `ST-SHELL-PIPE-EXEC` | AST02 | 6 | 4 | 9/9 | 5/5 |
| `ST-SHELL-PIPE-EXEC-NODE` | AST02 | 10 | 0 | 3/3 | 2/2 |
| `ST-SHELL-PIPE-EXEC-PY` | AST02 | 5 | 1 | 5/5 | 2/2 |
| `ST-SKILL-FETCH-EXEC` | AST02 | 5 | 5 | 1/1 | 2/2 |
| `ST-TYPOSQUAT` | AST02 | 1 | 0 | 2/2 | 1/1 |
| `ST-SKILL-DEP-REDIRECT` | AST02, AST04 | 1 | 0 | - | - |
| `ST-AGENT-AUTO-APPROVE` | AST03 | 0 | 0 | 4/4 | 3/3 |
| `ST-AGENT-CLI-BYPASS` | AST03 | 0 | 3 | 2/2 | 2/2 |
| `ST-AGENT-CLI-RELAY` | AST03 | 2 | 0 | - | - |
| `ST-MCP-AUTO-APPROVE` | AST03 | 0 | 0 | 1/1 | 1/1 |
| `ST-MCP-DANGEROUS-TOOL` | AST03 | 7 | 5 | 3/3 | 2/2 |
| `ST-MCP-OVERBROAD-SCOPE` | AST03 | 0 | 0 | 1/1 | 1/1 |
| `ST-MCP-SERVER-EXEC` | AST03 | 8 | 6 | 3/3 | 2/2 |
| `ST-MCP-ANNOTATION-MISMATCH` | AST03, AST04 | 0 | 0 | 5/5 | 3/3 |
| `ST-SKILL-CAP-MISMATCH` | AST03, AST04 | 1 | 2 | - | - |
| `ST-AGENT-API-REDIRECT` | AST04 | 0 | 0 | - | - |
| `ST-AGENT-CONFIG-INJECT` | AST04 | 1 | 3 | - | - |
| `ST-HIDDEN-ANSI` | AST04 | 9 | 0 | - | - |
| `ST-HIDDEN-UNICODE` | AST04 | 13 | 0 | - | - |
| `ST-HIDDEN-UNICODE-AMBIG` | AST04 | 0 | 0 | - | - |
| `ST-MCP-DESCRIPTION-SWAP` | AST04 | 2 | 0 | 2/2 | 1/1 |
| `ST-MCP-ELICIT-SECRET` | AST04 | 0 | 0 | - | - |
| `ST-MCP-SAMPLING-INJECTION` | AST04 | 1 | 0 | - | - |
| `ST-MCP-TOOL-POISONING` | AST04 | 35 | 0 | - | - |
| `ST-MCP-TOOL-SHADOWING` | AST04 | 0 | 0 | - | - |
| `ST-PROMPT-INJECTION` | AST04 | 46 | 0 | - | - |
| `ST-PROMPT-WEAK` | AST04 | 0 | 0 | - | - |
| `ST-SKILL-AUDIT-OVERRIDE` | AST04 | 2 | 0 | - | - |
| `ST-DESERIALIZE-PY` | AST05 | 1 | 0 | 1/1 | 1/1 |
| `ST-TAINT-DESERIAL-PY` | AST05 | 1 | 0 | - | - |

120 of 127 rules fire on at least one sample.
Fired on no sample: `ST-ENCRYPTED-ARCHIVE`, `ST-AGENT-GITCONFIG-EXEC-REMOTE`, `ST-AGENT-API-REDIRECT`, `ST-HIDDEN-UNICODE-AMBIG`, `ST-MCP-ELICIT-SECRET`, `ST-MCP-TOOL-SHADOWING`, `ST-PROMPT-WEAK`.

