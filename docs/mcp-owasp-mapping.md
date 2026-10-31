# MCP security coverage — OWASP MCP Security Cheat Sheet mapping

How SkillTotal's deterministic static analysis maps to the statically-checkable controls in the
[OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).
SkillTotal analyzes an MCP server's own files (manifest + code) only; it never executes the server
or inspects a deployment. Runtime/deployment controls are out of scope for a static engine and are
listed at the end as honest gaps (planned for the hosted SkillTotal Cloud).

## Statically checkable — covered

| OWASP control (static) | SkillTotal rule(s) | Notes |
|---|---|---|
| Tool-description / metadata injection (tool poisoning) | `ST-MCP-TOOL-POISONING`, `ST-PROMPT-INJECTION` | manifest tool/`inputSchema` descriptions + code docstrings; de-obfuscated (homoglyph/zero-width) |
| Sampling abuse (server-written prompt run by the client's model) | `ST-MCP-SAMPLING-INJECTION` | Python functions calling `create_message`, TypeScript `createMessage(`; needs two of credential request, command request, concealment |
| Cross-server tool shadowing | `ST-MCP-TOOL-SHADOWING` | surfaced for review (legit routing is indistinguishable by pattern) |
| Over-broad privilege / scope in manifest | `ST-MCP-OVERBROAD-SCOPE` | wildcard / `full_access` / `read_write_all` scope grants |
| Auto-approval / removed human-in-loop gate | `ST-MCP-AUTO-APPROVE` | `autoApprove` / `alwaysAllow` / `trust` |
| Server launches a host command | `ST-MCP-SERVER-EXEC` | `mcpServers[].command` |
| Command construction / OS-command injection | `ST-CMDI-PY`, `ST-CMDI-NODE`, `ST-TAINT-SHELL-PY`, `ST-SHELL-EVASION` | untrusted value into a shell |
| Input-validation gaps (untrusted input → dangerous sink) | `ST-TAINT-EXEC-PY`, `ST-TAINT-SHELL-PY`, `ST-TAINT-DESERIAL-PY` | intra-procedural taint (incl. MCP tool parameters as a source) |
| Hardcoded credentials / secrets in code or config | `ST-SECRET-EMBEDDED`, `ST-SENS-PATH` | known-prefix tokens, credential paths |
| Dangerous tool capabilities (shell/fs/network/browser/credential) | `ST-MCP-DANGEROUS-TOOL` | classified from tool name/description |
| Tool annotations that misstate what a tool does | `ST-MCP-ANNOTATION-MISMATCH` | `readOnlyHint: true` on a handler that writes, deletes, sends PUT/PATCH/DELETE, or runs a command it is handed or one that changes things; `destructiveHint: false` on one that deletes; the handler's own body only |
| Data-exfiltration surface (sensitive access + egress) | `ST-COMBO-EXFIL`, `ST-FLOW-TRIFECTA`, MCP exfiltration-surface review | credential access + network; lethal-trifecta flow |
| Supply-chain payload in the server's own code | `ST-OBF-DECODE-EXEC*`, `ST-PTH-EXEC`, `ST-INSTALL-DROPPER`, `ST-ENCRYPTED-ARCHIVE`, `ST-HIDDEN-UNICODE` | obfuscation, auto-exec persistence, install droppers, evasion |

## Not statically checkable — runtime / deployment (SkillTotal Cloud)

These OWASP controls require executing the server or observing the live deployment and are **not**
addressable by static analysis: sandboxing enforcement, human-in-loop approval UI, rate limiting /
DoS resistance, runtime rug-pull (tool re-hash at call time), replay/nonce enforcement, session
binding & confusion-deputy checks, cross-server runtime data-flow, credential rotation, and
verifying secrets are stored in an OS keychain at runtime. Dependency-CVE checks require registry
and advisory data and likewise live outside the offline engine. Typosquatting is checked offline:
`ST-TYPOSQUAT` compares an npm or PyPI package name with a built-in list of popular packages.

> A complete MCP posture needs both static (this engine) and runtime verification. SkillTotal's
> free engine runs the static checks mapped above and names the controls it does not cover.
