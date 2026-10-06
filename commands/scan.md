---
description: Scan an MCP server, agent skill, package or repo with SkillTotal before you trust it
argument-hint: <npm:name | pypi:name | git URL | local path>
allowed-tools: Bash(skilltotal scan:*)
---

Run `skilltotal scan $ARGUMENTS --json` and read the report.

Then tell me, briefly:
1. The verdict and the risk score, and whether there are malicious indicators.
2. Each malicious indicator or risky finding with its file:line and the snippet, in one line each.
3. The capabilities it has (shell, network, filesystem, credentials) as a short list. Capabilities are what the code can do, not a verdict.
4. A recommendation: install, install with the listed permissions only, or don't install.

If `skilltotal` is not installed, say so and suggest `pip install skilltotal`.
