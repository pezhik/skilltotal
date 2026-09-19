# The MCP registry, measured

A deterministic static scan of every distinct component in the public MCP registry — 17,535 of them — scanned on 2026-09-19 against the registry as of 2026-08-16 with SkillTotal 0.49.0 (ruleset 59).

## How to read this

Every figure below describes a **capability**: something a component is able to do, derived only from the code it ships. A capability is not a vulnerability. A server that runs shell commands may exist precisely to run shell commands. What the numbers show is the reach an agent inherits when it hands work to one of these components.

## Population

The registry lists a server per published *version*, so its 73,460 entries collapse to **17,535 distinct components**. Aggregating the raw list would count a single package many times over.

| | |
|---|---|
| Distinct components | 17,535 |
| Scanned | **15,341** (87.5%) |
| Not scanned | 2,194 (12.5%) |

Nothing was dropped silently — every exclusion is counted:

| Why a component was not scanned | Components | Share of population |
|---|---:|---:|
| repository or package no longer reachable | 1,637 | 9.3% |
| slower than the time bound | 302 | 1.7% |
| larger than the size bound | 188 | 1.1% |
| other | 65 | 0.4% |
| access denied | 2 | 0.0% |

| Ecosystem | Scanned | Listed | Coverage |
|---|---:|---:|---:|
| git | 5,389 | 7,312 | 73.7% |
| npm | 6,967 | 7,152 | 97.4% |
| pypi | 2,985 | 3,071 | 97.2% |

## What these components can do

Share of the 15,341 scanned components carrying each capability:

| Capability | Components | Share |
|---|---:|---:|
| exposes MCP tools | 13,524 | **88.2%** |
| can reach the network | 9,938 | **64.8%** |
| can execute shell commands | 3,230 | **21.1%** |
| reads the filesystem | 3,828 | **25.0%** |
| writes the filesystem | 3,206 | **20.9%** |
| runs code at install time | 1,134 | **7.4%** |
| uses delegated (OAuth/OIDC) authentication | 895 | **5.8%** |
| evaluates code dynamically | 475 | **3.1%** |
| uses a scoped, short-lived identity | 81 | **0.5%** |

## OWASP Agentic Skills Top 10

Every rule that has an honest static fit carries its OWASP class, so the same scan answers which classes this population actually exhibits. A class appears here when a component carries at least one finding mapped to it; a component can appear in several. Classes with no evidence in this population are left out rather than printed as zero. A class counts the rules mapped to it, not a verdict: the rules under *Malicious Skills* include exfiltration paths and evasion idioms that a legitimate tool can carry, and no component in this population carries a malicious indicator.

| Class | Components | Share |
|---|---:|---:|
| AST03 Over-Privileged Skills | 1,905 | 12.4% |
| AST02 Supply Chain Compromise | 1,216 | 7.9% |
| AST01 Malicious Skills | 73 | 0.5% |
| AST05 Unsafe Deserialization | 53 | 0.3% |

## Which rules fired

38 rules matched something in this population; the 15 most frequent are below, and the count for every rule is in the JSON beside this file. A rule firing describes what the code does, not what it intends — most of the traffic here is capability rules, which add nothing to the risk score. That is precisely why the risk table below is so much flatter than the capability table above. `skilltotal rules list` documents every id.

| Rule | Components | Share |
|---|---:|---:|
| `ST-MCP-DETECTED` | 13,524 | 88.2% |
| `ST-NET-NODE` | 7,417 | 48.3% |
| `ST-NET-PY` | 2,782 | 18.1% |
| `ST-FS-PY-READ` | 2,343 | 15.3% |
| `ST-SHELL-NODE` | 2,121 | 13.8% |
| `ST-FS-PY-WRITE` | 1,964 | 12.8% |
| `ST-FS-NODE-READ` | 1,547 | 10.1% |
| `ST-EXPOSE-BIND` | 1,363 | 8.9% |
| `ST-FS-NODE-WRITE` | 1,312 | 8.6% |
| `ST-MCP-DANGEROUS-TOOL` | 1,298 | 8.5% |
| `ST-SHELL-PY` | 1,149 | 7.5% |
| `ST-AUTH-DELEGATED` | 895 | 5.8% |
| `ST-INSTALL-NPM-PREPARE` | 749 | 4.9% |
| `ST-MCP-SERVER-EXEC` | 695 | 4.5% |
| `ST-INSTALL-NPM` | 375 | 2.4% |

## Risk levels

SkillTotal scores risky constructs and malicious indicators; a capability on its own contributes zero to the score, and so does a secret the component ships, which the engine reports separately as an exposure. The risk distribution is therefore far flatter than the capability table above, and that difference is the point.

| Level | Components | Share |
|---|---:|---:|
| low | 15,225 | 99.3% |
| medium | 90 | 0.6% |
| high | 22 | 0.1% |
| critical | 4 | <0.1% |
| carrying a malicious indicator | 0 | 0.0% |

## The registry itself

- 73,460 entries resolve to 17,535 distinct components.
- 9.3% of the population points at a repository or package that is gone or private.
- 7,312 components are hosted on GitHub across 4,325 owners — yet one owner accounts for **18.0%** of them, and the ten largest for 29.1%.

## What this report does not claim

**No count of leaked credentials.** The engine does detect embedded secrets and that signal ships in the product, but a sample of the hits in this population was dominated by values published on purpose: analytics project keys that vendors document as safe to expose, on-chain addresses, and public vendor constants. A raw count would measure *shape* rather than exposure, and presenting it as a number of leaks would be a false statement about named projects. A figure will appear here once it can be given with a precision estimate from a labelled sample.

**No claim that any component is safe.** A malicious indicator is a match against a published rule for a known attack shape: decode-and-execute, hidden Unicode, instructions planted for the agent, auto-run hooks, credentials sent out. A count of zero means no component matched one, not that none is harmful: code fetched at run time is out of a static scan's sight, and so is an attack no rule describes yet.

**No component is named.** These are population statistics.

## Method

- Engine 0.49.0, ruleset 59 — deterministic regex and AST analysis. The component is never executed and no LLM is involved, so the run reproduces.
- Scanned components by ruleset: 11,774 with ruleset 56, 9 with ruleset 57, 30 with ruleset 58, 3,528 with ruleset 59. The later ruleset re-scanned only the components whose result its changes could affect, plus those that exceeded a bound on the first pass. Ruleset 59 tied the Node.js shell-execution rule to an actual `child_process` import, after a hand-checked sample showed most of its earlier hits were regular-expression and database `.exec()` calls; every component that carried a shell finding was re-scanned, which is why the shell-execution share fell from 30.3% (ruleset 58) to 21.1%. The other capability figures moved by 1-2% only because 85 components that scanned on the first pass exceeded a bound (mostly the time bound) on the re-scan and left the scanned set.
- Population: `https://registry.modelcontextprotocol.io/v0/servers` as of 2026-08-16, deduplicated by source.
- Two bounds, both disclosed above: 50 MB per fetch and 60s of wall clock per component.
- Harness: `tests/manual_eval/survey_registry.py`. This report: `tests/manual_eval/survey_report.py`. Both ship in this repository.
- Shares are rounded to one decimal place so that each table sums exactly to its total (largest-remainder method); a share can therefore sit up to 0.1 point from its unrounded value. The counts beside them are exact.
