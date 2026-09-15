# The MCP registry, measured

A deterministic static scan of every distinct component in the public MCP registry — 17,535 of them — scanned on 2026-09-15 against the registry as of 2026-08-16 with SkillTotal 0.48.0 (ruleset 55).

## How to read this

Every figure below describes a **capability**: something a component is able to do, derived only from the code it ships. A capability is not a vulnerability. A server that runs shell commands may exist precisely to run shell commands. What the numbers show is the reach an agent inherits when it hands work to one of these components.

## Population

The registry lists a server per published *version*, so its 73,460 entries collapse to **17,535 distinct components**. Aggregating the raw list would count a single package many times over.

| | |
|---|---|
| Distinct components | 17,535 |
| Scanned | **15,457** (88.1%) |
| Not scanned | 2,078 (11.9%) |

Nothing was dropped silently — every exclusion is counted:

| Why a component was not scanned | Components | Share of population |
|---|---:|---:|
| repository or package no longer reachable | 1,635 | 9.3% |
| slower than the time bound | 220 | 1.3% |
| larger than the size bound | 157 | 0.9% |
| other | 64 | 0.4% |
| access denied | 2 | 0.0% |

| Ecosystem | Scanned | Listed | Coverage |
|---|---:|---:|---:|
| git | 5,456 | 7,312 | 74.6% |
| npm | 7,011 | 7,152 | 98.0% |
| pypi | 2,990 | 3,071 | 97.4% |

## What these components can do

Share of the 15,457 scanned components carrying each capability:

| Capability | Components | Share |
|---|---:|---:|
| exposes MCP tools | 13,644 | **88.3%** |
| can reach the network | 10,169 | **65.8%** |
| can execute shell commands | 4,708 | **30.5%** |
| reads the filesystem | 3,932 | **25.4%** |
| writes the filesystem | 3,288 | **21.3%** |
| runs code at install time | 1,162 | **7.5%** |
| uses delegated (OAuth/OIDC) authentication | 938 | **6.1%** |
| evaluates code dynamically | 564 | **3.6%** |
| uses a scoped, short-lived identity | 87 | **0.6%** |

## Risk levels

SkillTotal scores risky constructs and malicious indicators; a capability on its own contributes zero to the score, and so does a secret the component ships, which the engine reports separately as an exposure. The risk distribution is therefore far flatter than the capability table above, and that difference is the point.

| Level | Components | Share |
|---|---:|---:|
| low | 15,293 | 99.0% |
| medium | 127 | 0.8% |
| high | 33 | 0.2% |
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

- Engine 0.48.0, ruleset 55 — deterministic regex and AST analysis. The component is never executed and no LLM is involved, so the run reproduces.
- Scanned components by ruleset: 15,203 with ruleset 54, 254 with ruleset 55. The later ruleset re-scanned only the components whose result its changes could affect, plus those that exceeded a bound on the first pass.
- Population: `https://registry.modelcontextprotocol.io/v0/servers` as of 2026-08-16, deduplicated by source.
- Two bounds, both disclosed above: 50 MB per fetch and 60s of wall clock per component.
- Harness: `tests/manual_eval/survey_registry.py`. This report: `tests/manual_eval/survey_report.py`. Both ship in this repository.
- Shares are rounded to one decimal place so that each table sums exactly to its total (largest-remainder method); a share can therefore sit up to 0.1 point from its unrounded value. The counts beside them are exact.
