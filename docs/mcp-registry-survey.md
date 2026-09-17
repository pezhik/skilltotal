# The MCP registry, measured

A deterministic static scan of every distinct component in the public MCP registry — 17,535 of them — scanned on 2026-09-17 against the registry as of 2026-08-16 with SkillTotal 0.48.2 (ruleset 57).

## How to read this

Every figure below describes a **capability**: something a component is able to do, derived only from the code it ships. A capability is not a vulnerability. A server that runs shell commands may exist precisely to run shell commands. What the numbers show is the reach an agent inherits when it hands work to one of these components.

## Population

The registry lists a server per published *version*, so its 73,460 entries collapse to **17,535 distinct components**. Aggregating the raw list would count a single package many times over.

| | |
|---|---|
| Distinct components | 17,535 |
| Scanned | **15,426** (88.0%) |
| Not scanned | 2,109 (12.0%) |

Nothing was dropped silently — every exclusion is counted:

| Why a component was not scanned | Components | Share of population |
|---|---:|---:|
| repository or package no longer reachable | 1,635 | 9.3% |
| slower than the time bound | 235 | 1.3% |
| larger than the size bound | 174 | 1.0% |
| other | 63 | 0.4% |
| access denied | 2 | 0.0% |

| Ecosystem | Scanned | Listed | Coverage |
|---|---:|---:|---:|
| git | 5,439 | 7,312 | 74.4% |
| npm | 6,999 | 7,152 | 97.9% |
| pypi | 2,988 | 3,071 | 97.3% |

## What these components can do

Share of the 15,426 scanned components carrying each capability:

| Capability | Components | Share |
|---|---:|---:|
| exposes MCP tools | 13,609 | **88.2%** |
| can reach the network | 10,028 | **65.0%** |
| can execute shell commands | 4,679 | **30.3%** |
| reads the filesystem | 3,899 | **25.3%** |
| writes the filesystem | 3,262 | **21.1%** |
| runs code at install time | 1,158 | **7.5%** |
| uses delegated (OAuth/OIDC) authentication | 923 | **6.0%** |
| evaluates code dynamically | 552 | **3.6%** |
| uses a scoped, short-lived identity | 80 | **0.5%** |

## Risk levels

SkillTotal scores risky constructs and malicious indicators; a capability on its own contributes zero to the score, and so does a secret the component ships, which the engine reports separately as an exposure. The risk distribution is therefore far flatter than the capability table above, and that difference is the point.

| Level | Components | Share |
|---|---:|---:|
| low | 15,285 | 99.1% |
| medium | 110 | 0.7% |
| high | 27 | 0.2% |
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

- Engine 0.48.2, ruleset 57 — deterministic regex and AST analysis. The component is never executed and no LLM is involved, so the run reproduces.
- Scanned components by ruleset: 15,358 with ruleset 56, 68 with ruleset 57. The later ruleset re-scanned only the components whose result its changes could affect, plus those that exceeded a bound on the first pass.
- Population: `https://registry.modelcontextprotocol.io/v0/servers` as of 2026-08-16, deduplicated by source.
- Two bounds, both disclosed above: 50 MB per fetch and 60s of wall clock per component.
- Harness: `tests/manual_eval/survey_registry.py`. This report: `tests/manual_eval/survey_report.py`. Both ship in this repository.
- Shares are rounded to one decimal place so that each table sums exactly to its total (largest-remainder method); a share can therefore sit up to 0.1 point from its unrounded value. The counts beside them are exact.
