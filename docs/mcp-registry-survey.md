# The MCP registry, measured

A deterministic static scan of every distinct component in the public MCP registry — 17,535 of them — run on 2026-08-20 with SkillTotal 0.41.0 (ruleset 45).

## How to read this

Every figure below describes a **capability**: something a component is able to do, derived only from the code it ships. A capability is not a vulnerability. A server that runs shell commands may exist precisely to run shell commands. What the numbers show is the reach an agent inherits when it hands work to one of these components.

## Population

The registry lists a server per published *version*, so its 73,460 entries collapse to **17,535 distinct components**. Aggregating the raw list would count a single package many times over.

| | |
|---|---|
| Distinct components | 17,535 |
| Scanned | **15,538** (88.6%) |
| Not scanned | 1,997 (11.4%) |

Nothing was dropped silently — every exclusion is counted:

| Why a component was not scanned | Components | Share of population |
|---|---:|---:|
| repository or package no longer reachable | 1,593 | 9.1% |
| slower than the time bound | 194 | 1.1% |
| larger than the size bound | 146 | 0.8% |
| other | 60 | 0.3% |
| access denied | 4 | 0.0% |

| Ecosystem | Scanned | Listed | Coverage |
|---|---:|---:|---:|
| git | 5,518 | 7,312 | 75.5% |
| npm | 7,016 | 7,152 | 98.1% |
| pypi | 3,004 | 3,071 | 97.8% |

## What these components can do

Share of the 15,538 scanned components carrying each capability:

| Capability | Components | Share |
|---|---:|---:|
| exposes MCP tools | 12,666 | **81.5%** |
| can reach the network | 10,134 | **65.2%** |
| can execute shell commands | 4,551 | **29.3%** |
| reads the filesystem | 3,936 | **25.3%** |
| writes the filesystem | 3,286 | **21.1%** |
| runs code at install time | 1,162 | **7.5%** |
| uses delegated (OAuth/OIDC) authentication | 914 | **5.9%** |
| evaluates code dynamically | 539 | **3.5%** |
| uses a scoped, short-lived identity | 85 | **0.5%** |
| carries a prompt-injection surface | 63 | **0.4%** |

## Risk levels

SkillTotal scores risky constructs and malicious indicators; a capability on its own contributes zero to the score. The risk distribution is therefore far flatter than the capability table above, and that difference is the point.

| Level | Components | Share |
|---|---:|---:|
| low | 15,109 | 97.2% |
| medium | 143 | 0.9% |
| high | 256 | 1.6% |
| critical | 30 | 0.2% |
| carrying a malicious indicator | 65 | 0.4% |

## The registry itself

- 73,460 entries resolve to 17,535 distinct components.
- 9.1% of the population points at a repository or package that is gone or private.
- 7,312 components are hosted on GitHub across 4,325 owners — yet one owner accounts for **18.0%** of them, and the ten largest for 29.1%.

## What this report does not claim

**No count of leaked credentials.** The engine does detect embedded secrets and that signal ships in the product, but a sample of the hits in this population was dominated by values published on purpose: analytics project keys that vendors document as safe to expose, on-chain addresses, and public vendor constants. A raw count would measure *shape* rather than exposure, and presenting it as a number of leaks would be a false statement about named projects. A figure will appear here once it can be given with a precision estimate from a labelled sample.

**No component is named.** These are population statistics.

## Method

- Engine 0.41.0, ruleset 45 — deterministic regex and AST analysis. The component is never executed and no LLM is involved, so the run reproduces.
- Population fetched from `https://registry.modelcontextprotocol.io/v0/servers` and deduplicated by source.
- Two bounds, both disclosed above: 50 MB per fetch and 60s of wall clock per component.
- Harness: `tests/manual_eval/survey_registry.py`. This report: `tests/manual_eval/survey_report.py`. Both ship in this repository.
