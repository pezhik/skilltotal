# SkillTotal open-core model

SkillTotal is **open core**: the analysis engine is open source and fully usable on its own;
paid capabilities are delivered only as services of SkillTotal Cloud (the website), never as
code shipped in the open-source repository.

## Layers (dependency points one way: up)

```
[3] skilltotal-web  (PRIVATE repo)      FastAPI + workers + Next.js + billing
    └─ premium modules (PRIVATE):  llm/ (prompts, verification), sandbox/ (orchestration)
         imports skilltotal ; take a Report and enrich it
[2] skilltotal      (OSS, Apache-2.0, GitHub, PyPI)
    ├─ engine + all scanners/rules + CLI   (full, offline, zero runtime deps)
    └─ cloud client (thin):  `login`, `scan --deep`  -> HTTP to the paid API
[1] contract:  PyPI semver  +  docs/report.schema.json
```

The web app and premium modules depend on the engine; **the engine never depends on them**
(it already has zero web/LLM dependencies). The only coupling is the versioned package + the
report JSON schema.

## The boundary: WHAT vs WHY

- **Engine (OSS)** answers **WHAT** a component does — deterministic static facts with
  evidence (file/line/snippet): shell execution, filesystem/network/install/dynamic-code,
  sensitive paths, MCP dangerous tools, prompt-injection surface, hidden Unicode, the
  filesystem+network exfiltration combo, a 0–100 score and risk level.
- **Cloud (paid)** answers **WHY it matters / HOW MUCH / WHAT HAPPENS WHEN RUN / WHERE TO
  KEEP & WATCH IT** — LLM interpretation and prioritization of findings, dynamic sandbox
  execution, hosting, history, monitoring/alerting, dashboards, and organizational features.

**All detection rules stay in OSS.** The engine must be a genuinely useful, complete CI tool
on its own — that is what attracts the audience. Monetization is the layer *above* detection,
not a subset of it.

### Roadmap (paid, server-side — NOT the OSS engine)

These need runtime or external data, so they sit above the component-only static engine:

- **Runtime MCP proxy / continuous monitoring** — a local proxy between the agent and its MCP
  servers that inspects tool listings and calls live (catches behavior the static pass cannot,
  and re-checks on every update). Different architecture from the "never execute, component
  only" engine; belongs in the paid layer.
- **Upstream-diff & registry reputation** — compare a published package against its source
  repo to flag typosquats / forked-and-modified supply-chain trojans (e.g. the Postmark MCP
  email-stealer: the legitimate server re-published with one added BCC line). This needs
  external references (upstream repo, registry metadata), outside component-only static
  analysis — hence paid/server-side, not an engine rule.

## Why paid features can't be "taken from OSS"

They are **server-side services on top of the engine**, not functions inside it. The code that
creates the paid value — LLM prompt pipelines, finding-verification logic, sandbox
orchestration, billing — physically lives in the private `skilltotal-web` repo, not in OSS.
On top of that there's an operational moat: LLM keys, sandbox farms, hosting, and any private
datasets. Apache-2.0 maximizes adoption; the business is protected operationally, not by the
license. (A competitor could fork the engine — that's fine, the engine isn't the moat — but
they would not get the premium services.)

## Freemium bridge: the cloud client (design)

A thin, **open** HTTP client lives in the OSS CLI (`skilltotal/cloud/`, stdlib `urllib` only,
so zero-dep holds). It contains only request/response plumbing — **no premium logic** (prompts
and sandbox stay on the server).

- `skilltotal login` — stores an API key in `~/.config/skilltotal/config.json`.
- `skilltotal scan <src> --deep` — runs the full local static analysis, then POSTs the
  `Report` (or a component reference) to the paid API and prints the enriched report.
- Configurable endpoint: `SKILLTOTAL_API_KEY`, `SKILLTOTAL_API_URL` (default
  `https://api.skilltotal.dev`) — leaves room for enterprise self-host.
- Without a key, `--deep` prints a clear "requires a SkillTotal Cloud account" message and the
  **local scan still works fully and free**.

> Status: design only. The client is implemented together with the website API (it is
> pointless to ship HTTP to a non-existent endpoint). This file reserves the namespace and the
> contract.

## What must NEVER be committed to the OSS repo

- LLM prompts and the finding verification/prioritization pipeline
- Sandbox orchestration and images
- Billing code and any server-side secrets
- Any private premium corpora/datasets
- The website code itself

All of the above belongs to `skilltotal-web` (private).

## Versioned contract (recap)

`ENGINE_VERSION` (code/API, semver), `REPORT_SCHEMA_VERSION` (report shape), `RULESET_VERSION`
(detection set) — all in report `metadata`. Consumers pin the PyPI version and validate
reports against `report.schema.json`. See `releasing.md` and `report-schema.md`.
