# SkillTotal open-core model

SkillTotal is **open core**: the analysis engine is open source and fully usable on its own.
Planned paid features (SkillTotal Cloud) will be hosted services. None of their code ships in
this repository.

## Direction of dependency

The engine has zero web/LLM dependencies and never depends on anything above it. Hosted
services depend on the engine — they take a `Report` and enrich it. The only coupling is the
versioned PyPI package plus the report JSON schema (`docs/report.schema.json`).

## The boundary: WHAT vs WHY

- **Engine (OSS)** answers **WHAT** a component does — deterministic static facts with
  evidence (file/line/snippet): shell execution, filesystem/network/install/dynamic-code,
  sensitive paths, MCP dangerous tools, prompt-injection surface, hidden Unicode, the
  sensitive-data + network exfiltration combination, a 0–100 score and risk level.
- **SkillTotal Cloud (planned, paid)** is meant to answer **WHY it matters**: services on top of
  the report, such as interpretation and prioritization of findings. None of it is available
  yet.

**All detection rules stay in OSS.** The engine must be a genuinely useful, complete CI tool on
its own — that is what makes it worth adopting. Monetization is the hosted layer *above*
detection, not a subset of it: the paid value is server-side services and operations, so it is
not something that can be "taken from" the open source.

This repository never contains server-side or paid logic — LLM pipelines, finding-verification
code, sandbox orchestration, billing, server secrets, private datasets, or website code. A thin
client for a hosted API may be added to the CLI later. It would use the Python standard library
only and carry no premium logic, and the local scan would not depend on it.

## Versioned contract (recap)

`ENGINE_VERSION` (code/API, semver), `REPORT_SCHEMA_VERSION` (report shape), `RULESET_VERSION`
(detection set) — all in report `metadata`. Consumers pin the PyPI version and validate reports
against `report.schema.json`. See `releasing.md` and `report-schema.md`.
