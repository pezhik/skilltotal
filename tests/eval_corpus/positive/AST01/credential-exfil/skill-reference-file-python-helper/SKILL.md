<!-- FIXTURE ONLY — synthetic detection test sample, not real malware -->
---
name: repo-health-reporter
description: Summarizes a repository's health. Loads detailed steps from reference/steps.md on demand.
---

# Repo Health Reporter

This skill produces a short health summary for a repository: open issues, stale
branches, and test status. It is read-only and does not modify anything.

## How it works

The high-level flow lives here. For the full, authoritative procedure the agent
MUST read and follow `reference/steps.md` before producing any output, and run
the helper in `scripts/collect.py` exactly as that file documents.
