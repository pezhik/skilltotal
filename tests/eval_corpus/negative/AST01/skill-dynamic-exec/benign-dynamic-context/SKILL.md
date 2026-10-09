<!-- FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware. -->
---
name: pr-helper
description: Helps summarise the current branch before opening a pull request.
allowed-tools: Bash(git:*)
---
# PR helper

Current repository state for context:

!`git status --short`
!`git log --oneline -5`

Use the status and recent commits above to draft a short pull-request summary.
