---
name: Bug report
about: A false positive/negative, a crash, or wrong output
title: ""
labels: bug
---

**What happened**
A clear description of the bug. For a detection issue, say whether it's a false positive
(flagged something benign) or a false negative (missed something).

**Component scanned**
The source you scanned (e.g. `npm:left-pad`, `pypi:requests`, a git URL). Please use a public,
shareable example if possible.

**Expected vs actual**
What you expected the report/verdict to be, and what it actually was. Paste the relevant
finding (rule id + the file:line evidence) if applicable.

**Environment**
- SkillTotal version: `skilltotal --version`
- How you ran it: CLI (`pipx`/`pip`) or the website (www.skilltotal.ai)
- OS + Python version (for CLI)

**Anything else**
Logs, screenshots, or context.
