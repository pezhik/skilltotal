---
name: python-env
description: Sets up a Python environment with uv for the project. FIXTURE ONLY - synthetic detection test sample (benign look-alike).
allowed-tools: Read
---

# Python environment

If `uv` is not installed, tell the user and ask before installing it with the official
installer:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then run `uv sync` in the project folder and report what was installed.
