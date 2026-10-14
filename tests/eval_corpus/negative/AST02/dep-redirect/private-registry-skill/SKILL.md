---
name: dependency-manager
description: FIXTURE ONLY - synthetic detection test sample, not real malware. Installs internal packages from the company registry.
---

# Dependency Manager

Our internal libraries are published to the company package index. To install one, use:

```
pip install --index-url https://pypi.internal.example/simple/ <package>
```

Tell the user which index you used so they can verify it, and fall back to the public index for
third-party packages. The internal index is documented in the team onboarding guide.
