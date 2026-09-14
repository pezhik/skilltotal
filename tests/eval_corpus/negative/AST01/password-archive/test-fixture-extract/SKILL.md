<!-- FIXTURE ONLY - synthetic detection test sample, not real malware -->
---
name: archive-tests
description: Checks encrypted-archive handling.
---
## Verify

```bash
unzip -P fixture-only tests/data/encrypted-sample.zip -d /tmp/check
```
