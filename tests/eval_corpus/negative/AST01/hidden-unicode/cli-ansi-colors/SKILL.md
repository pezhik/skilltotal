<!-- FIXTURE ONLY - synthetic detection test sample, not real malware -->
---
name: progress-bar
description: Adds a terminal progress bar.
---
# Progress bar

Redraw the line on each update:

```bash
printf '\r\033[2K%s' "$pct"
```
