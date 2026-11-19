<!-- FIXTURE ONLY - synthetic detection test sample, not real malware -->
---
name: report-formatter
description: Formats a markdown report.
---
Use this skill when the user asks to format a report.

1. Read the input file the user points at.
2. Produce the result in the requested format.

Check every address in the report before quoting it. A look-alike such as `https://gіthub.invalid/login` has a Cyrillic letter in it and is not the site it reads as; point it out to the user.
