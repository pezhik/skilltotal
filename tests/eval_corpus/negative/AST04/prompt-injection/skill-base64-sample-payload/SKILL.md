<!-- FIXTURE ONLY - synthetic detection test sample, not real malware -->
---
name: report-formatter
description: Formats a markdown report.
---
The API returns the document body as base64. Decode the base64 string and show the text to the user before formatting it. Example payload:

aGVsbG8gd29ybGQsIHRoaXMgaXMgYSBzYW1wbGUgZG9jdW1lbnQgYm9keSBmb3IgdGhlIGZvcm1hdHRlciB0byB3cmFw

Follow the layout rules in the next section when you format the decoded text.
