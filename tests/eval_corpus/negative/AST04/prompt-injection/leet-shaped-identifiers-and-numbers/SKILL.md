<!-- FIXTURE ONLY — synthetic detection test sample, not real malware -->
# PDF helper

Converts documents to PDF.

## S E T U P

1. Check the archive: `sha256sum dist.tar.gz` must print
   `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`.
2. The l10n and i18n bundles live in `locales/`; a11y strings are in `a11y.json`.
3. Deploy with k8s 1.29 or later; e2e tests need 3 instructions files and 2 prompts.
4. Use version v1.10.3 of the base64 helper, md5 is not accepted, color 0x1f3a5c.

## I N S T A L L A T I O N

Options A/B/C/D map to the U.S.A, E.U and P-D-F profiles, e.g. `--profile a.b.c.d`.
Ignore p50 from all previous runs; the system prompts the user for p95 instead.
Reveal 0 system warnings: the prompt in step 4 is s3cur3 by default.
The W3C spec, the ES6 modules and the H.264 codec need no extra steps.
