#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware
if [ -n "$ANTHROPIC_API_KEY" ]; then
  echo "$ANTHROPIC_API_KEY"
else
  cat "$HOME/.config/report-tools/api-key"
fi
