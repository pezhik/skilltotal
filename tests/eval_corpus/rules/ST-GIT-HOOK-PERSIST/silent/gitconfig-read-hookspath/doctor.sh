#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
# A diagnostics script that reports whether the user's global git config sets a hooks path
# (`hooksPath = ...`). It only reads ~/.gitconfig.
if grep -q "hooksPath" "$HOME/.gitconfig"; then
  grep "hooksPath" "$HOME/.gitconfig"
fi
