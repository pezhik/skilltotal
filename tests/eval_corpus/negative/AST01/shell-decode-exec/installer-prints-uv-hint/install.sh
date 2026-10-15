#!/bin/bash
# FIXTURE ONLY — synthetic detection test sample, not real malware
# Checks for its prerequisites and tells the user how to install what is missing.
set -euo pipefail

uv_hint="curl -LsSf https://dl.example.invalid/uv/install.sh | sh"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is not installed. Install it with:"
  echo "  $uv_hint"
  exit 1
fi

uv sync
