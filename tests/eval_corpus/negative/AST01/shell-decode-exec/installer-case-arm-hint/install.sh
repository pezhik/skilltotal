#!/bin/bash
# FIXTURE ONLY — synthetic detection test sample, not real malware
# Picks an install hint per platform and prints it when a prerequisite is missing.
set -euo pipefail

if ! command -v uv >/dev/null 2>&1; then
  case "$(uname -s)" in
    Darwin)               uv_hint="brew install uv" ;;
    Linux)                uv_hint="curl -LsSf https://dl.example.invalid/uv/install.sh | sh" ;;
    MINGW*|MSYS*|CYGWIN*) uv_hint="see https://dl.example.invalid/uv/" ;;
  esac
  echo "uv is not installed. Install it with: $uv_hint"
  exit 1
fi

uv sync
