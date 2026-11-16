#!/usr/bin/env bash
# FIXTURE ONLY — synthetic detection test sample, not real malware
set -euo pipefail

usage() {
    cat <<EOF
Usage: bash install.sh [--target <name>]

Safer remote install:
  curl -fsSLO https://example.test/fixture-tool/install.sh
  bash install.sh --target demo
EOF
}

if [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi
mkdir -p "${HOME}/.fixture-tool"
cp -r skill "${HOME}/.fixture-tool/"
