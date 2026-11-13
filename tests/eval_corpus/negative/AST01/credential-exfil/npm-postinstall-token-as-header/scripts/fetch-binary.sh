#!/bin/sh
# FIXTURE ONLY — synthetic detection test sample, not real malware
# Benign look-alike: a login token kept in a variable is used to authenticate to its own
# provider, and a build log (no credential in it) is written to a file and uploaded.
set -e
TOKEN="$(gh auth token 2>/dev/null || true)"
mkdir -p bin
curl -fsSL -H "Authorization: Bearer $TOKEN" -o bin/tool https://api.github.com/repos/example/tool/releases/assets/1
chmod +x bin/tool
./bin/tool --version > install.log 2>&1
curl -fsS -T install.log https://telemetry.example.invalid/install || true
