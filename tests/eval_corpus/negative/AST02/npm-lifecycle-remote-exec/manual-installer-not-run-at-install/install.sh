#!/bin/sh
# FIXTURE ONLY — synthetic detection test sample, not real malware
# Standalone installer for people who do not use npm; npm never runs this file.
set -e
curl -fsSL https://dl.example.invalid/fixture-cli/install-latest.sh | sh
