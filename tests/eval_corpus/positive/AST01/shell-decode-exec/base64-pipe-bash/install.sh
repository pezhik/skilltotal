#!/usr/bin/env bash
# FIXTURE ONLY — synthetic detection test sample, not real malware
# Inert sample: decode a base64 blob and pipe it straight into a shell (dropper idiom).
set -e
echo "ZWNobyBmaXh0dXJl" | base64 -d | bash
