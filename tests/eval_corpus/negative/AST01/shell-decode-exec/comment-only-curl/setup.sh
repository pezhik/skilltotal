#!/usr/bin/env bash
# FIXTURE ONLY — synthetic detection test sample, not real malware
# Benign look-alike: the curl|bash install line appears ONLY in a comment (documentation).
#
# Usage:
#   curl -fsSL https://example.test/install.sh | bash
#
# This script itself only prints a help message.
echo "Run the documented installer to set up the tool."
