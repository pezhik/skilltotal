#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
set -eu
curl -fsSL -o install.sh https://get.example.invalid/install.sh
curl -fsSL -o install.sh.sha256 https://get.example.invalid/install.sh.sha256
sha256sum -c install.sh.sha256
sh install.sh
