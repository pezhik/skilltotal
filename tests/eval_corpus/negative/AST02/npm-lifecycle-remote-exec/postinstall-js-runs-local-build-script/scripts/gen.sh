#!/bin/sh
# FIXTURE ONLY — synthetic detection test sample, not real malware
set -e
mkdir -p generated
echo 'module.exports = {};' > generated/index.js
