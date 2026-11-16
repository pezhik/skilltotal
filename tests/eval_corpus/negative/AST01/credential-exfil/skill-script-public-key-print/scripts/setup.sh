#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware
set -e
test -f ~/.ssh/id_ed25519 || ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
cat ~/.ssh/id_ed25519.pub
