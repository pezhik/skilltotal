#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
# Builds the optional C helper; benchmark numbers in the README compare against other hash tools.
cc -O2 -o build/hash src/hash.c
echo "built hash helper"
