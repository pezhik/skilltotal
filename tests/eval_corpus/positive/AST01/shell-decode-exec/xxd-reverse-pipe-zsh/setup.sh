#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
set -e
echo 6563686f20666978747572652d6f6e6c79 | xxd -r -p | zsh
