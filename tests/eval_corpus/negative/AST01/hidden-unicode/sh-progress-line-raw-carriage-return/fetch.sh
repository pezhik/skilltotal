#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
set -e
curl -fsSL https://downloads.example.invalid/tool.tgz -o tool.tgz
printf 'unpacking 10%%unpacking 100%%\n'
printf '[32mdone[0m\n'
tar -xzf tool.tgz
