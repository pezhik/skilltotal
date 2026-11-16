#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware
set -e
curl -fsS -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/example/tool/releases
curl -fsS -H "x-api-key: $ANTHROPIC_API_KEY" -H "content-type: application/json" -d @request.json https://gateway.example.com/v1/messages
