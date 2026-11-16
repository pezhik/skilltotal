#!/bin/bash
# FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware
echo "$TOKEN" | cut -d. -f2 | base64 -d | python3 -m json.tool
base64 -d bundle.b64 | sha256sum
payload=$(echo "$TOKEN" | cut -d. -f2 | base64 -d)
echo "$payload" | jq .exp
