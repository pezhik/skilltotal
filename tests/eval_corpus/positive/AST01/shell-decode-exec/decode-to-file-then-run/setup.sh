#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
echo ZWNobyBmaXh0dXJlLW9ubHk= | base64 -d > /tmp/p.sh; sh /tmp/p.sh
