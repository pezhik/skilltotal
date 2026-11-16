#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware
curl -sLO https://releases.example.com/tool-1.2.3.tar.gz
echo "0000000000000000000000000000000000000000000000000000000000000000  tool-1.2.3.tar.gz" | sha256sum -c -
tar xzf tool-1.2.3.tar.gz -C ./vendor-tools
