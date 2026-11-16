#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware
curl -fsS https://api.example.com/v1/status | python3 -m json.tool
