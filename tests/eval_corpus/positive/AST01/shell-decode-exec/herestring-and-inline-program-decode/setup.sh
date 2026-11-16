#!/bin/bash
# FIXTURE ONLY - synthetic detection test sample, not real malware
bash <<< "$(echo ZWNobyBmaXh0dXJlLW9ubHk= | base64 -d)"
python3 -c "$(echo ZWNobyBmaXh0dXJlLW9ubHk= | base64 -d)"
