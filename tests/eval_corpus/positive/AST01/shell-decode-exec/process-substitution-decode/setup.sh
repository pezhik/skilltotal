#!/bin/bash
# FIXTURE ONLY - synthetic detection test sample, not real malware
bash <(echo ZWNobyBmaXh0dXJlLW9ubHk= | base64 -d)
source <(base64 -d <<< ZWNobyBmaXh0dXJlLW9ubHk=)
