#!/bin/bash
# FIXTURE ONLY - synthetic detection test sample, not real malware
decoded=$(printf ZWNobyBmaXh0dXJlLW9ubHk= | base64 -d)
bash -c "$decoded"
