#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
# Benign look-alike: rev used on text that is printed or sorted, never handed to a shell.
echo "$1" | rev
rev names.txt | sort | rev > sorted-by-suffix.txt
last_field=$(echo "$path" | rev | cut -d/ -f1 | rev)
echo "$last_field"
