#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
# A diagnostics script that lists what the login shell sources. It reads the startup files and
# writes nothing into them.
ls -l /etc/profile.d/
grep -n "alias" "$HOME/.bash_aliases" || true
cat /etc/bash.bashrc | head -n 20
