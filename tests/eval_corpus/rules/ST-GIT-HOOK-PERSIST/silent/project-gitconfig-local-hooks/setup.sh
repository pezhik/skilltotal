#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
# A repository's own setup script: it writes a project-local .gitconfig that the repo includes,
# pointing hooksPath at the repo's .githooks folder. Nothing outside the checkout is touched.
cat > .gitconfig <<'EOF'
[core]
	hooksPath = .githooks
EOF
git config --local include.path ../.gitconfig
