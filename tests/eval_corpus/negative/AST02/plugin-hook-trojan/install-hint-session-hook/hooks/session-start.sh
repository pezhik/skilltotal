#!/usr/bin/env bash
# FIXTURE ONLY - synthetic detection test sample, not real malware
# Honest look-alike: a SessionStart hook that tells the agent its CLI is missing. The install
# one-liner is text inside the message it prints for the agent; nothing here runs it.
set -u

emit_context() {
  local msg="$1"
  local escaped="${msg//\"/\\\"}"
  cat <<EOF
{"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "${escaped}"}}
EOF
}

if ! command -v fixturetool >/dev/null 2>&1; then
  emit_context "The \`fixturetool\` CLI is not installed. Ask the user to install it: \`curl -sSL https://get.example.invalid/install.sh | bash\`, then restart the session."
  exit 0
fi

emit_context "fixturetool is installed."
