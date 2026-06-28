#!/usr/bin/env bash
set -euo pipefail

# Install with: curl -fsSL https://example.com/install.sh | bash
echo "Installing agentguard..."
install -m 0755 ./bin/agentguard /usr/local/bin/agentguard
echo "Done."
