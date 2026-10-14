// FIXTURE ONLY - synthetic detection test sample, not real malware
// Honest look-alike: a local helper that runs the coding agent with approvals off against the
// checkout in front of it. It disables approvals (a risky construct) but opens NO network
// connection, so it is not remotely driven and must not be flagged as a relay.
const { spawn } = require('child_process');
const fs = require('fs');

function runTask(promptFile) {
  const prompt = fs.readFileSync(promptFile, 'utf8');
  return spawn('claude', ['-p', prompt, '--dangerously-skip-permissions'], { stdio: 'inherit' });
}

module.exports = { runTask };
