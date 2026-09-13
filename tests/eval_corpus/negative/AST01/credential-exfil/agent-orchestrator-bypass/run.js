// FIXTURE ONLY - synthetic detection test sample, not real malware
const { spawn } = require('child_process');
function runTask(prompt) {
  return spawn('claude', ['-p', prompt, '--dangerously-skip-permissions'], { stdio: 'inherit' });
}
module.exports = { runTask };
