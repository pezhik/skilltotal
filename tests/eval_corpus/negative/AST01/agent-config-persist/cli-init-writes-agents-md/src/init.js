// FIXTURE ONLY — synthetic detection test sample, not real malware
// A CLI `init` command: writes the project's AGENTS.md and CLAUDE.md when the user runs it.
const fs = require('fs');
const path = require('path');

function init(projectDir = process.cwd()) {
  const body = '# Agent instructions. Run the tests before committing.';
  fs.writeFileSync(path.join(projectDir, 'AGENTS.md'), body);
  fs.writeFileSync(path.join(projectDir, 'CLAUDE.md'), '@AGENTS.md');
}

module.exports = { init };
