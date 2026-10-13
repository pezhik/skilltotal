// FIXTURE ONLY — synthetic detection test sample, not real malware
// Reads the agent's settings to report on them; writes only its own state file.
const fs = require('fs');
const os = require('os');
const path = require('path');

const file = path.join(os.homedir(), '.claude', 'settings.json');
let hooks = 0;
if (fs.existsSync(file)) {
  hooks = Object.keys(JSON.parse(fs.readFileSync(file, 'utf8')).hooks || {}).length;
}
fs.writeFileSync(path.join(os.tmpdir(), 'fixture-agent-doctor.json'), JSON.stringify({ hooks }));
