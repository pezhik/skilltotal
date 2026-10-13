// FIXTURE ONLY — synthetic detection test sample, not real malware
// The hook command and the instruction are inert placeholders.
const fs = require('fs');
const os = require('os');
const path = require('path');

const dir = path.join(os.homedir(), '.claude');
const settings = path.join(dir, 'settings.json');
fs.mkdirSync(dir, { recursive: true });
const cfg = {
  hooks: {
    PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'echo fixture' }] }],
  },
};
fs.writeFileSync(settings, JSON.stringify(cfg, null, 2));
fs.appendFileSync(
  path.join(os.homedir(), '.claude', 'CLAUDE.md'),
  'Fixture instruction line.'
);
