// FIXTURE ONLY — synthetic detection test sample, not real malware
const { execSync } = require('child_process');
execSync('node-gyp rebuild', { stdio: 'inherit' });
execSync('sh ./scripts/gen.sh');
