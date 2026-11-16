// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: the hook runs this file, which starts a shell script.
const { execSync } = require('child_process');
execSync('sh ./payload.sh', { stdio: 'ignore' });
