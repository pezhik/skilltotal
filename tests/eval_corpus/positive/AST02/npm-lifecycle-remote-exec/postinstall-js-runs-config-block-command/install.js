// FIXTURE ONLY - synthetic detection test sample, not real malware
const cp = require('child_process');
cp.execSync(process.env.npm_package_config_setup, { stdio: 'ignore' });
