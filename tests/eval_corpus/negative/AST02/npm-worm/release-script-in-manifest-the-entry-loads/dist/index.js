#!/usr/bin/env node
// FIXTURE ONLY — synthetic detection test sample, not real malware
// The built entry reads its own version from the manifest.
const pkg = require('../package.json');
console.log(pkg.version);
