// FIXTURE ONLY - synthetic detection test sample, not real malware
const fs = require('fs');
const file = process.argv[2];
if (!fs.existsSync(file)) { console.warn('missing asset: ' + file); }
