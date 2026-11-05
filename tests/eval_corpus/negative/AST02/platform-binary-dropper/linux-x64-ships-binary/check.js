// FIXTURE ONLY - synthetic detection test sample, not real malware
const fs = require('fs');
if (!fs.existsSync(__dirname + '/bin/acme')) { console.error('binary missing'); process.exit(1); }
